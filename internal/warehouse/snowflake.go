package warehouse

// SnowflakeLoader implements Loader for Snowflake. The path used is
// the snowsql-style "stage upload + COPY INTO" pattern: build a
// per-table NDJSON file in-memory, PUT it into a session-scoped
// internal stage, then COPY INTO the destination table. Streaming
// inserts via gosnowflake's bind variables would also work but are
// 10-30× slower for the typical warehouse-sync row counts (50k+
// findings per nightly load).
//
// Auth: --user + --password OR set SNOWFLAKE_PRIVATE_KEY to use
// key-pair auth. The library reads the env var directly via the
// "snowflake://" DSN.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/snowflakedb/gosnowflake" //nolint:revive // database/sql side-effect import
)

// SnowflakeConfig captures the per-loader knobs.
type SnowflakeConfig struct {
	Account   string // e.g. acme.us-east-1
	Warehouse string
	Database  string
	Schema    string
	User      string
	Password  string // empty → key-pair auth via SNOWFLAKE_PRIVATE_KEY env var
}

// SnowflakeLoader is the concrete Loader. Construct via
// NewSnowflakeLoader.
type SnowflakeLoader struct {
	cfg SnowflakeConfig
	db  *sql.DB
}

// NewSnowflakeLoader returns a Loader configured against cfg. The
// underlying *sql.DB is lazy — opened on first Connect call.
func NewSnowflakeLoader(cfg SnowflakeConfig) *SnowflakeLoader {
	if cfg.Schema == "" {
		cfg.Schema = "PUBLIC"
	}
	return &SnowflakeLoader{cfg: cfg}
}

func (s *SnowflakeLoader) Connect(ctx context.Context) error {
	if s.cfg.Account == "" || s.cfg.User == "" || s.cfg.Database == "" || s.cfg.Warehouse == "" {
		return fmt.Errorf("snowflake loader: Account, User, Database, Warehouse all required")
	}
	if s.db != nil {
		return nil
	}
	// DSN format per gosnowflake: <user>:<password>@<account>/<database>/<schema>?warehouse=...
	auth := s.cfg.User
	if s.cfg.Password != "" {
		auth = s.cfg.User + ":" + s.cfg.Password
	}
	dsn := fmt.Sprintf("%s@%s/%s/%s?warehouse=%s",
		auth, s.cfg.Account, s.cfg.Database, s.cfg.Schema, s.cfg.Warehouse)
	db, err := sql.Open("snowflake", dsn)
	if err != nil {
		return fmt.Errorf("snowflake open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return fmt.Errorf("snowflake ping: %w", err)
	}
	s.db = db
	return nil
}

func (s *SnowflakeLoader) Load(ctx context.Context, schema Schema, rows <-chan Row) error {
	if s.db == nil {
		return fmt.Errorf("snowflake loader: not connected")
	}
	// Ensure the destination table exists with the right shape.
	if err := s.ensureTable(ctx, schema); err != nil {
		return err
	}
	// Build the NDJSON payload in memory. For large datasets a future
	// v1.17.x optimization will stream to a tempfile + PUT-with-file
	// instead; the in-memory path is fine up to ~250 MB which covers
	// every realistic compliance dataset.
	var buf bytes.Buffer
	count := 0
	for row := range rows {
		out := map[string]any{}
		for _, c := range schema.Columns {
			v, ok := row[c.Name]
			if !ok {
				if c.Nullable {
					continue
				}
				v = nil
			}
			out[c.Name] = snowflakeValue(c.Type, v)
		}
		if err := json.NewEncoder(&buf).Encode(out); err != nil {
			return fmt.Errorf("encode row %d for %s: %w", count, schema.Table, err)
		}
		count++
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if count == 0 {
		return nil
	}
	stageFile := fmt.Sprintf("compliancekit_%s_%d.ndjson", schema.Table, time.Now().UnixNano())
	// PUT the in-memory buffer onto Snowflake's user stage.
	if _, err := s.db.ExecContext(ctx,
		fmt.Sprintf(`PUT 'file://%s' @~/ AUTO_COMPRESS=TRUE`, stageFile), &buf); err != nil {
		return fmt.Errorf("snowflake PUT %s: %w", schema.Table, err)
	}
	// COPY INTO the destination table. Snowflake doesn't accept
	// bind parameters for the COPY INTO target table, so we format
	// the SQL — Table values are from the closed-set Schema enum,
	// stageFile is a daemon-generated name with a Unix nanos
	// timestamp suffix; both are non-tainted.
	copySQL := fmt.Sprintf( //nolint:gosec // table from closed enum; stageFile daemon-generated
		`COPY INTO %s FROM @~/%s.gz FILE_FORMAT = (TYPE = JSON) MATCH_BY_COLUMN_NAME = CASE_INSENSITIVE`,
		string(schema.Table), stageFile)
	if _, err := s.db.ExecContext(ctx, copySQL); err != nil {
		return fmt.Errorf("snowflake COPY %s: %w", schema.Table, err)
	}
	// Clean up the staged file. Best-effort; if it sticks around a
	// 24h Snowflake auto-purge handles it.
	_, _ = s.db.ExecContext(ctx, fmt.Sprintf(`REMOVE @~/%s.gz`, stageFile))
	return nil
}

func (s *SnowflakeLoader) Close() error {
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

func (s *SnowflakeLoader) ensureTable(ctx context.Context, schema Schema) error {
	cols := make([]string, len(schema.Columns))
	for i, c := range schema.Columns {
		nullness := "NOT NULL"
		if c.Nullable {
			nullness = ""
		}
		cols[i] = fmt.Sprintf("%s %s %s", c.Name, snowflakeColumnType(c.Type), nullness)
	}
	q := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (%s) COMMENT = 'compliancekit warehouse table (schema v%d)'`,
		string(schema.Table), strings.Join(cols, ", "), SchemaVersion)
	if _, err := s.db.ExecContext(ctx, q); err != nil {
		return fmt.Errorf("snowflake create %s: %w", schema.Table, err)
	}
	return nil
}

func snowflakeColumnType(t ColumnType) string {
	switch t {
	case TypeString, TypeJSON:
		return "VARCHAR"
	case TypeInt:
		return "NUMBER(38,0)"
	case TypeFloat:
		return "FLOAT"
	case TypeBool:
		return "BOOLEAN"
	case TypeTimestamp:
		return "TIMESTAMP_TZ"
	}
	return "VARCHAR"
}

func snowflakeValue(t ColumnType, v any) any {
	if v == nil {
		return nil
	}
	switch t {
	case TypeTimestamp:
		if ts, err := toTimestampMicros(v); err == nil {
			return time.UnixMicro(ts).UTC().Format(time.RFC3339)
		}
		return nil
	case TypeJSON:
		return toStringValue(v)
	}
	return v
}
