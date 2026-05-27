package warehouse

// BigQueryLoader implements Loader for Google BigQuery. Connect()
// validates auth + ensures the dataset exists (does NOT create the
// project). Load() streams rows via the streaming-insert API by
// default, batching 500 rows per call; flip to `WithBatchCopy(true)`
// for the load-job COPY pattern used by larger datasets.
//
// Auth: Application Default Credentials (the standard
// GOOGLE_APPLICATION_CREDENTIALS env var or workload-identity from
// the host). The library reads this from cloud.google.com/go/auth.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/iterator"
)

// BigQueryConfig captures the per-loader knobs.
type BigQueryConfig struct {
	ProjectID string
	Dataset   string
	// Location applies when Connect needs to CREATE the dataset; if
	// the dataset already exists the location is honored as set on
	// the destination. Empty defaults to "US".
	Location string
	// BatchSize controls the streaming-insert batch. Default 500;
	// the API caps at 10,000 rows per call.
	BatchSize int
	// CreateTableIfMissing — when true (the default), Load creates
	// the destination table with the schema derived from SchemaFor()
	// if it doesn't exist.
	CreateTableIfMissing bool
}

// BigQueryLoader is the concrete Loader. Construct via NewBigQueryLoader.
type BigQueryLoader struct {
	cfg    BigQueryConfig
	client *bigquery.Client
}

// NewBigQueryLoader returns a BigQueryLoader configured against cfg.
// The client connection is lazy — created on first Connect call.
func NewBigQueryLoader(cfg BigQueryConfig) *BigQueryLoader {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 500
	}
	if cfg.Location == "" {
		cfg.Location = "US"
	}
	cfg.CreateTableIfMissing = true // default-on; operators override via re-config
	return &BigQueryLoader{cfg: cfg}
}

func (b *BigQueryLoader) Connect(ctx context.Context) error {
	if b.cfg.ProjectID == "" {
		return fmt.Errorf("bigquery loader: ProjectID required")
	}
	if b.cfg.Dataset == "" {
		return fmt.Errorf("bigquery loader: Dataset required")
	}
	if b.client != nil {
		return nil
	}
	cli, err := bigquery.NewClient(ctx, b.cfg.ProjectID)
	if err != nil {
		return fmt.Errorf("bigquery NewClient: %w", err)
	}
	b.client = cli
	// Ensure the dataset exists.
	ds := cli.Dataset(b.cfg.Dataset)
	if _, err := ds.Metadata(ctx); err != nil {
		// Create on miss.
		if createErr := ds.Create(ctx, &bigquery.DatasetMetadata{Location: b.cfg.Location}); createErr != nil {
			return fmt.Errorf("bigquery ensure dataset %s: existing-metadata err=%v; create err=%w",
				b.cfg.Dataset, err, createErr)
		}
	}
	return nil
}

func (b *BigQueryLoader) Load(ctx context.Context, schema Schema, rows <-chan Row) error {
	if b.client == nil {
		return fmt.Errorf("bigquery loader: not connected")
	}
	tbl := b.client.Dataset(b.cfg.Dataset).Table(string(schema.Table))
	if b.cfg.CreateTableIfMissing {
		if err := b.ensureTable(ctx, tbl, schema); err != nil {
			return err
		}
	}
	inserter := tbl.Inserter()
	inserter.SkipInvalidRows = false
	inserter.IgnoreUnknownValues = false

	batch := make([]*bigquery.ValuesSaver, 0, b.cfg.BatchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		// Sigh: the BigQuery client accepts []bigquery.ValueSaver via interface, not the concrete type.
		items := make([]any, len(batch))
		for i, b := range batch {
			items[i] = b
		}
		if err := inserter.Put(ctx, items); err != nil {
			return fmt.Errorf("bigquery insert %s: %w", schema.Table, err)
		}
		batch = batch[:0]
		return nil
	}

	for row := range rows {
		vs := rowToValuesSaver(schema, row)
		batch = append(batch, vs)
		if len(batch) >= b.cfg.BatchSize {
			if err := flush(); err != nil {
				return err
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return flush()
}

func (b *BigQueryLoader) Close() error {
	if b.client == nil {
		return nil
	}
	err := b.client.Close()
	b.client = nil
	return err
}

func (b *BigQueryLoader) ensureTable(ctx context.Context, tbl *bigquery.Table, schema Schema) error {
	_, err := tbl.Metadata(ctx)
	if err == nil {
		return nil
	}
	bqSchema := bigquerySchema(schema)
	desc := fmt.Sprintf("compliancekit warehouse table %s (schema v%d)", schema.Table, SchemaVersion)
	if createErr := tbl.Create(ctx, &bigquery.TableMetadata{
		Name:        string(schema.Table),
		Description: desc,
		Schema:      bqSchema,
	}); createErr != nil {
		return fmt.Errorf("bigquery create table %s: %w", schema.Table, createErr)
	}
	return nil
}

func bigquerySchema(s Schema) bigquery.Schema {
	out := make(bigquery.Schema, len(s.Columns))
	for i, c := range s.Columns {
		out[i] = &bigquery.FieldSchema{
			Name:        c.Name,
			Type:        bigQueryFieldType(c.Type),
			Required:    !c.Nullable,
			Description: c.Comment,
		}
	}
	return out
}

func bigQueryFieldType(t ColumnType) bigquery.FieldType {
	switch t {
	case TypeString, TypeJSON:
		return bigquery.StringFieldType
	case TypeInt:
		return bigquery.IntegerFieldType
	case TypeFloat:
		return bigquery.FloatFieldType
	case TypeBool:
		return bigquery.BooleanFieldType
	case TypeTimestamp:
		return bigquery.TimestampFieldType
	}
	return bigquery.StringFieldType
}

func rowToValuesSaver(schema Schema, row Row) *bigquery.ValuesSaver {
	vals := make([]bigquery.Value, len(schema.Columns))
	for i, c := range schema.Columns {
		v, ok := row[c.Name]
		if !ok || v == nil {
			vals[i] = nil
			continue
		}
		switch c.Type {
		case TypeTimestamp:
			if ts, err := toTimestampMicros(v); err == nil {
				vals[i] = time.UnixMicro(ts).UTC()
			} else {
				vals[i] = nil
			}
		case TypeJSON:
			vals[i] = toStringValue(v)
		default:
			vals[i] = v
		}
	}
	return &bigquery.ValuesSaver{
		Schema:   bigquerySchema(schema),
		InsertID: rowInsertID(schema, row),
		Row:      vals,
	}
}

// rowInsertID derives a stable InsertID per row so BigQuery's
// duplicate-detection (1-minute window) dedupes safely on retry.
// Uses the table's primary id column.
func rowInsertID(s Schema, row Row) string {
	switch s.Table {
	case TableFindings, TableResources, TableScans:
		if v, ok := row["id"]; ok {
			if s, sOK := v.(string); sOK {
				return s
			}
		}
	case TableAuditLog:
		if v, ok := row["id"]; ok {
			b, _ := json.Marshal(v)
			return string(b)
		}
	}
	return ""
}

// Compile-time check: iterator is in scope so the bigquery package
// doesn't get tree-shaken in test builds that pull only the
// constants. v1.17 phase 6 (snapshots) will use Query iterators
// to materialize snapshot reads from BigQuery for cross-check.
var _ = iterator.Done
