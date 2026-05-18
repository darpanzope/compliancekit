// Package store is the persistent-state layer for compliancekit's
// serve-mode daemon. Phase 1 lands the schema + migration runner +
// the Store abstraction that phase 2's Postgres backend will
// re-implement.
//
// The schema lives under migrations/ as plain SQL files. Both the
// sqlite backend (phase 1) and the postgres backend (phase 2)
// consume the same files; portable SQL is enforced by review +
// integration tests against both engines.
//
// IDs are TEXT (uuid4) for portability across SQLite + Postgres;
// timestamps are TEXT (RFC-3339) for the same reason. See
// migrations/0001_initial.sql for the full schema rationale.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// nowFn is the clock source for applied_at timestamps. Tests
// override this to get deterministic schema_migrations rows.
var nowFn = func() time.Time { return time.Now().UTC() }

// Store is the abstract handle every daemon component consumes.
// Both the sqlite and postgres backends satisfy this interface.
// Phase 6/7 (REST API) and phase 11 (UI shell) layer Repositories on
// top of this in their respective packages.
type Store struct {
	db     *sql.DB
	driver Driver
}

// Driver identifies the underlying engine. Lets repository code
// branch on dialect when SQLite + Postgres diverge (e.g. JSONB vs
// TEXT JSON, RETURNING, LISTEN/NOTIFY).
type Driver string

const (
	DriverSQLite   Driver = "sqlite"
	DriverPostgres Driver = "postgres"
)

// DB returns the underlying *sql.DB for code paths that need direct
// SQL access (migrations, raw queries, transactions). Repository
// packages should prefer adding methods on Store over reaching for
// DB() — but the escape hatch is here when needed.
func (s *Store) DB() *sql.DB { return s.db }

// Driver reports the active backend.
func (s *Store) Driver() Driver { return s.driver }

// Close releases the underlying connection pool.
func (s *Store) Close() error { return s.db.Close() }

// Ping verifies the connection is alive. Used by /health (when phase 6
// makes it dependency-aware) and by tests.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// version reports the highest migration version applied. Used by
// MigrateUp + by /health to surface schema drift.
func (s *Store) version(ctx context.Context) (int, error) {
	var v sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("read schema_migrations: %w", err)
	}
	if !v.Valid {
		return 0, nil
	}
	return int(v.Int64), nil
}
