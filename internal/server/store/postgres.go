package store

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib" // register "pgx" driver for database/sql
)

// OpenPostgres returns a Store backed by jackc/pgx/v5/stdlib (the
// canonical Go PG driver, used via the standard database/sql
// interface so repository code stays driver-agnostic).
//
// dsn accepts the libpq DSN forms pgx understands:
//
//	postgres://user:pass@host:port/db?sslmode=require
//	postgresql://user:pass@host:port/db
//	host=... user=... password=... dbname=... sslmode=...
//
// Connection-pool sizing is set conservatively for the v1.3 workload
// (the daemon's reads dominate; writes happen via the worker pool
// from phase 8). Operators with high-throughput needs can tune via
// future Config knobs.
func OpenPostgres(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	// Defaults matched to a single-binary daemon, not a high-traffic
	// API gateway. The 25-conn ceiling is well below most PG instances'
	// max_connections and leaves headroom for adjacent services.
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	s := &Store{db: db, driver: DriverPostgres}
	if err := s.Ping(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return s, nil
}

// pgAdvisoryLockKey is a fixed 64-bit integer used as the PG advisory-
// lock key during MigrateUp. The number is arbitrary but stable; every
// daemon binary using this code path acquires the same lock, so only
// one process runs migrations against a given DB at a time. Chosen as
// a value unlikely to collide with operator-defined locks
// (compliancekit's name in hex-ish hash form, fits in a signed int64).
const pgAdvisoryLockKey int64 = 0x636B5F6D69677261 // "ck_migra"
