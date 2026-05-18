package store

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go sqlite driver; no CGO required.
)

// OpenSQLite returns a Store backed by modernc.org/sqlite (pure Go,
// no CGO). path may be a filesystem path, ":memory:" for tests, or
// "file::memory:?cache=shared" for cross-connection in-memory state.
//
// PRAGMA settings applied at open time:
//
//	journal_mode=WAL   — concurrent reads + single-writer with no
//	                     blocking. Required for the v1.3 worker pool
//	                     which writes while the UI reads.
//	foreign_keys=ON    — SQLite defaults to OFF; the schema relies on
//	                     CASCADE / SET NULL semantics so this must be
//	                     on for every connection.
//	synchronous=NORMAL — durability/perf trade matched to WAL; safe
//	                     against power loss (just may rewind to the
//	                     last fsync).
//	busy_timeout=5000  — five-second wait for the writer lock before
//	                     ERR; tests + concurrent webhook receivers
//	                     need this.
func OpenSQLite(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", path, err)
	}
	// Pure-Go modernc sqlite serializes writes; one connection is
	// enough for the v1.3 workload, but we allow a few more for
	// concurrent reads under WAL.
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(5)

	pragmas := []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA foreign_keys = ON`,
		`PRAGMA synchronous = NORMAL`,
		`PRAGMA busy_timeout = 5000`,
	}
	for _, p := range pragmas {
		if _, err := db.ExecContext(ctx, p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("apply %q: %w", p, err)
		}
	}

	s := &Store{db: db, driver: DriverSQLite}
	if err := s.Ping(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return s, nil
}
