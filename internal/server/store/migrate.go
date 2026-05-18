package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migration is one SQL file under migrations/. The file naming
// convention is `NNNN_description.sql` where NNNN is a zero-padded
// integer; the integer is the schema_migrations.version row written
// on successful apply.
type migration struct {
	version int
	name    string
	sql     string
}

// MigrateUp applies every pending migration in order. Idempotent —
// re-running after every migration has been applied is a no-op.
// Errors fail fast; the partial state of a failed migration is left
// in place (we don't roll back) so the operator can inspect.
//
// Concurrent calls are serialized via SQLite's writer lock; on
// Postgres (phase 2) we'll add an explicit advisory lock.
func (s *Store) MigrateUp(ctx context.Context) error {
	if err := s.ensureMigrationsTable(ctx); err != nil {
		return err
	}
	have, err := s.appliedVersions(ctx)
	if err != nil {
		return err
	}
	all, err := loadMigrations()
	if err != nil {
		return err
	}
	for _, m := range all {
		if have[m.version] {
			continue
		}
		if err := s.applyMigration(ctx, m); err != nil {
			return fmt.Errorf("migration %04d (%s): %w", m.version, m.name, err)
		}
	}
	return nil
}

// Version returns the highest migration version applied. Exposed for
// the /health endpoint and CLI helpers.
func (s *Store) Version(ctx context.Context) (int, error) {
	return s.version(ctx)
}

func (s *Store) ensureMigrationsTable(ctx context.Context) error {
	stmt := `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at TEXT NOT NULL
	)`
	_, err := s.db.ExecContext(ctx, stmt)
	return err
}

func (s *Store) appliedVersions(ctx context.Context) (map[int]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("scan applied migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	have := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		have[v] = true
	}
	return have, rows.Err()
}

// applyMigration runs the migration's SQL inside a transaction and
// records the version row in the same transaction so partial
// completion can't slip through.
func (s *Store) applyMigration(ctx context.Context, m migration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return err
	}
	now := nowFn().Format("2006-01-02T15:04:05Z07:00")
	_, err = tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
		m.version, m.name, now)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// loadMigrations reads every *.sql file under migrations/ and parses
// the leading NNNN_ prefix as the version. Returns the slice sorted
// by version asc. Bad filenames fail the build (panic) rather than
// silently skipping a migration — naming discipline is enforceable
// and a typo here would cause real damage at deploy time.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}
	out := make([]migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		parts := strings.SplitN(e.Name(), "_", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("migration %s: expected NNNN_description.sql", e.Name())
		}
		v, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("migration %s: leading %q is not an integer", e.Name(), parts[0])
		}
		body, err := fs.ReadFile(migrationsFS, "migrations/"+e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{
			version: v,
			name:    strings.TrimSuffix(parts[1], ".sql"),
			sql:     string(body),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	// Sanity check: versions are strictly increasing starting at 1, no gaps.
	for i, m := range out {
		want := i + 1
		if m.version != want {
			return nil, fmt.Errorf("migration version sequence broken: got %d at index %d, want %d", m.version, i, want)
		}
	}
	return out, nil
}

// errMissingMigration is returned if a query expects a table the
// migrations haven't created yet. Tests use it to assert that
// MigrateUp must be called before any data access.
var errMissingMigration = errors.New("schema not initialized — call MigrateUp first")

// Sentinel for callers that want to detect the "fresh DB" path.
func IsMissingMigration(err error) bool { return errors.Is(err, errMissingMigration) }

// Bring sql package in for the side-effect of unused-import-free
// dependency tracking; concrete uses are in sqlite.go + repositories.
var _ = sql.ErrNoRows
