// Package backups owns the v1.12 phase 8 backup/restore workflow.
//
// SQLite: SQL `VACUUM INTO 'path'` writes a consistent snapshot to a
// fresh file on disk. The file is portable — operators copy it
// off-host for archival.
//
// Postgres: shell out to `pg_dump` with the daemon's DSN. The binary
// must be on PATH; the daemon process must have permission to write
// to the configured backup directory. Restore is a manual
// `pg_restore` step documented in OPERATIONS.md — too destructive to
// expose as a one-click UI affordance.
//
// The catalog table (backups) is the index — every Create records one
// row with the path + size + kind so the operator can pick which one
// to restore from.
package backups

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// Kind names the backup format.
const (
	KindSQLite   = "sqlite"
	KindPostgres = "postgres"
)

// Backup is the in-memory shape of one catalog row.
type Backup struct {
	ID          string
	CreatedAt   time.Time
	Kind        string // "sqlite" or "postgres"
	Path        string
	SizeBytes   int64
	Status      string // "ok", "failed", "in_progress"
	Note        string
	TriggeredBy string
}

// Manager wraps the catalog + the on-disk dump operations.
type Manager struct {
	store *store.Store
	dir   string // directory where dumps land
	dsn   string // postgres DSN (empty for sqlite)
}

// New returns a Manager bound to st with backups landing under dir.
// dsn is the Postgres connection string when st is Postgres-backed;
// ignored for SQLite.
func New(st *store.Store, dir, dsn string) *Manager {
	return &Manager{store: st, dir: dir, dsn: dsn}
}

// Dir returns the backup directory.
func (m *Manager) Dir() string { return m.dir }

// Create dumps the daemon's database into m.dir. Returns the Backup
// row recorded in the catalog. note is a free-form operator label
// (e.g. "pre-v1.12-upgrade"); triggeredBy is the user ID — empty for
// scheduled / automatic backups.
func (m *Manager) Create(ctx context.Context, note, triggeredBy string) (*Backup, error) {
	if m.dir == "" {
		return nil, errors.New("backups: directory not configured (set CK_BACKUP_DIR)")
	}
	if err := os.MkdirAll(m.dir, 0o750); err != nil {
		return nil, fmt.Errorf("backups: mkdir: %w", err)
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	kind := KindSQLite
	if m.store.Driver() == store.DriverPostgres {
		kind = KindPostgres
	}
	filename := now.Format("20060102-150405") + "-" + id[:8]
	switch kind {
	case KindSQLite:
		filename += ".db"
	case KindPostgres:
		filename += ".dump"
	}
	dest := filepath.Join(m.dir, filename)

	insertQ := `INSERT INTO backups (id, created_at, kind, path, size_bytes, status, note, triggered_by)
	            VALUES (` + phList(m.store, 8) + `)`
	var triggeredArg any
	if triggeredBy != "" {
		triggeredArg = triggeredBy
	}
	if _, err := m.store.DB().ExecContext(ctx, insertQ,
		id, now.Format(time.RFC3339), kind, dest, 0, "in_progress", note, triggeredArg); err != nil {
		return nil, fmt.Errorf("backups: insert: %w", err)
	}

	var dumpErr error
	switch kind {
	case KindSQLite:
		dumpErr = m.dumpSQLite(ctx, dest)
	case KindPostgres:
		dumpErr = m.dumpPostgres(ctx, dest)
	}

	status := "ok"
	var size int64
	if dumpErr != nil {
		status = "failed"
	} else {
		if st, err := os.Stat(dest); err == nil {
			size = st.Size()
		}
	}
	updQ := `UPDATE backups SET status = ` + ph(m.store, 1) + `, size_bytes = ` + ph(m.store, 2) + ` WHERE id = ` + ph(m.store, 3)
	_, _ = m.store.DB().ExecContext(ctx, updQ, status, size, id)

	if dumpErr != nil {
		return nil, dumpErr
	}
	return m.ByID(ctx, id)
}

// dumpSQLite uses SQLite's VACUUM INTO statement to write a
// self-contained copy to dest. The operation runs in a single
// transaction so the dump is consistent.
func (m *Manager) dumpSQLite(ctx context.Context, dest string) error {
	q := `VACUUM INTO ` + sqliteLiteral(dest)
	_, err := m.store.DB().ExecContext(ctx, q)
	if err != nil {
		return fmt.Errorf("backups: VACUUM INTO: %w", err)
	}
	return nil
}

// dumpPostgres shells out to pg_dump with the daemon's DSN. Output
// uses the custom format so pg_restore can re-apply it. The binary
// must be on PATH (typically installed alongside the Postgres
// server / client packages).
func (m *Manager) dumpPostgres(ctx context.Context, dest string) error {
	if m.dsn == "" {
		return errors.New("backups: postgres DSN not provided")
	}
	//nolint:gosec // pg_dump invoked with an operator-controlled DSN + file path; daemon runs as a trusted process
	cmd := exec.CommandContext(ctx, "pg_dump", "--format=custom", "--file="+dest, m.dsn)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("backups: pg_dump failed: %v: %s", err, string(out))
	}
	return nil
}

// sqliteLiteral wraps s in single quotes with internal quote-doubling.
// VACUUM INTO requires a string literal — bind parameters aren't
// supported on the target path argument.
func sqliteLiteral(s string) string {
	out := make([]byte, 0, len(s)+4)
	out = append(out, '\'')
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'', '\'')
			continue
		}
		out = append(out, s[i])
	}
	out = append(out, '\'')
	return string(out)
}

// List returns every catalog row, newest first.
func (m *Manager) List(ctx context.Context) ([]*Backup, error) {
	rows, err := m.store.DB().QueryContext(ctx,
		`SELECT id, created_at, kind, path, size_bytes, status, note, COALESCE(triggered_by,'')
		 FROM backups ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Backup
	for rows.Next() {
		b := &Backup{}
		var createdAt string
		if err := rows.Scan(&b.ID, &createdAt, &b.Kind, &b.Path, &b.SizeBytes, &b.Status, &b.Note, &b.TriggeredBy); err != nil {
			return nil, err
		}
		b.CreatedAt = parseTime(createdAt)
		out = append(out, b)
	}
	return out, rows.Err()
}

// ByID returns the catalog row for id.
func (m *Manager) ByID(ctx context.Context, id string) (*Backup, error) {
	q := `SELECT id, created_at, kind, path, size_bytes, status, note, COALESCE(triggered_by,'')
	      FROM backups WHERE id = ` + ph(m.store, 1)
	row := m.store.DB().QueryRowContext(ctx, q, id)
	b := &Backup{}
	var createdAt string
	if err := row.Scan(&b.ID, &createdAt, &b.Kind, &b.Path, &b.SizeBytes, &b.Status, &b.Note, &b.TriggeredBy); err != nil {
		return nil, err
	}
	b.CreatedAt = parseTime(createdAt)
	return b, nil
}

// Delete removes a backup catalog row + its on-disk dump file. Best-
// effort on the file; the row deletion is the source of truth.
func (m *Manager) Delete(ctx context.Context, id string) error {
	b, err := m.ByID(ctx, id)
	if err != nil {
		return err
	}
	if _, err := m.store.DB().ExecContext(ctx,
		`DELETE FROM backups WHERE id = `+ph(m.store, 1), id); err != nil {
		return err
	}
	_ = os.Remove(b.Path)
	return nil
}

func ph(st *store.Store, n int) string {
	if st.Driver() == store.DriverPostgres {
		return "$" + fmt.Sprint(n)
	}
	return "?"
}

func phList(st *store.Store, n int) string {
	out := make([]byte, 0, n*3)
	for i := 1; i <= n; i++ {
		if i > 1 {
			out = append(out, ',')
		}
		out = append(out, []byte(ph(st, i))...)
	}
	return string(out)
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}
