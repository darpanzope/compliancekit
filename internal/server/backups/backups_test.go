package backups

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

func TestSQLiteBackupRoundtrip(t *testing.T) {
	ctx := context.Background()
	src := filepath.Join(t.TempDir(), "src.db")
	st, err := store.OpenSQLite(ctx, src)
	if err != nil {
		t.Fatalf("OpenSQLite src: %v", err)
	}
	defer func() { _ = st.Close() }()
	if err := st.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}

	// Seed a row so we can verify the dump is non-empty.
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO users (id, email, display_name, is_admin, created_at) VALUES (?, ?, ?, 1, ?)`,
		"u-1", "alice@example.com", "Alice", "2026-05-22T00:00:00Z"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	dir := t.TempDir()
	m := New(st, dir, "")
	b, err := m.Create(ctx, "test-note", "u-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if b.Status != "ok" {
		t.Errorf("status=%q want ok", b.Status)
	}
	if b.SizeBytes <= 0 {
		t.Errorf("size_bytes=%d, want >0", b.SizeBytes)
	}
	if _, err := os.Stat(b.Path); err != nil {
		t.Errorf("dump file missing: %v", err)
	}

	// Open the dump as a fresh SQLite and verify the user row landed.
	dst, err := store.OpenSQLite(ctx, b.Path)
	if err != nil {
		t.Fatalf("OpenSQLite dump: %v", err)
	}
	defer func() { _ = dst.Close() }()
	var email string
	if err := dst.DB().QueryRowContext(ctx, `SELECT email FROM users WHERE id = ?`, "u-1").Scan(&email); err != nil {
		t.Fatalf("read dump: %v", err)
	}
	if email != "alice@example.com" {
		t.Errorf("dump missing seeded row, got email=%q", email)
	}

	// Catalog listing should report the backup.
	items, err := m.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 1 {
		t.Errorf("List returned %d items, want 1", len(items))
	}

	if err := m.Delete(ctx, b.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(b.Path); !os.IsNotExist(err) {
		t.Errorf("dump file still present after Delete: %v", err)
	}
}

func TestSqliteLiteralQuoteEscape(t *testing.T) {
	got := sqliteLiteral("/tmp/it's-fine.db")
	want := "'/tmp/it''s-fine.db'"
	if got != want {
		t.Errorf("sqliteLiteral: got %q want %q", got, want)
	}
}
