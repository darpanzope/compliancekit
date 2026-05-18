package store

import (
	"context"
	"testing"
	"time"
)

// TestMigrateUp_FreshDB applies migrations against an in-memory
// SQLite + verifies every expected table is present.
func TestMigrateUp_FreshDB(t *testing.T) {
	s := openTestSQLite(t)
	t.Cleanup(func() { _ = s.Close() })
	assertMigrateUpFresh(context.Background(), t, s)
}

// TestMigrateUp_Idempotent re-runs MigrateUp on a fresh DB twice
// + verifies the second call is a no-op.
func TestMigrateUp_Idempotent(t *testing.T) {
	s := openTestSQLite(t)
	t.Cleanup(func() { _ = s.Close() })
	assertMigrateUpIdempotent(context.Background(), t, s)
}

// TestMigrateUp_ForeignKeysEnforced verifies that the
// foreign_keys=ON pragma is actually active — a CASCADE delete on
// scans should clear child findings rows.
func TestMigrateUp_ForeignKeysEnforced(t *testing.T) {
	s := openTestSQLite(t)
	t.Cleanup(func() { _ = s.Close() })
	assertForeignKeysEnforced(context.Background(), t, s)
}

// TestMigrateUp_CheckConstraints exercises a few of the CHECK
// constraints in the schema so a careless ALTER doesn't drop them.
func TestMigrateUp_CheckConstraints(t *testing.T) {
	s := openTestSQLite(t)
	t.Cleanup(func() { _ = s.Close() })
	assertCheckConstraints(context.Background(), t, s)
}

// TestPlaceholder verifies the dialect-aware parameter marker
// helper returns "?" for SQLite + "$N" for Postgres.
func TestPlaceholder(t *testing.T) {
	sqlite := &Store{driver: DriverSQLite}
	if got := sqlite.placeholder(1); got != "?" {
		t.Errorf("sqlite placeholder(1) = %q, want \"?\"", got)
	}
	if got := sqlite.placeholder(42); got != "?" {
		t.Errorf("sqlite placeholder(42) = %q, want \"?\"", got)
	}
	pg := &Store{driver: DriverPostgres}
	if got := pg.placeholder(1); got != "$1" {
		t.Errorf("postgres placeholder(1) = %q, want \"$1\"", got)
	}
	if got := pg.placeholder(42); got != "$42" {
		t.Errorf("postgres placeholder(42) = %q, want \"$42\"", got)
	}
}

// ─── Shared assertion helpers (called by both SQLite test funcs
//     above and the PG integration tests in postgres_integration_test.go).

func assertMigrateUpFresh(ctx context.Context, t *testing.T, s *Store) {
	t.Helper()
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	v, err := s.Version(ctx)
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if v != 1 {
		t.Errorf("Version = %d, want 1 (initial migration applied)", v)
	}
	wantTables := []string{
		"scans", "findings", "resources",
		"providers", "checks_state",
		"waivers", "users", "api_tokens",
		"schedules", "webhooks", "audit_log",
		"schema_migrations",
	}
	have := listTables(ctx, t, s)
	for _, name := range wantTables {
		if !have[name] {
			t.Errorf("missing table after MigrateUp: %s", name)
		}
	}
}

func assertMigrateUpIdempotent(ctx context.Context, t *testing.T, s *Store) {
	t.Helper()
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("first MigrateUp: %v", err)
	}
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("second MigrateUp (should be no-op): %v", err)
	}
	var count int
	err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count)
	if err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if count != 1 {
		t.Errorf("schema_migrations rows = %d, want 1 (idempotent)", count)
	}
}

func assertForeignKeysEnforced(ctx context.Context, t *testing.T, s *Store) {
	t.Helper()
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	insScan := "INSERT INTO scans (id, created_at, source, status) VALUES (" +
		s.placeholder(1) + "," + s.placeholder(2) + "," + s.placeholder(3) + "," + s.placeholder(4) + ")"
	_, err := s.DB().ExecContext(ctx, insScan, "scan-1", now, "cli", "completed")
	if err != nil {
		t.Fatalf("insert scan: %v", err)
	}
	insFinding := "INSERT INTO findings (id, scan_id, fingerprint, check_id, severity, status, provider, resource_id, resource_name, resource_type, first_seen_at, last_seen_at, created_at) VALUES (" +
		s.placeholder(1) + "," + s.placeholder(2) + "," + s.placeholder(3) + "," + s.placeholder(4) + "," +
		s.placeholder(5) + "," + s.placeholder(6) + "," + s.placeholder(7) + "," + s.placeholder(8) + "," +
		s.placeholder(9) + "," + s.placeholder(10) + "," + s.placeholder(11) + "," + s.placeholder(12) + "," + s.placeholder(13) + ")"
	_, err = s.DB().ExecContext(ctx, insFinding,
		"finding-1", "scan-1", "fp-1", "check-x", "high", "fail",
		"aws", "res-1", "my-resource", "aws.ec2.instance",
		now, now, now)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	delQ := "DELETE FROM scans WHERE id = " + s.placeholder(1)
	if _, err := s.DB().ExecContext(ctx, delQ, "scan-1"); err != nil {
		t.Fatalf("delete scan: %v", err)
	}
	var leftover int
	countQ := "SELECT COUNT(*) FROM findings WHERE scan_id = " + s.placeholder(1)
	if err := s.DB().QueryRowContext(ctx, countQ, "scan-1").Scan(&leftover); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	if leftover != 0 {
		t.Errorf("findings leftover after scan delete = %d, want 0 (CASCADE should clear them)", leftover)
	}
}

func assertCheckConstraints(ctx context.Context, t *testing.T, s *Store) {
	t.Helper()
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	insScan := "INSERT INTO scans (id, created_at, source, status) VALUES (" +
		s.placeholder(1) + "," + s.placeholder(2) + "," + s.placeholder(3) + "," + s.placeholder(4) + ")"
	_, err := s.DB().ExecContext(ctx, insScan, "scan-bad", now, "totally-made-up", "completed")
	if err == nil {
		t.Error("expected CHECK violation for scans.source='totally-made-up', got nil")
	}
	if _, err := s.DB().ExecContext(ctx, insScan, "scan-2", now, "cli", "completed"); err != nil {
		t.Fatalf("insert scan-2: %v", err)
	}
	insFinding := "INSERT INTO findings (id, scan_id, fingerprint, check_id, severity, status, provider, resource_id, resource_name, resource_type, first_seen_at, last_seen_at, created_at) VALUES (" +
		s.placeholder(1) + "," + s.placeholder(2) + "," + s.placeholder(3) + "," + s.placeholder(4) + "," +
		s.placeholder(5) + "," + s.placeholder(6) + "," + s.placeholder(7) + "," + s.placeholder(8) + "," +
		s.placeholder(9) + "," + s.placeholder(10) + "," + s.placeholder(11) + "," + s.placeholder(12) + "," + s.placeholder(13) + ")"
	_, err = s.DB().ExecContext(ctx, insFinding,
		"finding-bad", "scan-2", "fp", "ck", "purple", "fail",
		"aws", "r", "n", "aws.ec2", now, now, now)
	if err == nil {
		t.Error("expected CHECK violation for findings.severity='purple', got nil")
	}
}

// listTables reads the schema's tables in a dialect-aware way.
// SQLite uses sqlite_master; Postgres uses information_schema.
func listTables(ctx context.Context, t *testing.T, s *Store) map[string]bool {
	t.Helper()
	var q string
	switch s.Driver() {
	case DriverPostgres:
		q = `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`
	default:
		q = `SELECT name FROM sqlite_master WHERE type = 'table'`
	}
	rows, err := s.DB().QueryContext(ctx, q)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer func() { _ = rows.Close() }()
	have := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		have[name] = true
	}
	return have
}

// openTestSQLite returns a pristine in-memory SQLite Store; each
// test gets its own connection pool. ":memory:" with a cache=shared
// query string lets the pool size > 1 still see the same database.
func openTestSQLite(t *testing.T) *Store {
	t.Helper()
	s, err := OpenSQLite(context.Background(),
		"file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	return s
}
