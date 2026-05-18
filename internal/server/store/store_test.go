package store

import (
	"context"
	"testing"
	"time"
)

// TestMigrateUp_FreshDB applies migrations against an in-memory
// SQLite + verifies every expected table is present.
func TestMigrateUp_FreshDB(t *testing.T) {
	ctx := context.Background()
	s := openTestSQLite(t)
	t.Cleanup(func() { _ = s.Close() })

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
	have := map[string]bool{}
	rows, err := s.DB().QueryContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		have[name] = true
	}
	for _, t2 := range wantTables {
		if !have[t2] {
			t.Errorf("missing table after MigrateUp: %s", t2)
		}
	}
}

// TestMigrateUp_Idempotent re-runs MigrateUp on a fresh DB twice
// + verifies the second call is a no-op.
func TestMigrateUp_Idempotent(t *testing.T) {
	ctx := context.Background()
	s := openTestSQLite(t)
	t.Cleanup(func() { _ = s.Close() })

	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("first MigrateUp: %v", err)
	}
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("second MigrateUp (should be no-op): %v", err)
	}

	var count int
	err := s.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations`).Scan(&count)
	if err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if count != 1 {
		t.Errorf("schema_migrations rows = %d, want 1 (idempotent)", count)
	}
}

// TestMigrateUp_ForeignKeysEnforced verifies that the
// foreign_keys=ON pragma is actually active — a CASCADE delete on
// scans should clear child findings rows.
func TestMigrateUp_ForeignKeysEnforced(t *testing.T) {
	ctx := context.Background()
	s := openTestSQLite(t)
	t.Cleanup(func() { _ = s.Close() })

	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.DB().ExecContext(ctx,
		`INSERT INTO scans (id, created_at, source, status) VALUES (?,?,?,?)`,
		"scan-1", now, "cli", "completed")
	if err != nil {
		t.Fatalf("insert scan: %v", err)
	}
	_, err = s.DB().ExecContext(ctx,
		`INSERT INTO findings (id, scan_id, fingerprint, check_id, severity, status, provider, resource_id, resource_name, resource_type, first_seen_at, last_seen_at, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"finding-1", "scan-1", "fp-1", "check-x", "high", "fail",
		"aws", "res-1", "my-resource", "aws.ec2.instance",
		now, now, now)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx, `DELETE FROM scans WHERE id = 'scan-1'`); err != nil {
		t.Fatalf("delete scan: %v", err)
	}
	var leftover int
	err = s.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM findings WHERE scan_id = 'scan-1'`).Scan(&leftover)
	if err != nil {
		t.Fatalf("count findings: %v", err)
	}
	if leftover != 0 {
		t.Errorf("findings leftover after scan delete = %d, want 0 (CASCADE should clear them)", leftover)
	}
}

// TestMigrateUp_CheckConstraints exercises a few of the CHECK
// constraints in the schema so a careless ALTER doesn't drop them.
func TestMigrateUp_CheckConstraints(t *testing.T) {
	ctx := context.Background()
	s := openTestSQLite(t)
	t.Cleanup(func() { _ = s.Close() })
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)

	// scans.source has a fixed allowed-set.
	_, err := s.DB().ExecContext(ctx,
		`INSERT INTO scans (id, created_at, source, status) VALUES (?,?,?,?)`,
		"scan-bad", now, "totally-made-up", "completed")
	if err == nil {
		t.Error("expected CHECK violation for scans.source='totally-made-up', got nil")
	}

	// findings.severity has the canonical 5-value enum.
	_, err = s.DB().ExecContext(ctx,
		`INSERT INTO scans (id, created_at, source, status) VALUES (?,?,?,?)`,
		"scan-2", now, "cli", "completed")
	if err != nil {
		t.Fatalf("insert scan-2: %v", err)
	}
	_, err = s.DB().ExecContext(ctx,
		`INSERT INTO findings (id, scan_id, fingerprint, check_id, severity, status, provider, resource_id, resource_name, resource_type, first_seen_at, last_seen_at, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"finding-bad", "scan-2", "fp", "ck", "purple", "fail",
		"aws", "r", "n", "aws.ec2", now, now, now)
	if err == nil {
		t.Error("expected CHECK violation for findings.severity='purple', got nil")
	}
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
