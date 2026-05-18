//go:build integration

// Integration tests for the Postgres backend. Gated by the
// `integration` build tag so the default `go test ./...` run stays
// CGO-free and dependency-free.
//
// To run locally:
//
//	# Start a throwaway PG:
//	docker run --rm -d -e POSTGRES_PASSWORD=ck -p 15432:5432 --name ck-pg postgres:16
//	export PG_TEST_DSN="postgres://postgres:ck@127.0.0.1:15432/postgres?sslmode=disable"
//	go test -tags=integration ./internal/server/store/
//	docker rm -f ck-pg
//
// CI sets PG_TEST_DSN against a service container.

package store

import (
	"context"
	"os"
	"testing"
)

func TestPostgres_MigrateUp_FreshDB(t *testing.T) {
	s := openTestPostgres(t)
	t.Cleanup(func() { _ = s.Close() })
	assertMigrateUpFresh(context.Background(), t, s)
}

func TestPostgres_MigrateUp_Idempotent(t *testing.T) {
	s := openTestPostgres(t)
	t.Cleanup(func() { _ = s.Close() })
	assertMigrateUpIdempotent(context.Background(), t, s)
}

func TestPostgres_MigrateUp_ForeignKeysEnforced(t *testing.T) {
	s := openTestPostgres(t)
	t.Cleanup(func() { _ = s.Close() })
	assertForeignKeysEnforced(context.Background(), t, s)
}

func TestPostgres_MigrateUp_CheckConstraints(t *testing.T) {
	s := openTestPostgres(t)
	t.Cleanup(func() { _ = s.Close() })
	assertCheckConstraints(context.Background(), t, s)
}

// openTestPostgres opens a connection against PG_TEST_DSN and
// resets the public schema so each test starts clean.
func openTestPostgres(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("PG_TEST_DSN")
	if dsn == "" {
		t.Skip("PG_TEST_DSN not set; see file header for setup instructions")
	}
	ctx := context.Background()
	s, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenPostgres: %v", err)
	}
	// Drop + recreate public schema so every test starts with a
	// blank slate; safe because PG_TEST_DSN MUST point at a
	// throwaway DB (see file header).
	if _, err := s.DB().ExecContext(ctx, `DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public`); err != nil {
		_ = s.Close()
		t.Fatalf("reset public schema: %v", err)
	}
	return s
}
