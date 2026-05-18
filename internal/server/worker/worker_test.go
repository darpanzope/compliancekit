package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// TestPool_HappyPath: enqueues two scans, lets the pool drain them,
// verifies both transition to completed + the runner was invoked
// twice with the right IDs.
func TestPool_HappyPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	st := openMigratedStore(t)
	t.Cleanup(func() { _ = st.Close() })

	var (
		ran     atomic.Int32
		seenIDs sync.Map
	)
	runner := RunnerFunc(func(_ context.Context, j Job) error {
		ran.Add(1)
		seenIDs.Store(j.ScanID, true)
		return nil
	})

	p := New(st, Config{
		Concurrency: 2,
		PollEvery:   50 * time.Millisecond, // fast for tests
		Runner:      runner,
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	// Seed two queued scans.
	for _, id := range []string{"scan-A", "scan-B"} {
		seedScan(t, st, id)
	}

	p.Start(ctx)
	defer p.Stop()

	// Wait for both to complete or context to expire.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ran.Load() == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	p.Stop()

	if got := ran.Load(); got != 2 {
		t.Errorf("runner invocations = %d, want 2", got)
	}
	for _, id := range []string{"scan-A", "scan-B"} {
		if _, ok := seenIDs.Load(id); !ok {
			t.Errorf("runner never saw scan %s", id)
		}
		s := getScanStatus(t, st, id)
		if s != "completed" {
			t.Errorf("scan %s ended in status %q, want completed", id, s)
		}
	}
}

// TestPool_FailedScanPersistsError: the runner returns an error;
// the pool transitions the row to failed + persists the message.
func TestPool_FailedScanPersistsError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	st := openMigratedStore(t)
	t.Cleanup(func() { _ = st.Close() })

	runner := RunnerFunc(func(_ context.Context, _ Job) error {
		return errors.New("synthetic failure")
	})
	p := New(st, Config{
		Concurrency: 1,
		PollEvery:   50 * time.Millisecond,
		Runner:      runner,
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	seedScan(t, st, "scan-fail")
	p.Start(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if getScanStatus(t, st, "scan-fail") == "failed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	p.Stop()

	if s := getScanStatus(t, st, "scan-fail"); s != "failed" {
		t.Errorf("scan-fail status = %q, want failed", s)
	}
	msg := getScanErrorMessage(t, st, "scan-fail")
	if msg != "synthetic failure" {
		t.Errorf("error_message = %q, want %q", msg, "synthetic failure")
	}
}

// TestStubRunner is the default Runner the pool uses when no real
// one is wired. Just covers the no-error contract.
func TestStubRunner(t *testing.T) {
	if err := StubRunner.Run(context.Background(), Job{ScanID: "x"}); err != nil {
		t.Errorf("StubRunner returned %v, want nil", err)
	}
}

// openMigratedStore returns an in-memory SQLite Store with the v1.3
// schema applied. Each test gets its own DB.
func openMigratedStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.OpenSQLite(context.Background(),
		"file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	if err := st.MigrateUp(context.Background()); err != nil {
		_ = st.Close()
		t.Fatalf("MigrateUp: %v", err)
	}
	return st
}

func seedScan(t *testing.T, st *store.Store, id string) {
	t.Helper()
	_, err := st.DB().ExecContext(context.Background(),
		`INSERT INTO scans (id, created_at, source, status, providers_scanned, frameworks_scanned)
		 VALUES (?, ?, ?, 'queued', '["aws"]', '["soc2"]')`,
		id, time.Now().UTC().Format(time.RFC3339), "cli")
	if err != nil {
		t.Fatalf("seed scan %s: %v", id, err)
	}
}

func getScanStatus(t *testing.T, st *store.Store, id string) string {
	t.Helper()
	var s string
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT status FROM scans WHERE id = ?`, id).Scan(&s); err != nil {
		t.Fatalf("get status %s: %v", id, err)
	}
	return s
}

func getScanErrorMessage(t *testing.T, st *store.Store, id string) string {
	t.Helper()
	var s string
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COALESCE(error_message,'') FROM scans WHERE id = ?`, id).Scan(&s); err != nil {
		t.Fatalf("get error_message %s: %v", id, err)
	}
	return s
}

// Quiet unused-import nag — fmt is used via the package's own SQL
// helpers in worker.go but the test file doesn't reference it.
var _ = fmt.Sprintf
