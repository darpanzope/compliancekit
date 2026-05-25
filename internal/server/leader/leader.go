// Package leader implements pg_advisory_lock-based leader election
// for the v1.15 phase 4 HA Postgres mode.
//
// Each daemon holding an open Postgres connection races for a fixed
// session-scoped advisory lock; the winner becomes the worker
// leader + dispatches scans, while the standbys serve read traffic
// (UI + API) and wait for the leader to fall over. When the leader
// dies (graceful shutdown or process death), Postgres drops its
// session + releases the lock; a standby acquires it within seconds.
//
// SQLite mode is trivially leader-always-true because the
// single-replica deploy can't have a contender.
//
// Lock key: 0x636B5F6C656164 ("ck_lead") — disjoint from the
// migration lock at 0x636B5F6D69677261 ("ck_migra") in
// internal/server/store so the two never deadlock.
package leader

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// LockKey is the fixed pg_advisory_lock key the leader election
// races on. Disjoint from the migration key in store/postgres.go.
const LockKey int64 = 0x636B5F6C656164 // "ck_lead"

// PollInterval is the cadence the elector retries acquiring the
// lock when it currently holds standby. 10s balances "fail over
// quickly when the leader dies" against "don't hammer Postgres
// with pg_try_advisory_lock from every replica."
const PollInterval = 10 * time.Second

// Elector races for the advisory lock + exposes IsLeader() to the
// worker pool. Construct via New; Start launches the background
// loop; Stop releases the lock (graceful handoff).
type Elector struct {
	store  *store.Store
	conn   *sql.Conn // session-scoped; the lock dies with this conn
	leader atomic.Bool

	cancel  context.CancelFunc
	stopped chan struct{}
}

// New returns an Elector bound to st.
func New(st *store.Store) *Elector {
	return &Elector{store: st, stopped: make(chan struct{})}
}

// IsLeader reports whether this daemon currently holds the lock.
// Safe to call from any goroutine.
func (e *Elector) IsLeader() bool { return e.leader.Load() }

// Start launches the elector loop. SQLite stores short-circuit to
// leader=true immediately (no contention possible). Postgres stores
// open a dedicated session-scoped *sql.Conn + race for the lock.
//
// The returned channel is closed when Start has applied the initial
// leadership decision so callers can wait for stable state at boot.
func (e *Elector) Start(ctx context.Context) <-chan struct{} {
	ready := make(chan struct{})
	if e.store.Driver() != store.DriverPostgres {
		e.leader.Store(true)
		close(ready)
		close(e.stopped)
		return ready
	}
	ctx, e.cancel = context.WithCancel(ctx)
	go e.loop(ctx, ready)
	return ready
}

// Stop releases the advisory lock + waits for the background loop
// to exit. Idempotent.
func (e *Elector) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	<-e.stopped
}

func (e *Elector) loop(ctx context.Context, ready chan struct{}) {
	defer close(e.stopped)
	defer e.release(context.Background()) // best-effort handoff on exit

	first := true
	for {
		if err := e.maybeAcquire(ctx); err != nil {
			slog.Warn("leader: acquire failed",
				"err", err, "leader", e.leader.Load())
		}
		if first {
			close(ready)
			first = false
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(PollInterval):
		}
	}
}

// maybeAcquire grabs the lock when we don't already hold it.
// Stays no-op when we're already leader + the session is healthy.
func (e *Elector) maybeAcquire(ctx context.Context) error {
	if e.leader.Load() && e.conn != nil {
		// Cheap health check on the existing session.
		if err := e.conn.PingContext(ctx); err == nil {
			return nil
		}
		// Stale connection — drop it; pg_advisory_lock vanished with
		// the session, so we're no longer leader. Re-race.
		_ = e.conn.Close()
		e.conn = nil
		e.leader.Store(false)
	}
	conn, err := e.store.DB().Conn(ctx)
	if err != nil {
		return fmt.Errorf("conn: %w", err)
	}
	var got bool
	if err := conn.QueryRowContext(ctx,
		`SELECT pg_try_advisory_lock($1)`, LockKey).Scan(&got); err != nil {
		_ = conn.Close()
		return fmt.Errorf("try_advisory_lock: %w", err)
	}
	if !got {
		_ = conn.Close()
		return nil
	}
	e.conn = conn
	e.leader.Store(true)
	slog.Info("leader: acquired pg_advisory_lock", "key", LockKey)
	return nil
}

// release drops the advisory lock + closes the session.
func (e *Elector) release(ctx context.Context) {
	if e.conn == nil {
		return
	}
	_, _ = e.conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, LockKey)
	_ = e.conn.Close()
	e.conn = nil
	e.leader.Store(false)
	slog.Info("leader: released pg_advisory_lock", "key", LockKey)
}
