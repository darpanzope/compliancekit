// Package worker is the v1.3 background job runner. The daemon
// spawns a Pool at startup; the pool polls scans WHERE status =
// 'queued' (SQLite) or LISTENs on a Postgres channel for new rows,
// transitions each picked-up row through running → completed/failed,
// and invokes a Runner for the actual work.
//
// In phase 8 the Runner is a stub: it logs "would scan providers X"
// and marks the row completed with zero findings. The real scan-
// engine integration ships with v1.4 phase 9 (scan-now SSE flow),
// where the studio loads the operator's compliancekit.yaml +
// constructs the Engine + streams progress. The interface here is
// designed so swapping in a real Runner is a one-line constructor
// change with no schema or API impact.
//
// LISTEN/NOTIFY for Postgres lets multiple daemon replicas share a
// single queue without polling. SQLite drops to a 500ms polling
// loop — fine for the single-process case Default sqlite serves.
package worker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// Pool is the running background worker pool. Construct via New;
// start with Start (returns immediately after spawning goroutines);
// stop via the parent context's cancellation.
type Pool struct {
	store       *store.Store
	runner      Runner
	concurrency int
	pollEvery   time.Duration
	log         *slog.Logger
	wg          sync.WaitGroup
}

// Job is one row picked off the queue. The pool hands it to the
// Runner; the runner decides what to do with the providers /
// frameworks list (in phase 8 the stub just logs).
type Job struct {
	ScanID            string
	ProvidersScanned  []string
	FrameworksScanned []string
	TriggeredByUser   string
	TriggeredByToken  string
}

// Runner is the work-doer. Real implementations call
// compliancekit's Engine; the phase-8 default just stubs.
type Runner interface {
	Run(ctx context.Context, j Job) error
}

// RunnerFunc adapts a function to the Runner interface.
type RunnerFunc func(ctx context.Context, j Job) error

func (f RunnerFunc) Run(ctx context.Context, j Job) error { return f(ctx, j) }

// StubRunner is the phase-8 default: log + sleep 100ms + mark
// completed. Wired into Pool.New() so the daemon comes up runnable
// without any extra dep — v1.4 phase 9 swaps this for a real
// scan-engine Runner.
var StubRunner Runner = RunnerFunc(func(_ context.Context, j Job) error {
	slog.Default().Info("worker: stub scan run",
		"scan_id", j.ScanID,
		"providers", j.ProvidersScanned,
	)
	// Simulate a tiny amount of work so timing fields in scans get
	// non-zero values for the v1.4 studio's progress UI demo.
	time.Sleep(50 * time.Millisecond)
	return nil
})

// Config is the runtime knobs the pool takes. Zero values resolve to
// sensible defaults via Default.
type Config struct {
	// Concurrency caps how many jobs run in parallel. 0 → 2.
	Concurrency int

	// PollEvery is how often the SQLite path scans the scans table
	// for new queued rows. Ignored on Postgres (LISTEN/NOTIFY is
	// event-driven). 0 → 500ms.
	PollEvery time.Duration

	// Runner is the work-doer. Defaults to StubRunner if nil.
	Runner Runner

	// Log destination. Defaults to slog.Default().
	Log *slog.Logger
}

// Default returns the recommended baseline Config.
func Default() Config {
	return Config{
		Concurrency: 2,
		PollEvery:   500 * time.Millisecond,
		Runner:      StubRunner,
		Log:         slog.Default(),
	}
}

// New constructs the pool. Call Start to begin processing jobs.
func New(st *store.Store, cfg Config) *Pool {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 2
	}
	if cfg.PollEvery <= 0 {
		cfg.PollEvery = 500 * time.Millisecond
	}
	if cfg.Runner == nil {
		cfg.Runner = StubRunner
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Pool{
		store:       st,
		runner:      cfg.Runner,
		concurrency: cfg.Concurrency,
		pollEvery:   cfg.PollEvery,
		log:         cfg.Log,
	}
}

// Start spawns the worker goroutines. Returns immediately. Workers
// stop when ctx is canceled and Wait()-able via the pool's internal
// WaitGroup (use Stop()).
func (p *Pool) Start(ctx context.Context) {
	jobs := make(chan Job, p.concurrency*2)

	// Producer: SQLite path uses a poll loop; Postgres uses
	// LISTEN/NOTIFY when phase-2 wiring is fully exercised. For
	// portability in v1.3 both go through the polling loop; v1.4
	// adds the LISTEN/NOTIFY optimization for the Postgres case.
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ticker := time.NewTicker(p.pollEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				close(jobs)
				return
			case <-ticker.C:
				p.drainQueue(ctx, jobs)
			}
		}
	}()

	// v1.5.1 phase 6 (F4): schedules cron loop. Polls the schedules
	// table for rows whose next_run_at has passed, enqueues a scan
	// for each, rolls next_run_at forward via robfig/cron/v3. The
	// v1.4 Studio's /schedules form already writes rows here; this
	// is the missing producer that turns them into actual scans.
	p.startCronLoop(ctx)

	// Consumers.
	for i := 0; i < p.concurrency; i++ {
		p.wg.Add(1)
		go func(idx int) {
			defer p.wg.Done()
			for j := range jobs {
				p.handleJob(ctx, j)
			}
			p.log.Debug("worker shut down", "worker", idx)
		}(i)
	}
}

// Stop waits for every spawned goroutine to exit. Call after the
// parent context is canceled.
func (p *Pool) Stop() { p.wg.Wait() }

// drainQueue picks up every queued row in order and pushes them to
// the jobs channel. Each row is transitioned to status='running'
// inside the same SELECT...UPDATE transaction (with a fresh
// triggered_at timestamp). Failed updates simply skip the row — the
// next tick will retry.
func (p *Pool) drainQueue(ctx context.Context, jobs chan<- Job) {
	for {
		j, ok := p.claimOne(ctx)
		if !ok {
			return
		}
		select {
		case <-ctx.Done():
			return
		case jobs <- j:
		}
	}
}

// claimOne uses a tx to find the oldest queued scan + mark it
// running. Returns (Job, true) on success; (zero, false) when the
// queue is empty or on error.
func (p *Pool) claimOne(ctx context.Context) (Job, bool) {
	tx, err := p.store.DB().BeginTx(ctx, nil)
	if err != nil {
		p.log.Debug("worker: begin tx failed", "err", err)
		return Job{}, false
	}
	defer func() { _ = tx.Rollback() }()

	const selectQ = `SELECT id, providers_scanned, frameworks_scanned,
		        COALESCE(triggered_by_user_id, ''), COALESCE(triggered_by_token_id, '')
		 FROM scans WHERE status = 'queued' ORDER BY created_at ASC LIMIT 1`
	var (
		id, providersJSON, frameworksJSON, userID, tokenID string
	)
	if err := tx.QueryRowContext(ctx, selectQ).Scan(&id, &providersJSON, &frameworksJSON, &userID, &tokenID); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			p.log.Debug("worker: select queued failed", "err", err)
		}
		return Job{}, false
	}
	now := time.Now().UTC().Format(time.RFC3339)
	updateQ := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`UPDATE scans SET status = 'running', started_at = %s WHERE id = %s AND status = 'queued'`,
		p.ph(1), p.ph(2))
	res, err := tx.ExecContext(ctx, updateQ, now, id)
	if err != nil {
		p.log.Debug("worker: transition failed", "err", err)
		return Job{}, false
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		// Lost the race to a sibling worker; let them have it.
		return Job{}, false
	}
	if err := tx.Commit(); err != nil {
		p.log.Debug("worker: commit failed", "err", err)
		return Job{}, false
	}

	var providers, frameworks []string
	_ = json.Unmarshal([]byte(providersJSON), &providers)
	_ = json.Unmarshal([]byte(frameworksJSON), &frameworks)
	return Job{
		ScanID:            id,
		ProvidersScanned:  providers,
		FrameworksScanned: frameworks,
		TriggeredByUser:   userID,
		TriggeredByToken:  tokenID,
	}, true
}

// handleJob invokes the Runner + updates the scan row to either
// completed or failed based on the result. Run errors get persisted
// in error_message + the failed status; ctx cancellation transitions
// to failed with "canceled" so a daemon shutdown doesn't leave a
// stuck-in-running row.
func (p *Pool) handleJob(ctx context.Context, j Job) {
	start := time.Now()
	runErr := p.runner.Run(ctx, j)

	now := time.Now().UTC().Format(time.RFC3339)
	duration := int(time.Since(start).Milliseconds())

	if errors.Is(ctx.Err(), context.Canceled) {
		p.updateScanFailed(context.Background(), j.ScanID, now, "canceled by shutdown", duration)
		return
	}
	if runErr != nil {
		p.log.Warn("worker: scan failed", "scan_id", j.ScanID, "err", runErr)
		p.updateScanFailed(ctx, j.ScanID, now, runErr.Error(), duration)
		return
	}
	p.updateScanCompleted(ctx, j.ScanID, now, duration)
}

func (p *Pool) updateScanCompleted(ctx context.Context, id, finishedAt string, durationMS int) {
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`UPDATE scans SET status = 'completed', finished_at = %s, duration_ms = %s WHERE id = %s`,
		p.ph(1), p.ph(2), p.ph(3))
	if _, err := p.store.DB().ExecContext(ctx, q, finishedAt, durationMS, id); err != nil {
		p.log.Warn("worker: mark completed failed", "scan_id", id, "err", err)
	}
}

func (p *Pool) updateScanFailed(ctx context.Context, id, finishedAt, message string, durationMS int) {
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`UPDATE scans SET status = 'failed', finished_at = %s, duration_ms = %s, error_message = %s WHERE id = %s`,
		p.ph(1), p.ph(2), p.ph(3), p.ph(4))
	if _, err := p.store.DB().ExecContext(ctx, q, finishedAt, durationMS, message, id); err != nil {
		p.log.Warn("worker: mark failed failed", "scan_id", id, "err", err)
	}
}

func (p *Pool) ph(n int) string {
	if p.store.Driver() == store.DriverPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}
