package warehouse

// Schedule + Scheduler — v1.17 phase 7. Drives nightly warehouse
// loads from rows in the warehouse_schedules table. Mirrors the
// v1.5.1 schedules / v1.9 cron-driven-rules pattern: a single 30s
// loop polls the table + fires every schedule whose next_run_at
// has passed.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
)

// Schedule is one warehouse_schedules row.
type Schedule struct {
	ID           string
	Name         string
	Target       string // bigquery / snowflake / redshift
	Cron         string
	ConfigJSON   string
	SnapshotName string
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastRunAt    *time.Time
	LastStatus   string
	LastError    string
	NextRunAt    *time.Time
}

// ScheduleStore wraps the warehouse_schedules table.
type ScheduleStore struct{ db *sql.DB }

func NewScheduleStore(db *sql.DB) *ScheduleStore { return &ScheduleStore{db: db} }

// Create inserts a new schedule + computes its first next_run_at.
func (s *ScheduleStore) Create(ctx context.Context, sched Schedule) (Schedule, error) {
	if _, err := cron.ParseStandard(sched.Cron); err != nil {
		return sched, fmt.Errorf("invalid cron %q: %w", sched.Cron, err)
	}
	if sched.ID == "" {
		sched.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	sched.CreatedAt = now
	sched.UpdatedAt = now
	sched.Enabled = true
	next := nextRunTime(sched.Cron, now)
	sched.NextRunAt = &next
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO warehouse_schedules (id, name, target, cron, config_json, snapshot_name,
		                                  enabled, created_at, updated_at, next_run_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sched.ID, sched.Name, sched.Target, sched.Cron, sched.ConfigJSON,
		nullStringPtr(sched.SnapshotName), 1, now.Format(time.RFC3339), now.Format(time.RFC3339),
		next.Format(time.RFC3339))
	return sched, err
}

// Due returns every enabled schedule whose next_run_at <= now.
func (s *ScheduleStore) Due(ctx context.Context, now time.Time) ([]Schedule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, target, cron, config_json, COALESCE(snapshot_name,''),
		        enabled, created_at, updated_at,
		        COALESCE(last_run_at,''), COALESCE(last_status,''), COALESCE(last_error,''),
		        COALESCE(next_run_at,'')
		 FROM warehouse_schedules
		 WHERE enabled = 1 AND next_run_at IS NOT NULL AND next_run_at <= ?`,
		now.Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Schedule
	for rows.Next() {
		s, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// RecordRun bumps last_run_at + last_status + last_error + advances
// next_run_at. status is "ok" or "failed"; loadErr populates last_error
// when status="failed".
func (s *ScheduleStore) RecordRun(ctx context.Context, id, status string, loadErr error) error {
	now := time.Now().UTC()
	var current Schedule
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, target, cron, config_json, COALESCE(snapshot_name,''),
		        enabled, created_at, updated_at,
		        COALESCE(last_run_at,''), COALESCE(last_status,''), COALESCE(last_error,''),
		        COALESCE(next_run_at,'')
		 FROM warehouse_schedules WHERE id = ?`, id)
	current, err := scanScheduleRow(row)
	if err != nil {
		return err
	}
	next := nextRunTime(current.Cron, now)
	errStr := ""
	if loadErr != nil {
		errStr = loadErr.Error()
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE warehouse_schedules
		   SET last_run_at = ?, last_status = ?, last_error = ?, next_run_at = ?, updated_at = ?
		 WHERE id = ?`,
		now.Format(time.RFC3339), status, errStr, next.Format(time.RFC3339),
		now.Format(time.RFC3339), id)
	return err
}

// Scheduler ticks every 30s, fires Due() schedules, calls Hook for
// each. The Hook constructs + drives a Loader; failure is recorded
// via RecordRun.
type Scheduler struct {
	store *ScheduleStore
	hook  ScheduleHook
	log   *slog.Logger
}

// ScheduleHook owns the per-schedule load. The implementation
// builds a Loader from sched.Target + sched.ConfigJSON, calls
// Connect + Load over every AllTables row.
type ScheduleHook func(ctx context.Context, sched Schedule) error

// NewScheduler returns a Scheduler bound to a ScheduleStore + hook.
// Call Run with a context to block until cancellation.
func NewScheduler(s *ScheduleStore, hook ScheduleHook) *Scheduler {
	return &Scheduler{store: s, hook: hook, log: slog.Default()}
}

// Run blocks until ctx cancellation; ticks every 30s; per-tick fires
// every due schedule.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

func (s *Scheduler) tick(ctx context.Context) {
	due, err := s.store.Due(ctx, time.Now().UTC())
	if err != nil {
		s.log.Warn("warehouse scheduler: Due failed", "err", err)
		return
	}
	for _, sched := range due {
		s.fire(ctx, sched)
	}
}

func (s *Scheduler) fire(ctx context.Context, sched Schedule) {
	s.log.Info("warehouse sync: firing", "id", sched.ID, "target", sched.Target, "name", sched.Name)
	if s.hook == nil {
		_ = s.store.RecordRun(ctx, sched.ID, "failed", fmt.Errorf("no hook installed"))
		return
	}
	err := s.hook(ctx, sched)
	if err != nil {
		s.log.Warn("warehouse sync: failed", "id", sched.ID, "err", err)
		_ = s.store.RecordRun(ctx, sched.ID, "failed", err)
		return
	}
	_ = s.store.RecordRun(ctx, sched.ID, "ok", nil)
}

func nextRunTime(spec string, after time.Time) time.Time {
	parsed, err := cron.ParseStandard(spec)
	if err != nil {
		// Should never happen — Create validates — but keep the daemon
		// alive by deferring 24h on parse failures rather than panic.
		return after.Add(24 * time.Hour)
	}
	return parsed.Next(after)
}

func scanSchedule(rows *sql.Rows) (Schedule, error) {
	return scanScheduleAny(rows.Scan)
}

func scanScheduleRow(row *sql.Row) (Schedule, error) {
	return scanScheduleAny(row.Scan)
}

func scanScheduleAny(scan func(...any) error) (Schedule, error) {
	var s Schedule
	var enabled int
	var createdAt, updatedAt, lastRun, lastStatus, lastError, nextRun string
	if err := scan(&s.ID, &s.Name, &s.Target, &s.Cron, &s.ConfigJSON, &s.SnapshotName,
		&enabled, &createdAt, &updatedAt, &lastRun, &lastStatus, &lastError, &nextRun); err != nil {
		return s, err
	}
	s.Enabled = enabled != 0
	s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	s.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	s.LastStatus = lastStatus
	s.LastError = lastError
	if lastRun != "" {
		t, _ := time.Parse(time.RFC3339, lastRun)
		s.LastRunAt = &t
	}
	if nextRun != "" {
		t, _ := time.Parse(time.RFC3339, nextRun)
		s.NextRunAt = &t
	}
	return s, nil
}

// ConfigOf unmarshals the schedule's config_json into v. Targets
// keep their own config struct shape (BigQueryConfig, Snowflake-
// Config, RedshiftConfig); the hook routes to the right type.
func ConfigOf(s Schedule, v any) error {
	return json.Unmarshal([]byte(s.ConfigJSON), v)
}

func nullStringPtr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
