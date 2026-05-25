package dashboards

// v1.14 phase 6 — scheduled-report storage + dispatcher.
//
// One ScheduledReport per (dashboard, cron expr, recipient list).
// The daemon's RunLoop polls scheduled_reports every minute, picks
// rows whose next_run_at has elapsed, calls the Dispatcher (an
// email sink in production; a fake in tests), and stamps
// last_run_at + last_status + the freshly-computed next_run_at.
//
// We lean on robfig/cron/v3 (already vendored at v1.9) for cron
// parsing so the daemon doesn't re-implement DST + standard schedule
// math.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
)

// ScheduledReport is the row shape.
type ScheduledReport struct {
	ID              string
	DashboardID     string
	Name            string
	CronExpr        string
	Timezone        string
	Recipients      []string
	Subject         string
	Enabled         bool
	CreatedByUserID string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastRunAt       time.Time
	LastStatus      string
	NextRunAt       time.Time
}

// Dispatcher is the callback the RunLoop invokes per due row. The
// daemon wires the v0.17 email sink + the v1.14 phase 9 PDF
// renderer behind this interface so the dashboards package stays
// dependency-free.
type Dispatcher interface {
	Send(ctx context.Context, r *ScheduledReport, d *Dashboard) error
}

// DispatcherFunc adapts a function to the Dispatcher interface.
type DispatcherFunc func(ctx context.Context, r *ScheduledReport, d *Dashboard) error

// Send implements Dispatcher.
func (f DispatcherFunc) Send(ctx context.Context, r *ScheduledReport, d *Dashboard) error {
	return f(ctx, r, d)
}

// CreateScheduledReport persists a new row. Validates the cron
// expression by parsing it through robfig/cron — invalid syntax
// fails fast at the create step instead of silently never firing.
func (s *Store) CreateScheduledReport(ctx context.Context, in *ScheduledReport) (*ScheduledReport, error) {
	if in == nil || in.Name == "" || in.DashboardID == "" || in.CronExpr == "" || len(in.Recipients) == 0 {
		return nil, errors.New("dashboards: name, dashboard_id, cron_expr, recipients required")
	}
	if in.Timezone == "" {
		in.Timezone = "UTC"
	}
	schedule, err := cron.ParseStandard(in.CronExpr)
	if err != nil {
		return nil, fmt.Errorf("invalid cron_expr: %w", err)
	}
	now := time.Now().UTC()
	in.ID = uuid.NewString()
	in.CreatedAt = now
	in.UpdatedAt = now
	in.NextRunAt = schedule.Next(now)
	q := `INSERT INTO scheduled_reports
	      (id, dashboard_id, name, cron_expr, timezone, recipients, subject, enabled,
	       created_by_user_id, created_at, updated_at, next_run_at)
	      VALUES (` + s.phList(12) + `)`
	enabled := 0
	if in.Enabled {
		enabled = 1
	}
	if _, err := s.store.DB().ExecContext(ctx, q,
		in.ID, in.DashboardID, in.Name, in.CronExpr, in.Timezone,
		strings.Join(in.Recipients, ","), in.Subject, enabled,
		nullable(in.CreatedByUserID),
		in.CreatedAt.Format(time.RFC3339),
		in.UpdatedAt.Format(time.RFC3339),
		in.NextRunAt.Format(time.RFC3339)); err != nil {
		return nil, fmt.Errorf("insert scheduled_report: %w", err)
	}
	return in, nil
}

// ListScheduledReports returns every row, newest first. Dashboards
// UI uses this for the /settings/scheduled-reports admin page.
func (s *Store) ListScheduledReports(ctx context.Context) ([]*ScheduledReport, error) {
	rows, err := s.store.DB().QueryContext(ctx,
		`SELECT id, dashboard_id, name, cron_expr, timezone, recipients,
		        subject, enabled,
		        COALESCE(created_by_user_id,''),
		        created_at, updated_at,
		        COALESCE(last_run_at,''), last_status,
		        COALESCE(next_run_at,'')
		 FROM scheduled_reports ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*ScheduledReport
	for rows.Next() {
		r := &ScheduledReport{}
		var enabled int
		var recipients, created, updated, lastRun, nextRun string
		if err := rows.Scan(&r.ID, &r.DashboardID, &r.Name, &r.CronExpr, &r.Timezone,
			&recipients, &r.Subject, &enabled, &r.CreatedByUserID,
			&created, &updated, &lastRun, &r.LastStatus, &nextRun); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		r.Recipients = splitRecipients(recipients)
		r.CreatedAt = parseTime(created)
		r.UpdatedAt = parseTime(updated)
		r.LastRunAt = parseTime(lastRun)
		r.NextRunAt = parseTime(nextRun)
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteScheduledReport removes a row.
func (s *Store) DeleteScheduledReport(ctx context.Context, id string) error {
	_, err := s.store.DB().ExecContext(ctx,
		`DELETE FROM scheduled_reports WHERE id = `+s.ph(1), id)
	return err
}

// RunDueReports picks every enabled row whose next_run_at has
// elapsed + dispatches each via d. The loop stamps last_run_at +
// last_status + the recomputed next_run_at regardless of dispatch
// outcome so the operator can see failures in the UI.
func (s *Store) RunDueReports(ctx context.Context, dispatch Dispatcher) error {
	now := time.Now().UTC()
	rows, err := s.store.DB().QueryContext(ctx,
		`SELECT id, dashboard_id, cron_expr, recipients, subject
		 FROM scheduled_reports
		 WHERE enabled = 1 AND (next_run_at IS NULL OR next_run_at <= `+s.ph(1)+`)`,
		now.Format(time.RFC3339))
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	type due struct {
		id, dashboardID, cronExpr, recipientsCSV, subject string
	}
	var dues []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.dashboardID, &d.cronExpr, &d.recipientsCSV, &d.subject); err != nil {
			return err
		}
		dues = append(dues, d)
	}
	_ = rows.Close()

	for _, d := range dues {
		schedule, err := cron.ParseStandard(d.cronExpr)
		if err != nil {
			slog.Warn("scheduled-report: bad cron",
				"id", d.id, "expr", d.cronExpr, "err", err)
			s.stampRun(ctx, d.id, "failed:invalid-cron", now)
			continue
		}
		dash, err := s.ByID(ctx, d.dashboardID)
		if err != nil {
			slog.Warn("scheduled-report: dashboard missing",
				"id", d.id, "dashboard_id", d.dashboardID, "err", err)
			s.stampRun(ctx, d.id, "failed:dashboard-missing", now)
			continue
		}
		sr := &ScheduledReport{
			ID:          d.id,
			DashboardID: d.dashboardID,
			Recipients:  splitRecipients(d.recipientsCSV),
			Subject:     d.subject,
		}
		status := "ok"
		if err := dispatch.Send(ctx, sr, dash); err != nil {
			status = "failed:" + truncated(err.Error(), 60)
			slog.Warn("scheduled-report: dispatch failed",
				"id", d.id, "err", err)
		}
		s.stampRunWithNext(ctx, d.id, status, now, schedule.Next(now))
	}
	return nil
}

func (s *Store) stampRun(ctx context.Context, id, status string, now time.Time) {
	_, _ = s.store.DB().ExecContext(ctx,
		`UPDATE scheduled_reports SET last_run_at = `+s.ph(1)+
			`, last_status = `+s.ph(2)+` WHERE id = `+s.ph(3),
		now.Format(time.RFC3339), status, id)
}

func (s *Store) stampRunWithNext(ctx context.Context, id, status string, now, next time.Time) {
	_, _ = s.store.DB().ExecContext(ctx,
		`UPDATE scheduled_reports SET last_run_at = `+s.ph(1)+
			`, last_status = `+s.ph(2)+
			`, next_run_at = `+s.ph(3)+` WHERE id = `+s.ph(4),
		now.Format(time.RFC3339), status,
		next.Format(time.RFC3339), id)
}

func splitRecipients(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func truncated(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
