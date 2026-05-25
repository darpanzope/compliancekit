package dashboards

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestCreateScheduledReport_InvalidCron(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	d, _ := s.CreateDashboard(ctx, "", "", "x", "", "")
	_, err := s.CreateScheduledReport(ctx, &ScheduledReport{
		DashboardID: d.ID,
		Name:        "x",
		CronExpr:    "not-a-cron",
		Recipients:  []string{"a@x.com"},
		Enabled:     true,
	})
	if err == nil {
		t.Errorf("expected error on invalid cron")
	}
}

func TestCreateScheduledReport_HappyPath(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	d, _ := s.CreateDashboard(ctx, "", "", "x", "", "")
	r, err := s.CreateScheduledReport(ctx, &ScheduledReport{
		DashboardID: d.ID,
		Name:        "weekly",
		CronExpr:    "0 9 * * 1", // Mon 09:00
		Recipients:  []string{"alice@x.com", "bob@x.com"},
		Enabled:     true,
		Subject:     "Weekly compliance summary",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if r.NextRunAt.IsZero() {
		t.Errorf("expected NextRunAt populated, got zero")
	}
	if len(r.Recipients) != 2 {
		t.Errorf("recipients = %v want 2", r.Recipients)
	}

	list, err := s.ListScheduledReports(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("list len = %d want 1", len(list))
	}
}

func TestRunDueReports_DispatchInvoked(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	d, _ := s.CreateDashboard(ctx, "", "", "x", "", "")
	if _, err := s.CreateScheduledReport(ctx, &ScheduledReport{
		DashboardID: d.ID,
		Name:        "every-minute",
		CronExpr:    "* * * * *",
		Recipients:  []string{"a@x.com"},
		Enabled:     true,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Force next_run_at into the past so RunDueReports picks it up.
	if _, err := s.store.DB().ExecContext(ctx,
		`UPDATE scheduled_reports SET next_run_at = ?`,
		"1970-01-01T00:00:00Z"); err != nil {
		t.Fatalf("rewind: %v", err)
	}

	var mu sync.Mutex
	calls := 0
	dispatch := DispatcherFunc(func(ctx context.Context, r *ScheduledReport, d *Dashboard) error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return nil
	})
	if err := s.RunDueReports(ctx, dispatch); err != nil {
		t.Fatalf("RunDueReports: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("dispatch calls = %d want 1", calls)
	}

	// next_run_at should have advanced past now.
	list, _ := s.ListScheduledReports(ctx)
	if !list[0].NextRunAt.After(time.Now().Add(-time.Hour)) {
		t.Errorf("next_run_at not advanced: %v", list[0].NextRunAt)
	}
	if list[0].LastStatus != "ok" {
		t.Errorf("status = %q want ok", list[0].LastStatus)
	}
}

func TestRunDueReports_DispatchFailureStamped(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	d, _ := s.CreateDashboard(ctx, "", "", "x", "", "")
	if _, err := s.CreateScheduledReport(ctx, &ScheduledReport{
		DashboardID: d.ID,
		Name:        "every-minute",
		CronExpr:    "* * * * *",
		Recipients:  []string{"a@x.com"},
		Enabled:     true,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.store.DB().ExecContext(ctx,
		`UPDATE scheduled_reports SET next_run_at = ?`,
		"1970-01-01T00:00:00Z"); err != nil {
		t.Fatalf("rewind: %v", err)
	}
	dispatch := DispatcherFunc(func(ctx context.Context, r *ScheduledReport, d *Dashboard) error {
		return errSMTPRefused
	})
	if err := s.RunDueReports(ctx, dispatch); err != nil {
		t.Fatalf("RunDueReports: %v", err)
	}
	list, _ := s.ListScheduledReports(ctx)
	if list[0].LastStatus == "ok" || list[0].LastStatus == "" {
		t.Errorf("expected non-ok status, got %q", list[0].LastStatus)
	}
}

// errSMTPRefused is a stub error the dispatch-failure test uses.
var errSMTPRefused = stubError("smtp refused")

type stubError string

func (e stubError) Error() string { return string(e) }
