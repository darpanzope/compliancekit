package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestSchedulesCreate_HappyPath round-trips a valid cron + tz +
// providers; expects next_run_at populated.
func TestSchedulesCreate_HappyPath(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)

	form := url.Values{
		"name":      []string{"Weekly DO"},
		"cron_expr": []string{"0 4 * * 1"},
		"timezone":  []string{"UTC"},
		"provider":  []string{"digitalocean"},
	}
	req := httptest.NewRequest("POST", "/schedules", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	u.schedulesCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d want 303", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=created") {
		t.Errorf("Location=%q expected flash=created", rec.Header().Get("Location"))
	}

	var name, expr, tz, providers, nextRun string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT name, cron_expr, timezone, providers, next_run_at FROM schedules LIMIT 1`).
		Scan(&name, &expr, &tz, &providers, &nextRun); err != nil {
		t.Fatalf("query: %v", err)
	}
	if name != "Weekly DO" || expr != "0 4 * * 1" || tz != "UTC" {
		t.Errorf("fields mismatch")
	}
	if !strings.Contains(providers, "digitalocean") {
		t.Errorf("providers=%q expected to contain digitalocean", providers)
	}
	if nextRun == "" {
		t.Errorf("next_run_at empty — cron parser didn't compute next fire")
	}
}

func TestSchedulesCreate_BadCron(t *testing.T) {
	u, _ := newUIForTests(t)
	form := url.Values{"name": []string{"x"}, "cron_expr": []string{"not a cron"}}
	req := httptest.NewRequest("POST", "/schedules", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	u.schedulesCreate(rec, req)
	if !strings.Contains(rec.Header().Get("Location"), "err=bad-cron") {
		t.Errorf("Location=%q expected err=bad-cron", rec.Header().Get("Location"))
	}
}

func TestSchedulesCreate_BadTimezone(t *testing.T) {
	u, _ := newUIForTests(t)
	form := url.Values{
		"name":      []string{"x"},
		"cron_expr": []string{"* * * * *"},
		"timezone":  []string{"Galaxy/Saturn"},
	}
	req := httptest.NewRequest("POST", "/schedules", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	u.schedulesCreate(rec, req)
	if !strings.Contains(rec.Header().Get("Location"), "err=bad-timezone") {
		t.Errorf("Location=%q expected err=bad-timezone", rec.Header().Get("Location"))
	}
}

func TestSchedulesRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountScheduleRoutes(r)
	for _, path := range []string{"/schedules", "/schedules/new"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("GET %s: 404 (route not mounted)", path)
		}
	}
}
