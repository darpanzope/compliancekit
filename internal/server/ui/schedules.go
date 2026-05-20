package ui

// v1.4 Phase 10 — Cron scheduler.
//
// Lets the operator define cron-scheduled scans that the worker pool
// fires. Each schedule has a cron_expr + IANA timezone + provider
// scope + framework scope. The daemon computes next_run_at at insert
// time and updates it whenever the schedule runs.
//
// Routes:
//
//	GET  /schedules                  list
//	GET  /schedules/new              create form
//	POST /schedules                  create
//	POST /schedules/{id}/delete      delete
//	POST /schedules/{id}/run-now     manual trigger
//
// The actual cron loop (poll schedules table for next_run_at <= now)
// is a future enhancement — this phase ships the data shape + the UI
// surface, and the existing scan-queue handler runs as soon as
// "Run now" is hit.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
)

// scheduleRow is the per-row payload the list template iterates over.
type scheduleRow struct {
	ID         string
	Name       string
	CronExpr   string
	Timezone   string
	Providers  []string
	Frameworks []string
	NextRunAt  string
	NextRunIn  string
	LastRunAt  string
	LastRunIn  string
}

type schedulesView struct {
	View
	Items []scheduleRow
	Flash string
	Error string
}

type scheduleNewView struct {
	View
	Providers []scanNewProvider
	Error     string
}

// mountScheduleRoutes registers the Phase 10 endpoints.
func (u *UI) mountScheduleRoutes(r chi.Router) {
	r.Get("/schedules", u.schedulesList)
	r.Get("/schedules/new", u.schedulesNewForm)
	r.Post("/schedules", u.schedulesCreate)
	r.Post("/schedules/{id}/delete", u.schedulesDelete)
	r.Post("/schedules/{id}/run-now", u.schedulesRunNow)
}

func (u *UI) schedulesList(w http.ResponseWriter, r *http.Request) {
	items, err := u.loadSchedules(r.Context())
	if err != nil {
		u.fail(w, "load schedules: "+err.Error())
		return
	}
	view := schedulesView{
		View:  u.viewFor(r, "Schedules · Settings", "settings", View{}),
		Items: items,
		Flash: r.URL.Query().Get("flash"),
		Error: r.URL.Query().Get("err"),
	}
	u.render(w, "schedules.html", view)
}

func (u *UI) schedulesNewForm(w http.ResponseWriter, r *http.Request) {
	rows, err := u.loadProviderRows(r.Context())
	if err != nil {
		u.fail(w, "load providers: "+err.Error())
		return
	}
	items := []scanNewProvider{}
	for _, row := range rows {
		if !row.Configured {
			continue
		}
		items = append(items, scanNewProvider{
			ID:      row.ID,
			Name:    row.Name,
			Enabled: row.Enabled,
		})
	}
	view := scheduleNewView{
		View:      u.viewFor(r, "New schedule", "settings", View{}),
		Providers: items,
		Error:     r.URL.Query().Get("err"),
	}
	u.render(w, "schedules_new.html", view)
}

// cronParser shared across the package — 5-field standard cron syntax
// (minute, hour, day-of-month, month, day-of-week).
var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

func (u *UI) schedulesCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	expr := strings.TrimSpace(r.PostForm.Get("cron_expr"))
	tz := strings.TrimSpace(r.PostForm.Get("timezone"))
	providers := r.PostForm["provider"]
	if name == "" || expr == "" {
		http.Redirect(w, r, "/schedules/new?err=missing-fields", http.StatusSeeOther)
		return
	}
	if tz == "" {
		tz = "UTC"
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		http.Redirect(w, r, "/schedules/new?err=bad-timezone", http.StatusSeeOther)
		return
	}
	sched, err := cronParser.Parse(expr)
	if err != nil {
		http.Redirect(w, r, "/schedules/new?err=bad-cron", http.StatusSeeOther)
		return
	}
	nextRun := sched.Next(time.Now().In(loc)).UTC().Format(time.RFC3339)

	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339)
	provJSON, _ := json.Marshal(providers)
	fwJSON := []byte("[]")
	q := `INSERT INTO schedules (id, name, cron_expr, timezone, providers, frameworks,
	                              created_at, next_run_at)
	      VALUES (` + phList(u.store, 8) + `)`
	_, err = u.store.DB().ExecContext(r.Context(), q,
		id, name, expr, tz, string(provJSON), string(fwJSON), now, nextRun)
	if err != nil {
		u.fail(w, "create schedule: "+err.Error())
		return
	}
	u.AuditLog(r.Context(), "schedule.create", "schedule", id, map[string]any{
		"name": name, "cron_expr": expr, "timezone": tz, "providers": providers,
	})
	http.Redirect(w, r, "/schedules?flash=created", http.StatusSeeOther)
}

func (u *UI) schedulesDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_, err := u.store.DB().ExecContext(r.Context(),
		`DELETE FROM schedules WHERE id = `+ph(u.store, 1), id)
	if err != nil {
		u.fail(w, "delete: "+err.Error())
		return
	}
	u.AuditLog(r.Context(), "schedule.delete", "schedule", id, nil)
	http.Redirect(w, r, "/schedules?flash=deleted", http.StatusSeeOther)
}

// schedulesRunNow ignores the cron expression and immediately queues
// a scan for the schedule's providers. Useful for "test this schedule
// right now" without waiting for next_run_at.
func (u *UI) schedulesRunNow(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var provJSON string
	err := u.store.DB().QueryRowContext(r.Context(),
		`SELECT providers FROM schedules WHERE id = `+ph(u.store, 1), id).Scan(&provJSON)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var providers []string
	_ = json.Unmarshal([]byte(provJSON), &providers)
	if len(providers) == 0 {
		http.Redirect(w, r, "/schedules?err=no-providers", http.StatusSeeOther)
		return
	}
	scanID, err := u.enqueueWizardScanMulti(r.Context(), providers)
	if err != nil {
		u.fail(w, "enqueue: "+err.Error())
		return
	}
	// Record this manual run on the schedule row for the next "last
	// run" hint.
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = u.store.DB().ExecContext(r.Context(),
		`UPDATE schedules SET last_run_at = `+ph(u.store, 1)+`, last_run_scan_id = `+ph(u.store, 2)+
			` WHERE id = `+ph(u.store, 3),
		now, scanID, id)
	http.Redirect(w, r, "/scans/"+scanID, http.StatusSeeOther)
}

func (u *UI) loadSchedules(ctx context.Context) ([]scheduleRow, error) {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT id, name, cron_expr, timezone, providers,
		        COALESCE(next_run_at,''), COALESCE(last_run_at,'')
		 FROM schedules ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []scheduleRow{}
	now := time.Now()
	for rows.Next() {
		var s scheduleRow
		var provJSON string
		if err := rows.Scan(&s.ID, &s.Name, &s.CronExpr, &s.Timezone, &provJSON,
			&s.NextRunAt, &s.LastRunAt); err != nil {
			return out, err
		}
		_ = json.Unmarshal([]byte(provJSON), &s.Providers)
		if s.NextRunAt != "" {
			if t, e := time.Parse(time.RFC3339, s.NextRunAt); e == nil {
				s.NextRunIn = humanizeUntil(t, now)
			}
		}
		if s.LastRunAt != "" {
			if t, e := time.Parse(time.RFC3339, s.LastRunAt); e == nil {
				s.LastRunIn = humanizeAgo(t.UTC().Format(time.RFC3339))
			}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
