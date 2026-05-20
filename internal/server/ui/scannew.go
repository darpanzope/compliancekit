package ui

// v1.4 Phase 9 — Scan trigger UI with SSE live progress.
//
// Routes:
//
//	GET  /scans/new           pick provider scope + click Run
//	POST /scans/new           queues a scan row (status='queued')
//	                          then redirects to /scans/{id}
//	GET  /scans/{id}/stream   text/event-stream progress feed
//
// The SSE source polls the scans table once a second and emits an
// event whenever the row's status changes (queued → running →
// completed/failed/canceled). When the v1.4-era runner lands the
// emitter swaps to a real progress channel without changing the
// /stream contract — the client UI keeps consuming the same shape.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// scanNewView is the GET /scans/new payload — every enabled provider
// renders as a checkbox card so the operator can scope the scan.
type scanNewView struct {
	View
	Providers []scanNewProvider
	Error     string
}

type scanNewProvider struct {
	ID       string
	Name     string
	Enabled  bool
	HasToken bool
}

// mountScanNewRoutes registers the Phase 9 endpoints.
func (u *UI) mountScanNewRoutes(r chi.Router) {
	r.Get("/scans/new", u.scanNewForm)
	r.Post("/scans/new", u.scanNewSubmit)
	r.Get("/scans/{id}/stream", u.scanStream)
}

func (u *UI) scanNewForm(w http.ResponseWriter, r *http.Request) {
	rows, err := u.loadProviderRows(r.Context())
	if err != nil {
		u.fail(w, "load providers: "+err.Error())
		return
	}
	items := make([]scanNewProvider, 0, len(rows))
	for _, row := range rows {
		if !row.Configured {
			continue
		}
		raw, _ := u.providerRawConfig(r.Context(), row.ID)
		var pc providerConfig
		if raw != "" {
			_ = json.Unmarshal([]byte(raw), &pc)
		}
		items = append(items, scanNewProvider{
			ID:       row.ID,
			Name:     row.Name,
			Enabled:  row.Enabled,
			HasToken: pc.Token != "",
		})
	}
	view := scanNewView{
		View:      u.viewFor(r, "New scan", "scans", View{}),
		Providers: items,
		Error:     r.URL.Query().Get("err"),
	}
	u.render(w, "scan_new.html", view)
}

func (u *UI) scanNewSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	picked := r.PostForm["provider"]
	if len(picked) == 0 {
		http.Redirect(w, r, "/scans/new?err=no-providers", http.StatusSeeOther)
		return
	}

	// Validate each picked id against the catalog + DB-enabled flag.
	rows, err := u.loadProviderRows(r.Context())
	if err != nil {
		u.fail(w, "load providers: "+err.Error())
		return
	}
	enabledSet := map[string]bool{}
	for _, row := range rows {
		if row.Configured && row.Enabled {
			enabledSet[row.ID] = true
		}
	}
	allowed := []string{}
	for _, id := range picked {
		if enabledSet[id] {
			allowed = append(allowed, id)
		}
	}
	if len(allowed) == 0 {
		http.Redirect(w, r, "/scans/new?err=none-enabled", http.StatusSeeOther)
		return
	}

	// Queue using the existing wizard helper (it accepts a single
	// provider; loop for the multi-pick case). The worker pool picks
	// the row up via the v1.3 phase 8 producer.
	scanID, err := u.enqueueWizardScanMulti(r.Context(), allowed)
	if err != nil {
		u.fail(w, "enqueue: "+err.Error())
		return
	}
	u.AuditLog(r.Context(), "scan.trigger", "scan", scanID, map[string]any{
		"providers": allowed, "source": "ui",
	})
	http.Redirect(w, r, "/scans/"+scanID+"?welcome=0&new=1", http.StatusSeeOther)
}

// enqueueWizardScanMulti is the n-provider variant of
// enqueueWizardScan (Phase 1). Stores a single scan row whose
// providers_scanned JSON array carries every picked id; the worker
// runner walks the array.
func (u *UI) enqueueWizardScanMulti(ctx context.Context, providerIDs []string) (string, error) {
	js, _ := json.Marshal(providerIDs)
	frameworks := []byte("[]")
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339)
	q := `INSERT INTO scans (id, created_at, source, status, providers_scanned,
	                         frameworks_scanned, score, coverage, total_findings,
	                         actionable_findings)
	      VALUES (` + phList(u.store, 10) + `)`
	_, err := u.store.DB().ExecContext(ctx, q,
		id, now, "daemon", "queued",
		string(js), string(frameworks),
		0, 0, 0, 0)
	return id, err
}

// scanStream is the SSE feed. Polls the scans row's status once a
// second and emits an event on every change. Closes the connection
// after a terminal status (completed/failed/canceled) is observed
// so the client doesn't keep a socket open forever.
func (u *UI) scanStream(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	if scanID == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx proxy buffering

	// Send an initial sync so the client can render starting state
	// without waiting a poll tick.
	if !u.emitScanEvent(w, scanID) {
		return
	}
	flusher.Flush()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	timeout := time.After(5 * time.Minute) // cap any one connection at 5min

	var lastStatus string
	for {
		select {
		case <-r.Context().Done():
			return
		case <-timeout:
			fmt.Fprint(w, "event: timeout\ndata: {\"message\":\"client timeout after 5 minutes\"}\n\n")
			flusher.Flush()
			return
		case <-ticker.C:
			status, terminal := u.readScanStatus(r.Context(), scanID)
			if status != lastStatus {
				if !u.emitScanEvent(w, scanID) {
					return
				}
				flusher.Flush()
				lastStatus = status
			}
			if terminal {
				return
			}
		}
	}
}

// emitScanEvent sends a single SSE message describing the scan row.
// Returns false if the row vanished (caller should close the stream).
func (u *UI) emitScanEvent(w http.ResponseWriter, scanID string) bool {
	row, ok := u.loadScanProgress(scanID)
	if !ok {
		fmt.Fprint(w, "event: error\ndata: {\"message\":\"scan not found\"}\n\n")
		return false
	}
	payload, _ := json.Marshal(row)
	fmt.Fprintf(w, "event: status\ndata: %s\n\n", payload)
	return true
}

// scanProgressEvent is the per-event payload the SSE stream emits.
type scanProgressEvent struct {
	ID                 string `json:"id"`
	Status             string `json:"status"`
	TotalFindings      int    `json:"total_findings"`
	ActionableFindings int    `json:"actionable_findings"`
	Score              int    `json:"score"`
}

func (u *UI) loadScanProgress(scanID string) (scanProgressEvent, bool) {
	var ev scanProgressEvent
	err := u.store.DB().QueryRow(
		`SELECT id, status, total_findings, actionable_findings, COALESCE(score,0)
		 FROM scans WHERE id = `+ph(u.store, 1),
		scanID).Scan(&ev.ID, &ev.Status, &ev.TotalFindings, &ev.ActionableFindings, &ev.Score)
	if err != nil {
		return ev, false
	}
	return ev, true
}

func (u *UI) readScanStatus(_ context.Context, scanID string) (status string, terminal bool) {
	var s string
	_ = u.store.DB().QueryRow(`SELECT status FROM scans WHERE id = `+ph(u.store, 1), scanID).Scan(&s)
	terminal = s == "completed" || s == "failed" || s == "canceled"
	return s, terminal
}
