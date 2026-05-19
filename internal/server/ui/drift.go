package ui

// v1.5 Phase 7 — Drift timeline per finding.
//
// /findings/{id}/timeline returns a chrome-less partial showing the
// finding's lifecycle across every scan that ever saw it: first
// scan, intermediate status changes, latest scan. Findings join on
// fingerprint (the v0.6 baseline mechanism).
//
// The side-panel detail view (Phase 3) loads this partial into its
// Timeline tab via htmx so the operator gets the full lifecycle in
// one click.

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// driftEvent is one row in the timeline.
type driftEvent struct {
	ScanID      string
	ScanCreated string
	ScanIn      string // humanized "5d ago"
	Status      string
	Severity    string
	StatusKind  string // "first" / "change" / "stable" / "latest"
}

type driftView struct {
	View
	Events      []driftEvent
	Fingerprint string
	First       driftEvent
	Last        driftEvent
}

func (u *UI) mountDriftRoutes(r chi.Router) {
	r.Get("/findings/{id}/timeline", u.driftTimelinePartial)
}

func (u *UI) driftTimelinePartial(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row, err := u.loadFindingByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Look up the fingerprint for this finding row, then find every
	// finding that shares it (the v0.6 baseline join key).
	var fingerprint string
	_ = u.store.DB().QueryRowContext(r.Context(),
		`SELECT fingerprint FROM findings WHERE id = `+ph(u.store, 1), id).Scan(&fingerprint)

	rows, err := u.store.DB().QueryContext(r.Context(),
		`SELECT f.scan_id, s.created_at, f.status, f.severity
		 FROM findings f JOIN scans s ON s.id = f.scan_id
		 WHERE f.fingerprint = `+ph(u.store, 1)+
			` ORDER BY s.created_at ASC`,
		fingerprint)
	if err != nil {
		http.Error(w, "load timeline: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = rows.Close() }()

	events := []driftEvent{}
	now := time.Now()
	prevStatus := ""
	for rows.Next() {
		var ev driftEvent
		if err := rows.Scan(&ev.ScanID, &ev.ScanCreated, &ev.Status, &ev.Severity); err != nil {
			http.Error(w, "scan: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if t, e := time.Parse(time.RFC3339, ev.ScanCreated); e == nil {
			ev.ScanIn = humanizeAgoFrom(t, now)
		}
		switch {
		case prevStatus == "":
			ev.StatusKind = "first"
		case ev.Status != prevStatus:
			ev.StatusKind = "change"
		default:
			ev.StatusKind = "stable"
		}
		events = append(events, ev)
		prevStatus = ev.Status
	}
	if len(events) > 0 {
		events[len(events)-1].StatusKind = "latest"
	}

	v := driftView{
		View:        u.viewFor(r, "", "findings", View{}),
		Events:      events,
		Fingerprint: fingerprint,
	}
	if len(events) > 0 {
		v.First = events[0]
		v.Last = events[len(events)-1]
	}

	_ = row // suppress unused — kept for symmetry with sibling handlers
	u.renderPartial(w, "drift_timeline", v)
}
