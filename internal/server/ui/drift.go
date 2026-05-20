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

	"github.com/darpanzope/compliancekit/internal/server/collab"
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
	// v1.8 phase 3 — chronological collaboration events alongside the
	// scan-driven lifecycle. Rendered as a second timeline below the
	// scan history.
	Activity []activityEvent
}

// activityEvent is the template-friendly projection of a
// collab.Activity row.
type activityEvent struct {
	ID        string
	When      string // humanized
	Kind      string
	KindLabel string
	Actor     string
	Source    string
	Detail    string
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

	// Layer collaboration activity onto the same view; the template
	// renders both timelines side-by-side. Failures here are
	// non-fatal — the scan-history list is still useful.
	if acts, err := u.activities().List(r.Context(), fingerprint); err == nil {
		v.Activity = make([]activityEvent, 0, len(acts))
		for _, a := range acts {
			v.Activity = append(v.Activity, projectActivity(a, now))
		}
	}

	_ = row // suppress unused — kept for symmetry with sibling handlers
	u.renderPartial(w, "drift_timeline", v)
}

// projectActivity turns a collab.Activity row into the template-
// friendly activityEvent shape.
func projectActivity(a collabActivityRow, now time.Time) activityEvent {
	actor := a.ActorName
	if actor == "" {
		actor = a.ActorEmail
	}
	if actor == "" {
		actor = "system"
	}
	return activityEvent{
		ID:        a.ID,
		When:      humanizeAgoFrom(a.CreatedAt, now),
		Kind:      a.Kind,
		KindLabel: activityKindLabel(a.Kind),
		Actor:     actor,
		Source:    a.ActorSource,
		Detail:    activityDetail(a),
	}
}

// collabActivityRow is a tiny alias so this file doesn't have to
// import the collab package twice (Activity is already used via
// u.activities()).
type collabActivityRow = collab.Activity

// activityKindLabel maps the kind constant to operator-readable
// text. Keep the strings tight; the timeline UI is dense.
func activityKindLabel(kind string) string {
	switch kind {
	case collab.ActivityStateChanged:
		return "status changed"
	case collab.ActivityCommentAdded:
		return "commented"
	case collab.ActivityCommentEdited:
		return "edited comment"
	case collab.ActivityWaiverApplied:
		return "waiver applied"
	case collab.ActivityWaiverRevoked:
		return "waiver revoked"
	case collab.ActivityScanRan:
		return "scan ran"
	case collab.ActivityWebhookEvent:
		return "webhook event"
	case collab.ActivityAssigned:
		return "assigned"
	case collab.ActivityUnassigned:
		return "unassigned"
	case collab.ActivityOwnerChanged:
		return "owner changed"
	case collab.ActivityFollowerAdded:
		return "follower added"
	case collab.ActivityFollowerRemoved:
		return "follower removed"
	}
	return kind
}

// activityDetail picks the most useful slice of metadata for the
// row. Returns "" when nothing extra is useful.
func activityDetail(a collabActivityRow) string {
	if a.Kind == collab.ActivityStateChanged {
		from, _ := a.Metadata["from"].(string)
		to, _ := a.Metadata["to"].(string)
		if from != "" && to != "" {
			return from + " → " + to
		}
	}
	return ""
}
