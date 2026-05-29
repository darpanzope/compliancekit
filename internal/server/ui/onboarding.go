package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/ui/design"
)

// tourDef is one replayable feature tour. The step content lives in the
// page templates as `data-ck-tour="<ID>"` attributes (tour.js collects
// them); this registry just powers the /onboarding replay list + the
// "what tours exist" surface. v1.19 phase 0.
type tourDef struct {
	ID          string
	Title       string
	Description string
	Href        string // page that hosts the tour; ?tour=<ID> auto-starts it
}

// tours is the shipped tour catalog. Add a tour here + tag the touched
// elements with data-ck-tour="<ID>" in the relevant template.
var tours = []tourDef{
	{
		ID:          "welcome",
		Title:       "Welcome tour",
		Description: "A guided walk through the four surfaces you'll use daily — Scans, Findings, Checks, and Settings.",
		Href:        "/scans?tour=welcome",
	},
	{
		ID:          "search",
		Title:       "Global search",
		Description: "Find any finding, resource, scan, or setting from anywhere with Cmd+K (or press /).",
		Href:        "/scans?tour=search",
	},
}

// onboardingView is the /onboarding payload.
type onboardingView struct {
	View
	Tours     []tourDef
	Dismissed map[string]bool
}

func (u *UI) mountOnboardingRoutes(r chi.Router) {
	r.Get("/onboarding", u.onboardingPage)
	r.Post("/onboarding/tours/{id}/dismiss", u.dismissTourHandler)
	r.Post("/onboarding/reset", u.resetToursHandler)
}

func (u *UI) onboardingPage(w http.ResponseWriter, r *http.Request) {
	dismissed := map[string]bool{}
	if sess := auth.FromContext(r.Context()); sess != nil {
		for _, id := range u.dismissedTours(r.Context(), sess.UserID) {
			dismissed[id] = true
		}
	}
	v := onboardingView{
		View:      u.viewFor(r, "Onboarding", "", View{}),
		Tours:     tours,
		Dismissed: dismissed,
	}
	u.render(w, "onboarding.html", v)
}

// dismissTourHandler records that the session user has dismissed /
// completed a tour. Idempotent (INSERT OR REPLACE). Returns 204.
func (u *UI) dismissTourHandler(w http.ResponseWriter, r *http.Request) {
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing tour id", http.StatusBadRequest)
		return
	}
	if err := u.dismissTour(r.Context(), sess.UserID, id); err != nil {
		u.fail(w, "dismiss tour: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// resetToursHandler clears every dismissed-tour row for the session
// user so all tours auto-prompt again. Redirects back to /onboarding.
func (u *UI) resetToursHandler(w http.ResponseWriter, r *http.Request) {
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	if _, err := u.store.DB().ExecContext(r.Context(),
		`DELETE FROM user_tour_state WHERE user_id = `+ph(u.store, 1), sess.UserID); err != nil {
		u.fail(w, "reset tours: "+err.Error())
		return
	}
	http.Redirect(w, r, "/onboarding", http.StatusSeeOther)
}

// dismissTour upserts a (user, tour) dismissal row.
func (u *UI) dismissTour(ctx context.Context, userID, tourID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	// INSERT ... ON CONFLICT works on both SQLite + Postgres for the
	// composite PK; matches the upsert style used elsewhere in the UI.
	_, err := u.store.DB().ExecContext(ctx,
		`INSERT INTO user_tour_state (user_id, tour_id, dismissed_at) VALUES (`+
			ph(u.store, 1)+`, `+ph(u.store, 2)+`, `+ph(u.store, 3)+`) `+
			`ON CONFLICT (user_id, tour_id) DO UPDATE SET dismissed_at = `+ph(u.store, 4),
		userID, tourID, now, now)
	return err
}

// dismissedTours returns the tour IDs the user has dismissed. Errors
// are swallowed to an empty slice — a tour-state read must never break
// a page render.
func (u *UI) dismissedTours(ctx context.Context, userID string) []string {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT tour_id FROM user_tour_state WHERE user_id = `+ph(u.store, 1), userID)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return out
		}
		out = append(out, id)
	}
	return out
}

// jsonArray renders a []string as a JSON array string for the body
// data-attribute tour.js reads. nil/empty → "[]".
func jsonArray(ids []string) string {
	if len(ids) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ids)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// containsString reports whether s is in xs.
func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// firstRunCoach is the v1.19 phase 3 empty-state coaching card the scans
// page shows when the operator has zero scans: the no-scans illustration
// + a deep-linked 3-step CTA that walks them from connecting a provider
// through reviewing findings.
func firstRunCoach() design.EmptyStateArgs {
	return design.EmptyStateArgs{
		Illustration: design.Illustration("no-scans"),
		Title:        "Let's run your first scan",
		Description:  "Three steps to your first compliance report.",
		Steps: []design.EmptyStep{
			{Text: "Connect a provider (AWS / GCP / DO / Hetzner / K8s / Linux).", Href: "/setup", CTA: "Connect →"},
			{Text: "Run a scan against it.", Href: "/scans/new", CTA: "Run scan →"},
			{Text: "Review + triage the findings.", Href: "/findings", CTA: "Findings →"},
		},
	}
}
