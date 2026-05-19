package ui

// v1.4 Phase 3 — Check catalog browser w/ per-check toggles + diff
// view. Extends the v1.3 read-only /checks page with:
//
//	- free-text search across ID + title + service + tags
//	- multi-select filter chips for provider / severity / framework
//	- per-row on/off toggle persisting to the checks_state table
//	- /checks/diff page showing every override against the shipped
//	  defaults (the "tailored profile" view auditors will want for
//	  evidence packs)
//
// Phase 4 layers per-service toggles on top of this surface (a
// service-level toggle disables every check inside that service in
// one click); Phase 5 layers framework tailoring (per-control
// include/exclude with justification text). This phase keeps the
// per-check granularity as the primitive.

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// checkRow is the per-row payload the catalog template iterates over.
// Wider than v1.3's checkItem so the filter chips + diff view have
// every field they need without re-querying the registry.
type checkRow struct {
	ID               string
	Severity         string
	Provider         string
	Service          string
	Title            string
	Frameworks       []string
	Tags             []string
	EnabledByDefault bool
	Enabled          bool
	Overridden       bool // true iff the operator set checks_state for this id
}

// checksView is the catalog-page payload (search + filters + items).
type checksView struct {
	View
	Items         []checkRow
	Total         int // total registry size
	Matching      int // rows that survive the filter set
	OverrideCount int

	// Filter state echoed back into the form controls so the operator
	// sees what's selected.
	Query      string
	Severities []string
	Providers  []string
	Frameworks []string

	// Per-filter facet rosters (one of each value present in the
	// catalog). Drives the chip set without hard-coding lists.
	AllSeverities []string
	AllProviders  []string
	AllFrameworks []string
}

// mountChecksRoutes wires the Phase 3 routes. Called inside the
// authenticated group via mountAuthedRoutes.
func (u *UI) mountChecksRoutes(r chi.Router) {
	r.Get("/checks", u.checksList)
	r.Get("/checks/diff", u.checksDiff)
	r.Post("/checks/{id}/toggle", u.checksToggle)
}

// checksList renders the catalog with search + facet filters. All
// filtering is done in-process against compliancekit.RegisteredChecks();
// 574 checks fits comfortably in memory for sub-ms filters even
// without an index.
func (u *UI) checksList(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	wantSev := splitCSV(r.URL.Query().Get("severity"))
	wantPro := splitCSV(r.URL.Query().Get("provider"))
	wantFw := splitCSV(r.URL.Query().Get("framework"))

	overrides := u.loadCheckOverrides(r.Context())
	registered := compliancekit.RegisteredChecks()

	var (
		items      = make([]checkRow, 0, len(registered))
		matchCount int
	)
	sevSet := map[string]struct{}{}
	proSet := map[string]struct{}{}
	fwSet := map[string]struct{}{}

	for _, c := range registered {
		row := buildCheckRow(c, overrides)

		// Track facet rosters from the unfiltered catalog so the chip
		// set stays the same regardless of which filter is active.
		sevSet[row.Severity] = struct{}{}
		proSet[row.Provider] = struct{}{}
		for _, fw := range row.Frameworks {
			fwSet[fw] = struct{}{}
		}

		if !rowMatchesFilters(row, q, wantSev, wantPro, wantFw) {
			continue
		}
		items = append(items, row)
		matchCount++
	}

	view := checksView{
		View:          u.viewFor(r, "Checks", "checks", View{}),
		Items:         items,
		Total:         len(registered),
		Matching:      matchCount,
		OverrideCount: len(overrides),
		Query:         r.URL.Query().Get("q"),
		Severities:    wantSev,
		Providers:     wantPro,
		Frameworks:    wantFw,
		AllSeverities: sortedKeys(sevSet),
		AllProviders:  sortedKeys(proSet),
		AllFrameworks: sortedKeys(fwSet),
	}
	u.render(w, "checks.html", view)
}

// checksToggle flips a single check's enabled flag. POST body has no
// required fields — the current state is read, inverted, and written.
// Idempotent in shape: the same POST twice returns the row to the
// shipped default.
func (u *UI) checksToggle(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing check id", http.StatusBadRequest)
		return
	}

	// Confirm the id is a real check before writing a row.
	registered := compliancekit.RegisteredChecks()
	var ck compliancekit.Check
	found := false
	for _, c := range registered {
		if c.ID == id {
			ck = c
			found = true
			break
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}

	overrides := u.loadCheckOverrides(r.Context())
	current, hasOverride := overrides[id]
	if !hasOverride {
		current = true // shipped default is "enabled"
	}
	_ = ck // reserved for future per-check audit metadata
	next := !current

	if err := u.upsertCheckOverride(r.Context(), id, next); err != nil {
		http.Error(w, "toggle: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Preserve the operator's search/filter state by echoing the
	// referer's query string back. Falls back to the bare /checks.
	next302 := "/checks"
	if ref := r.Header.Get("Referer"); ref != "" {
		if i := strings.Index(ref, "?"); i >= 0 {
			next302 = "/checks" + ref[i:]
		}
	}
	http.Redirect(w, r, next302, http.StatusSeeOther)
}

// checksDiff renders only the rows where the operator has overridden
// the shipped default. The auditor's "show me your tailoring" view.
func (u *UI) checksDiff(w http.ResponseWriter, r *http.Request) {
	overrides := u.loadCheckOverrides(r.Context())
	registered := compliancekit.RegisteredChecks()

	items := make([]checkRow, 0, len(overrides))
	for _, c := range registered {
		if _, ok := overrides[c.ID]; !ok {
			continue
		}
		items = append(items, buildCheckRow(c, overrides))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })

	view := checksView{
		View:          u.viewFor(r, "Tailoring diff · Checks", "checks", View{}),
		Items:         items,
		Total:         len(registered),
		Matching:      len(items),
		OverrideCount: len(overrides),
	}
	u.render(w, "checks_diff.html", view)
}

// upsertCheckOverride writes (or replaces) a row in checks_state.
// disabled_at/by are NULL by design — the v1.4 Phase 3 toggle is a
// pure on/off; Phase 5 (framework tailoring) adds the justification
// + audit-trail fields.
func (u *UI) upsertCheckOverride(ctx context.Context, checkID string, enabled bool) error {
	now := time.Now().UTC().Format(time.RFC3339)
	enabledVal := 0
	if enabled {
		enabledVal = 1
	}
	q := `INSERT INTO checks_state (check_id, enabled, updated_at) VALUES (` + phList(u.store, 3) + `)
	      ON CONFLICT(check_id) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at`
	_, err := u.store.DB().ExecContext(ctx, q, checkID, enabledVal, now)
	return err
}

// buildCheckRow stamps a registry entry into a checkRow with the
// operator's override applied (if any).
func buildCheckRow(c compliancekit.Check, overrides map[string]bool) checkRow {
	row := checkRow{
		ID:               c.ID,
		Severity:         c.Severity.String(),
		Provider:         c.Provider,
		Service:          c.Service,
		Title:            c.Title,
		Frameworks:       frameworksFor(c),
		Tags:             c.Tags,
		EnabledByDefault: true,
		Enabled:          true,
	}
	if v, ok := overrides[c.ID]; ok {
		row.Enabled = v
		row.Overridden = v != row.EnabledByDefault
	}
	return row
}

// frameworksFor returns the framework IDs a check claims via its
// Frameworks map. The map shape is framework-id → []control-id; we
// only need the keys for the filter facet. Sorted so the chip set
// is stable.
func frameworksFor(c compliancekit.Check) []string {
	seen := map[string]struct{}{}
	for fw := range c.Frameworks {
		seen[fw] = struct{}{}
	}
	return sortedKeys(seen)
}

// rowMatchesFilters applies the query string + the chip selections.
// Query matches against ID / Title / Service (lowercase substring);
// each filter slice is OR-within / AND-across (matches v1.2 HTML
// report's chip semantics).
func rowMatchesFilters(row checkRow, q string, sev, pro, fw []string) bool {
	if q != "" {
		hay := strings.ToLower(row.ID + " " + row.Title + " " + row.Service)
		if !strings.Contains(hay, strings.ToLower(q)) {
			return false
		}
	}
	if len(sev) > 0 && !contains(sev, row.Severity) {
		return false
	}
	if len(pro) > 0 && !contains(pro, row.Provider) {
		return false
	}
	if len(fw) > 0 {
		match := false
		for _, want := range fw {
			if contains(row.Frameworks, want) {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	return true
}

// splitCSV splits a comma-separated query value into trimmed pieces.
// "critical,high" → ["critical", "high"]; "" → nil.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	out := []string{}
	for _, piece := range strings.Split(s, ",") {
		t := strings.TrimSpace(piece)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k == "" {
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
