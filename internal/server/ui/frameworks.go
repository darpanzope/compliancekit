package ui

// v1.4 Phase 5 — Framework tailoring UI.
//
// /settings/frameworks lists every shipping framework with its
// control count + currently-tailored count. Drilling into one opens
// /settings/frameworks/{id} where each control has an include /
// exclude toggle plus a required justification text field.
//
// Justification is required when included=0 — the auditor's reason
// for skipping a control sits next to the toggle decision and ends
// up in the evidence pack (Phase 7 generator emits the equivalent
// `tailoring:` section into compliancekit.yaml).

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/frameworks"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// frameworkRow is the list-view payload — name + counts. Drives the
// frameworks catalog tile.
type frameworkRow struct {
	ID            string
	Name          string
	Version       string
	Description   string
	URL           string
	Category      string
	ControlCount  int
	TailoredCount int // entries in framework_tailoring matching this id
}

// controlRow is the detail-page payload, joining the catalog control
// with the operator's tailoring decision.
type controlRow struct {
	ID            string
	Name          string
	Description   string
	Family        string
	Tags          []string
	Included      bool   // true = scoped in (default); false = scoped out
	Justification string // free-text, required when Included == false
	Overridden    bool   // true iff a row exists in framework_tailoring
}

// frameworksView is the list-page payload.
type frameworksView struct {
	View
	Items []frameworkRow
	Total int
}

// frameworkDetail is the detail-page payload.
type frameworkDetail struct {
	View
	Framework     *frameworks.Framework
	Controls      []controlRow
	IncludedCount int
	ExcludedCount int
	Flash         string
	Error         string
}

// mountFrameworksRoutes registers the Phase 5 routes.
func (u *UI) mountFrameworksRoutes(r chi.Router) {
	r.Get("/settings/frameworks", u.frameworksList)
	r.Get("/settings/frameworks/{id}", u.frameworkShow)
	r.Post("/settings/frameworks/{id}/control/{control}", u.frameworkControlUpdate)
}

// frameworksList renders the catalog of shipping frameworks with
// each one's tailoring count.
func (u *UI) frameworksList(w http.ResponseWriter, r *http.Request) {
	cat, err := frameworks.All()
	if err != nil {
		u.fail(w, "load frameworks: "+err.Error())
		return
	}

	tailoringCounts := u.tailoringCountsByFramework(r.Context())
	items := make([]frameworkRow, 0, len(cat))
	for id, fw := range cat {
		items = append(items, frameworkRow{
			ID:            id,
			Name:          fw.Name,
			Version:       fw.Version,
			Description:   fw.Description,
			URL:           fw.URL,
			Category:      fw.Category,
			ControlCount:  len(fw.Controls),
			TailoredCount: tailoringCounts[id],
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })

	view := frameworksView{
		View:  u.viewFor(r, "Frameworks · Settings", "settings", View{}),
		Items: items,
		Total: len(items),
	}
	u.render(w, "settings_frameworks.html", view)
}

// frameworkShow renders the per-framework control list with toggles
// and the operator's tailoring decisions overlaid.
func (u *UI) frameworkShow(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	fw, ok := frameworks.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	decisions := u.loadTailoringDecisions(r.Context(), id)

	rows := make([]controlRow, 0, len(fw.Controls))
	excluded := 0
	for controlID, c := range fw.Controls {
		row := controlRow{
			ID:          controlID,
			Name:        c.Name,
			Description: c.Description,
			Family:      c.Family,
			Tags:        c.Tags,
			Included:    true, // shipped default
		}
		if d, ok := decisions[controlID]; ok {
			row.Included = d.included
			row.Justification = d.justification
			row.Overridden = true
			if !d.included {
				excluded++
			}
		}
		rows = append(rows, row)
	}
	// Stable sort: family first, then control id, then included rows
	// before excluded ones inside the same group.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Family != rows[j].Family {
			return rows[i].Family < rows[j].Family
		}
		return rows[i].ID < rows[j].ID
	})

	detail := frameworkDetail{
		View:          u.viewFor(r, fw.Name+" · Frameworks", "settings", View{}),
		Framework:     fw,
		Controls:      rows,
		IncludedCount: len(rows) - excluded,
		ExcludedCount: excluded,
		Flash:         r.URL.Query().Get("flash"),
		Error:         r.URL.Query().Get("err"),
	}
	u.render(w, "settings_framework_detail.html", detail)
}

// frameworkControlUpdate processes the per-control form submission.
// Two-action shape: include / exclude. Exclude requires a non-empty
// justification — the form-validation error path redirects back with
// ?err=need-justification.
func (u *UI) frameworkControlUpdate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	control := chi.URLParam(r, "control")
	fw, ok := frameworks.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, ok := fw.Controls[control]; !ok {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	action := r.PostForm.Get("action") // "include" or "exclude"
	justification := strings.TrimSpace(r.PostForm.Get("justification"))
	included := action != "exclude" // include is the default; only explicit "exclude" flips

	if !included && justification == "" {
		http.Redirect(w, r,
			"/settings/frameworks/"+id+"?err=need-justification&control="+control,
			http.StatusSeeOther)
		return
	}

	// If the operator is re-including a previously-excluded control,
	// drop the tailoring row entirely (back to shipped-default).
	if included && action == "include" {
		_, err := u.store.DB().ExecContext(r.Context(),
			`DELETE FROM framework_tailoring WHERE framework_id = `+ph(u.store, 1)+
				` AND control_id = `+ph(u.store, 2),
			id, control)
		if err != nil {
			u.fail(w, "drop tailoring: "+err.Error())
			return
		}
		http.Redirect(w, r, "/settings/frameworks/"+id+"?flash=control-restored", http.StatusSeeOther)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	includedVal := 0
	if included {
		includedVal = 1
	}
	q := `INSERT INTO framework_tailoring (framework_id, control_id, included, justification, updated_at)
	      VALUES (` + phList(u.store, 5) + `)
	      ON CONFLICT(framework_id, control_id) DO UPDATE SET
	        included = excluded.included,
	        justification = excluded.justification,
	        updated_at = excluded.updated_at`
	if _, err := u.store.DB().ExecContext(r.Context(), q,
		id, control, includedVal, justification, now); err != nil {
		u.fail(w, "persist tailoring: "+err.Error())
		return
	}
	flash := "control-excluded"
	if included {
		flash = "control-tailored"
	}
	http.Redirect(w, r, "/settings/frameworks/"+id+"?flash="+flash, http.StatusSeeOther)
}

// tailoringDecision is the typed row from framework_tailoring used
// by the per-framework detail view.
type tailoringDecision struct {
	included      bool
	justification string
}

func (u *UI) loadTailoringDecisions(ctx context.Context, frameworkID string) map[string]tailoringDecision {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT control_id, included, COALESCE(justification,'')
		 FROM framework_tailoring WHERE framework_id = `+ph(u.store, 1),
		frameworkID)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	out := map[string]tailoringDecision{}
	for rows.Next() {
		var id string
		var inc int
		var just string
		if err := rows.Scan(&id, &inc, &just); err != nil {
			return out
		}
		out[id] = tailoringDecision{included: inc != 0, justification: just}
	}
	return out
}

func (u *UI) tailoringCountsByFramework(ctx context.Context) map[string]int {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT framework_id, COUNT(*) FROM framework_tailoring GROUP BY framework_id`)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var fw string
		var n int
		if err := rows.Scan(&fw, &n); err != nil {
			return out
		}
		out[fw] = n
	}
	return out
}

// Ensure the compliancekit import is referenced (Framework is reachable
// via the frameworks package alias). Keeps the import wired for the
// next phase that pulls the v1.0 types directly.
var _ compliancekit.Framework
