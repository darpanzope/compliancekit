package ui

// v1.14 phase 5 — 3-up multi-scan compare.
//
// /scans/compare?a=&b=&c= picks up to three scans and renders the
// per-scan rollup (score, severity mix, top failing checks) side by
// side. Reuses the v1.5 diff scan picker for option loading + the
// v0.6 scans rollup columns (scans.score, scans.actionable_findings,
// scans.severity_breakdown_json from v1.11 phase 3) so the page is
// one query per scan with no joins.

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func (u *UI) mountMultiscanRoutes(r chi.Router) {
	r.Get("/scans/compare", u.scansCompareView)
}

type compareView struct {
	View
	Scans    []compareCol
	AllScans []diffScanOption
}

type compareCol struct {
	ID            string
	CreatedAgo    string
	Score         int
	TotalFindings int
	Actionable    int
	Severities    map[string]int
	TopChecks     []compareCheckRow
}

type compareCheckRow struct {
	CheckID  string
	Severity string
	Count    int
}

func (u *UI) scansCompareView(w http.ResponseWriter, r *http.Request) {
	ids := []string{
		r.URL.Query().Get("a"),
		r.URL.Query().Get("b"),
		r.URL.Query().Get("c"),
	}
	options, err := u.loadDiffScanOptions(r.Context())
	if err != nil {
		u.fail(w, "load scans: "+err.Error())
		return
	}
	// Auto-pick the three most recent when nothing was specified.
	for i, id := range ids {
		if id == "" && i < len(options) {
			ids[i] = options[i].ID
		}
	}
	cols := make([]compareCol, 0, 3)
	for _, id := range ids {
		if id == "" {
			continue
		}
		col, err := u.loadCompareCol(r.Context(), id)
		if err != nil {
			u.fail(w, "compare scan: "+err.Error())
			return
		}
		cols = append(cols, col)
	}
	for i := range options {
		for _, id := range ids {
			if options[i].ID == id {
				options[i].Selected = true
			}
		}
	}
	view := compareView{
		View:     u.viewFor(r, "Scan compare", "findings", View{}),
		Scans:    cols,
		AllScans: options,
	}
	u.render(w, "scans_compare.html", view)
}

// loadCompareCol pulls the per-scan rollup + the top failing checks
// for one column.
func (u *UI) loadCompareCol(ctx context.Context, scanID string) (compareCol, error) {
	col := compareCol{ID: scanID}
	var sevJSON string
	var createdAt string
	row := u.store.DB().QueryRowContext(ctx,
		`SELECT created_at, COALESCE(score,0), COALESCE(total_findings,0),
		        COALESCE(actionable_findings,0),
		        COALESCE(severity_breakdown_json,'{}')
		 FROM scans WHERE id = `+ph(u.store, 1), scanID)
	if err := row.Scan(&createdAt, &col.Score, &col.TotalFindings, &col.Actionable, &sevJSON); err != nil {
		return col, err
	}
	col.CreatedAgo = humanizeAgo(createdAt)
	col.Severities = map[string]int{}
	_ = json.Unmarshal([]byte(sevJSON), &col.Severities)

	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT check_id, severity, COUNT(*) FROM findings
		 WHERE scan_id = `+ph(u.store, 1)+` AND status = 'fail'
		 GROUP BY check_id, severity ORDER BY COUNT(*) DESC LIMIT 5`, scanID)
	if err != nil {
		return col, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var r compareCheckRow
		if err := rows.Scan(&r.CheckID, &r.Severity, &r.Count); err != nil {
			return col, err
		}
		col.TopChecks = append(col.TopChecks, r)
	}
	return col, rows.Err()
}

// _ keeps chi import alive when only used implicitly via the router.
var _ = chi.URLParam
