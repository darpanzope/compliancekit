package ui

// v1.5 Phase 9 — Cross-scan diff.
//
// /scans/diff?a=<id>&b=<id> picks two historical scans and renders
// three sections: New (in B but not A), Resolved (in A but not B),
// Changed (in both, different status). Joins on fingerprint — the
// v0.6 baseline-tracking primitive.
//
// Default behavior when only one (or neither) scan id is provided:
// auto-pick the two most-recent completed scans so the operator
// lands on a useful diff without typing.

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// diffEntry is one row in any of the three sections.
type diffEntry struct {
	FindingID    string
	CheckID      string
	Severity     string
	StatusA      string
	StatusB      string
	ResourceName string
	ResourceID   string
	Provider     string
}

type diffView struct {
	View
	ScanA, ScanB string
	ScanACreated string
	ScanBCreated string
	New          []diffEntry
	Resolved     []diffEntry
	Changed      []diffEntry
	AllScans     []diffScanOption
}

type diffScanOption struct {
	ID        string
	CreatedAt string
	Score     int
	Selected  bool
}

func (u *UI) mountDiffRoutes(r chi.Router) {
	r.Get("/scans/diff", u.scansDiffView)
}

func (u *UI) scansDiffView(w http.ResponseWriter, r *http.Request) {
	a := r.URL.Query().Get("a")
	b := r.URL.Query().Get("b")

	// Picker options + auto-pick when ids are missing.
	options, err := u.loadDiffScanOptions(r.Context())
	if err != nil {
		u.fail(w, "load scans: "+err.Error())
		return
	}
	if a == "" && len(options) >= 2 {
		a = options[1].ID // older of the two most-recent
	}
	if b == "" && len(options) >= 1 {
		b = options[0].ID // newest
	}

	view := diffView{
		View:     u.viewFor(r, "Diff", "findings", View{}),
		ScanA:    a,
		ScanB:    b,
		AllScans: options,
	}
	for i := range view.AllScans {
		if view.AllScans[i].ID == a || view.AllScans[i].ID == b {
			view.AllScans[i].Selected = true
		}
	}

	if a != "" && b != "" {
		res, err := u.diffScans(r.Context(), a, b)
		if err != nil {
			u.fail(w, "diff: "+err.Error())
			return
		}
		view.New = res.New
		view.Resolved = res.Resolved
		view.Changed = res.Changed
		view.ScanACreated = res.ScanACreated
		view.ScanBCreated = res.ScanBCreated
	}
	u.render(w, "scans_diff.html", view)
}

// loadDiffScanOptions returns the last 30 completed scans for the
// picker dropdowns.
func (u *UI) loadDiffScanOptions(ctx context.Context) ([]diffScanOption, error) {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT id, created_at, COALESCE(score, 0)
		 FROM scans WHERE status = 'completed'
		 ORDER BY created_at DESC LIMIT 30`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []diffScanOption{}
	for rows.Next() {
		var o diffScanOption
		if err := rows.Scan(&o.ID, &o.CreatedAt, &o.Score); err != nil {
			return out, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// findingByFingerprint is a lightweight per-finding struct for the
// in-memory join.
type findingByFingerprint struct {
	id, checkID, severity, status, resourceID, resourceName, provider, fingerprint string
}

// diffResult bundles every output of diffScans into one struct so
// the function stays under gocritic's 5-return-value threshold.
type diffResult struct {
	New          []diffEntry
	Resolved     []diffEntry
	Changed      []diffEntry
	ScanACreated string
	ScanBCreated string
}

// diffScans loads both scans' findings into memory and computes
// new / resolved / changed sets via fingerprint join.
func (u *UI) diffScans(ctx context.Context, a, b string) (diffResult, error) {
	res := diffResult{}
	aSet, aCreated, err := u.loadScanFindings(ctx, a)
	if err != nil {
		return res, err
	}
	bSet, bCreated, err := u.loadScanFindings(ctx, b)
	if err != nil {
		return res, err
	}
	res.ScanACreated = aCreated
	res.ScanBCreated = bCreated

	for fp, fb := range bSet {
		fa, present := aSet[fp]
		if !present {
			res.New = append(res.New, toDiffEntry(fb, "", fb.status))
			continue
		}
		if fa.status != fb.status {
			res.Changed = append(res.Changed, toDiffEntry(fb, fa.status, fb.status))
		}
	}
	for fp, fa := range aSet {
		if _, present := bSet[fp]; !present {
			res.Resolved = append(res.Resolved, toDiffEntry(fa, fa.status, ""))
		}
	}
	return res, nil
}

func toDiffEntry(f findingByFingerprint, statusA, statusB string) diffEntry {
	return diffEntry{
		FindingID:    f.id,
		CheckID:      f.checkID,
		Severity:     f.severity,
		StatusA:      statusA,
		StatusB:      statusB,
		ResourceName: f.resourceName,
		ResourceID:   f.resourceID,
		Provider:     f.provider,
	}
}

// loadScanFindings returns the findings of one scan keyed by
// fingerprint, plus the scan's created_at timestamp.
func (u *UI) loadScanFindings(ctx context.Context, scanID string) (findings map[string]findingByFingerprint, createdAt string, err error) {
	var created string
	_ = u.store.DB().QueryRowContext(ctx,
		`SELECT created_at FROM scans WHERE id = `+ph(u.store, 1), scanID).Scan(&created)
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT id, check_id, severity, status, resource_id, resource_name, provider, fingerprint
		 FROM findings WHERE scan_id = `+ph(u.store, 1), scanID)
	if err != nil {
		return nil, created, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]findingByFingerprint{}
	for rows.Next() {
		var f findingByFingerprint
		if err := rows.Scan(&f.id, &f.checkID, &f.severity, &f.status,
			&f.resourceID, &f.resourceName, &f.provider, &f.fingerprint); err != nil {
			return out, created, err
		}
		out[f.fingerprint] = f
	}
	return out, created, rows.Err()
}
