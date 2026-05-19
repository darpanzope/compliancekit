package ui

// v1.5 Phase 10 — Cmd+K global search + PDF export.
//
// Cmd+K opens a command-palette modal (Alpine-driven, no extra JS
// framework) that searches across:
//   - resources (resource_name / resource_id LIKE)
//   - findings (check_id LIKE)
//   - checks (in-memory registry, ID/title LIKE)
//   - providers (catalog id LIKE)
//   - saved views (name LIKE)
//
// PDF export: /scans/{id}/pdf returns the v1.2 HTML report with a
// print-friendly stylesheet hint + a Content-Disposition that
// nudges the browser into the print/save-as-PDF flow. True chromedp
// integration is deferred to v1.5.x; this MVP works on any browser
// without the daemon needing a headless Chrome binary on PATH.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// searchResult is one row in the Cmd+K results panel.
type searchResult struct {
	Kind  string `json:"kind"`  // "resource" / "finding" / "check" / "provider" / "view"
	Label string `json:"label"` // primary text
	Sub   string `json:"sub"`   // secondary text (id / type / etc.)
	Href  string `json:"href"`  // click target
	Hint  string `json:"hint"`  // small badge ("DO" / "soc2" / ...)
}

func (u *UI) mountSearchRoutes(r chi.Router) {
	r.Get("/search", u.searchJSON)
	r.Get("/scans/{id}/pdf", u.scanPDF)
}

// searchJSON is the Cmd+K backend. Returns up to 5 results from
// each kind, JSON-encoded for the modal's fetch().
func (u *UI) searchJSON(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	out := []searchResult{}
	if q == "" {
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	q = strings.ToLower(q)
	out = append(out, u.searchResources(r.Context(), q)...)
	out = append(out, u.searchFindings(r.Context(), q)...)
	out = append(out, searchChecks(q)...)
	out = append(out, searchProviders(q)...)
	out = append(out, u.searchSavedViews(r.Context(), q)...)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (u *UI) searchResources(ctx context.Context, q string) []searchResult {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT DISTINCT provider, resource_id, resource_name, resource_type
		 FROM findings
		 WHERE LOWER(resource_name) LIKE `+ph(u.store, 1)+` OR LOWER(resource_id) LIKE `+ph(u.store, 2)+`
		 LIMIT 5`, "%"+q+"%", "%"+q+"%")
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	out := []searchResult{}
	for rows.Next() {
		var p, id, name, rt string
		if err := rows.Scan(&p, &id, &name, &rt); err != nil {
			continue
		}
		out = append(out, searchResult{
			Kind: "resource", Label: name, Sub: rt + " · " + id,
			Href: "/findings?provider=" + p + "&q=" + name, Hint: p,
		})
	}
	return out
}

func (u *UI) searchFindings(ctx context.Context, q string) []searchResult {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT id, check_id, severity, resource_name FROM findings
		 WHERE LOWER(check_id) LIKE `+ph(u.store, 1)+` LIMIT 5`, "%"+q+"%")
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	out := []searchResult{}
	for rows.Next() {
		var id, checkID, sev, rn string
		if err := rows.Scan(&id, &checkID, &sev, &rn); err != nil {
			continue
		}
		out = append(out, searchResult{
			Kind: "finding", Label: checkID, Sub: rn,
			Href: "/findings?q=" + checkID, Hint: sev,
		})
	}
	return out
}

func searchChecks(q string) []searchResult {
	out := []searchResult{}
	count := 0
	for _, c := range compliancekit.RegisteredChecks() {
		if count >= 5 {
			break
		}
		if !strings.Contains(strings.ToLower(c.ID), q) &&
			!strings.Contains(strings.ToLower(c.Title), q) {
			continue
		}
		out = append(out, searchResult{
			Kind: "check", Label: c.ID, Sub: c.Title,
			Href: "/checks?provider=" + c.Provider, Hint: c.Severity.String(),
		})
		count++
	}
	return out
}

func searchProviders(q string) []searchResult {
	out := []searchResult{}
	for _, p := range providerCatalog {
		if !strings.Contains(strings.ToLower(p.ID), q) &&
			!strings.Contains(strings.ToLower(p.Name), q) {
			continue
		}
		out = append(out, searchResult{
			Kind: "provider", Label: p.Name, Sub: p.Description,
			Href: "/settings/providers/" + p.ID,
		})
	}
	return out
}

func (u *UI) searchSavedViews(ctx context.Context, q string) []searchResult {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT id, name, COALESCE(query_string,'') FROM saved_views
		 WHERE LOWER(name) LIKE `+ph(u.store, 1)+` LIMIT 5`, "%"+q+"%")
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	out := []searchResult{}
	for rows.Next() {
		var id, name, qs string
		if err := rows.Scan(&id, &name, &qs); err != nil {
			continue
		}
		out = append(out, searchResult{
			Kind: "view", Label: name, Sub: "Saved filter view",
			Href: "/findings?" + qs,
		})
	}
	return out
}

// scanPDF renders the v1.2 HTML report with a print-friendly hint.
// True chromedp-backed PDF generation is a v1.5.x enhancement; the
// MVP uses the browser's native "Save as PDF" via the print dialog
// (the v1.2 reporter already ships an @media print stylesheet).
func (u *UI) scanPDF(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	findings, err := u.loadFindings(r.Context(), scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition",
		`inline; filename="compliancekit-`+scanID+`.html"`)
	// Inject a small print-trigger script so the browser opens the
	// print dialog on load.
	rep := htmlReport{}
	_, _ = w.Write([]byte("<!doctype html><html><head><script>window.addEventListener('load',()=>window.print())</script></head><body>"))
	rep.RenderInline(w, findings)
	_, _ = w.Write([]byte("</body></html>"))
}
