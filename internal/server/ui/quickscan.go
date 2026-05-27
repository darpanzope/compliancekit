package ui

// v1.16 phase 5 — Mobile quick-scan flow. /quick-scan is a one-tap
// stripped-down replacement for /scans/new on phones: a card-grid
// of enabled providers, a single tap triggers the scan, the SSE
// progress bar shows inline, then the top-5 findings render in the
// same view. No nav escape required between "kick the scan" and
// "see what's wrong" — useful for stand-ups, on-call check-ins,
// and coffee-shop sanity glances.
//
// Reuses the v1.4 scan-trigger path (POST /scans/new + GET /scans/
// {id}/stream) so there's no new worker logic — just a different
// presentation of the same daemon surface.

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
)

func (u *UI) mountQuickScanRoutes(r chi.Router) {
	r.Get("/quick-scan", u.quickScanLanding)
	r.Post("/quick-scan/run", u.quickScanRun)
	r.Get("/quick-scan/{id}/results", u.quickScanResults)
}

type quickScanView struct {
	View
	Providers []quickScanProvider
	ScanID    string
	StreamURL string
	Findings  []quickScanFinding
	Error     string
}

type quickScanProvider struct {
	ID      string
	Label   string
	Enabled bool
	Status  string // last auth check status — "ok" / "needs setup"
}

type quickScanFinding struct {
	Severity     string
	CheckID      string
	ResourceName string
	Message      string
	HRef         string
}

// quickScanLanding renders the provider card grid. Pulls from the
// providers table so the operator sees exactly what they configured
// in /settings/providers, in the same order.
func (u *UI) quickScanLanding(w http.ResponseWriter, r *http.Request) {
	view := quickScanView{
		View: u.viewFor(r, "Quick scan", "quick-scan", View{}),
	}
	view.Providers = u.loadQuickScanProviders(r.Context())
	u.render(w, "quickscan.html", view)
}

func (u *UI) loadQuickScanProviders(ctx context.Context) []quickScanProvider {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT id, COALESCE(enabled, 0), COALESCE(last_auth_status, '')
		 FROM providers
		 ORDER BY id ASC`)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []quickScanProvider
	for rows.Next() {
		var p quickScanProvider
		var enabled int
		if err := rows.Scan(&p.ID, &enabled, &p.Status); err != nil {
			continue
		}
		p.Enabled = enabled != 0
		p.Label = providerLabel(p.ID)
		out = append(out, p)
	}
	return out
}

// quickScanRun POSTs the chosen provider, kicks the scan, returns
// the inline progress fragment that htmx swaps into the page. The
// fragment includes the SSE stream URL the script subscribes to.
func (u *UI) quickScanRun(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
		return
	}
	providerID := r.FormValue("provider")
	if providerID == "" {
		http.Error(w, "provider is required", http.StatusBadRequest)
		return
	}
	scanID, err := u.enqueueWizardScanMulti(r.Context(), []string{providerID})
	if err != nil {
		view := quickScanView{
			View:      u.viewFor(r, "Quick scan", "quick-scan", View{}),
			Providers: u.loadQuickScanProviders(r.Context()),
			Error:     fmt.Sprintf("Couldn't start scan: %v", err),
		}
		u.render(w, "quickscan.html", view)
		return
	}
	// htmx loads the progress partial into the same view; the partial
	// includes an HX-Trigger=scan-complete callback that swaps in the
	// results panel on success.
	view := quickScanView{
		View:      u.viewFor(r, "Quick scan", "quick-scan", View{}),
		ScanID:    scanID,
		StreamURL: "/scans/" + scanID + "/stream",
	}
	w.Header().Set("HX-Trigger", "quick-scan-started")
	u.renderPartial(w, "quickscan_progress", view)
}

// quickScanResults loads the top-5 highest-severity findings from a
// completed scan and renders a card stack. htmx swaps this into the
// progress panel after the SSE stream signals completion.
func (u *UI) quickScanResults(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	if scanID == "" {
		http.Error(w, "scan id required", http.StatusBadRequest)
		return
	}
	limitStr := r.URL.Query().Get("limit")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 50 {
		limit = 5
	}
	view := quickScanView{
		View:   u.viewFor(r, "Quick scan results", "quick-scan", View{}),
		ScanID: scanID,
	}
	rows, err := u.store.DB().QueryContext(r.Context(),
		`SELECT severity, check_id, resource_name, COALESCE(message, '')
		 FROM findings
		 WHERE scan_id = ? AND status IN ('fail','error')
		 ORDER BY CASE severity
		            WHEN 'critical' THEN 0
		            WHEN 'high'     THEN 1
		            WHEN 'medium'   THEN 2
		            WHEN 'low'      THEN 3
		            ELSE 4 END,
		          last_seen_at DESC
		 LIMIT ?`, scanID, limit)
	if err != nil {
		view.Error = err.Error()
		u.renderPartial(w, "quickscan_results", view)
		return
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var f quickScanFinding
		if err := rows.Scan(&f.Severity, &f.CheckID, &f.ResourceName, &f.Message); err != nil {
			continue
		}
		f.HRef = "/findings?check=" + f.CheckID
		view.Findings = append(view.Findings, f)
	}
	u.renderPartial(w, "quickscan_results", view)
}

func providerLabel(id string) string {
	switch id {
	case providerAWS:
		return "Amazon Web Services"
	case providerGCP:
		return "Google Cloud"
	case providerDigitalOcean:
		return "DigitalOcean"
	case providerHetzner:
		return "Hetzner Cloud"
	case providerKubernetes:
		return "Kubernetes"
	case providerLinux:
		return "Linux fleet"
	default:
		return id
	}
}

// Suppress unused imports warning in case the time helpers below
// don't yet land. Compiler will drop this if everything's referenced.
var _ = auth.FromContext
var _ = time.Now
