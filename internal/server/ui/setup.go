package ui

// v1.4 Phase 1 — First-run onboarding wizard.
//
// /setup is a 5-step htmx-friendly flow that turns a fresh daemon
// (admin user but no providers configured) into a working install:
//
//	step=welcome    intro + "Get started"
//	step=provider   pick the first provider (DigitalOcean in MVP;
//	                AWS / GCP / Hetzner / K8s / Linux show as
//	                "coming next" cards backed by Phase 2 settings)
//	step=auth       paste a provider token; submits to a per-provider
//	                handler that upserts providers.config_json + runs
//	                the doctor-style auth probe in-line
//	step=doctor     auth-probe outcome page: green tick + summary, or
//	                red error + retry CTA
//	step=scan       trigger the first scan (POST queues a row into
//	                the v1.3 worker pool's job queue); confirmation
//	                CTA links to /scans
//
// Wizard state is derived from DB rather than persisted as wizard
// rows: the same operator can leave + return and the daemon resumes
// at the right step from providers + scans table state.
//
// Phase 9 (live SSE scan progress) and Phase 2 (settings page —
// add more providers later) layer onto this; for v1.4 Phase 1 the
// MVP is DO-only with a clear "more providers next" surface.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	docollector "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/server/store"
)

// setupStep enumerates the wizard pages so URL params + redirects
// agree on the canonical step names. Order matters; nextStep() walks
// forward.
type setupStep string

const (
	stepWelcome  setupStep = "welcome"
	stepProvider setupStep = "provider"
	stepAuth     setupStep = "auth"
	stepDoctor   setupStep = "doctor"
	stepScan     setupStep = "scan"
)

// providerCard is the shape every provider tile in step=provider
// renders from. The MVP enables DO only; the rest are visible with
// "Coming in v1.4 Phase 2 (settings page)" hints so the operator
// sees the runway.
type providerCard struct {
	ID          string
	Name        string
	Description string
	Available   bool // false → grayed out card with "next" hint
	DocsURL     string
}

// providerCatalog lists every provider compliancekit ships. Order
// matches the audience preference (DO first per the v0.x audience
// arc); v1.4 Phase 2 expands availability as the settings page
// covers each provider.
var providerCatalog = []providerCard{
	{ID: "digitalocean", Name: "DigitalOcean", Description: "Droplets, Spaces, VPC, Managed DBs, App Platform, DOKS", Available: true,
		DocsURL: "https://cloud.digitalocean.com/account/api/tokens"},
	{ID: "aws", Name: "AWS", Description: "IAM, S3, EC2, RDS, CloudTrail, KMS, Config, GuardDuty", Available: false,
		DocsURL: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"},
	{ID: "gcp", Name: "Google Cloud", Description: "IAM, Compute, GCS, Cloud SQL, Logging, KMS, BigQuery", Available: false,
		DocsURL: "https://cloud.google.com/iam/docs/keys-create-delete"},
	{ID: "hetzner", Name: "Hetzner Cloud", Description: "Servers, firewalls, networks, load balancers, volumes", Available: false,
		DocsURL: "https://docs.hetzner.cloud/#getting-started"},
	{ID: "kubernetes", Name: "Kubernetes", Description: "CIS K8s + NSA/CISA hardening across pods, RBAC, network, supply chain", Available: false,
		DocsURL: "https://kubernetes.io/docs/tasks/access-application-cluster/access-cluster/"},
	{ID: "linux", Name: "Linux hosts", Description: "CIS Linux Server benchmark across Debian, RHEL, Alpine, AL2", Available: false,
		DocsURL: "https://compliancekit.dev/docs/linux"},
}

// setupView is the per-step payload base.html + each step template
// renders against.
type setupView struct {
	View       // embeds the standard chrome payload (User, CSRFToken, etc.)
	Step       setupStep
	StepNumber int // 1..5 for the progress bar
	TotalSteps int // always 5 for now
	Providers  []providerCard
	Provider   providerCard      // the currently-picked provider on auth/doctor/scan
	Error      string            // inline form error
	Probe      *setupProbeResult // doctor-step outcome
}

// setupProbeResult is the doctor-step display payload — what the
// auth handler captured after running the per-provider probe.
type setupProbeResult struct {
	OK       bool
	Duration time.Duration
	Message  string // success summary or failure detail
}

// mountSetupRoutes registers the /setup/* surface on r. Called from
// (*UI).Mount inside the authenticated route group — every wizard
// step requires a logged-in admin.
func (u *UI) mountSetupRoutes(r interface {
	Get(pattern string, h http.HandlerFunc)
	Post(pattern string, h http.HandlerFunc)
}) {
	r.Get("/setup", u.setupEntry)
	r.Get("/setup/welcome", u.setupWelcome)
	r.Get("/setup/provider", u.setupProvider)
	r.Post("/setup/provider", u.setupProviderChoose)
	r.Get("/setup/auth", u.setupAuth)
	r.Post("/setup/auth", u.setupAuthSubmit)
	r.Get("/setup/doctor", u.setupDoctor)
	r.Get("/setup/scan", u.setupScan)
	r.Post("/setup/scan", u.setupScanTrigger)
}

// enabledProviderCount returns how many provider rows have
// enabled=1. Drives the rootRedirect onboarding gate.
func (u *UI) enabledProviderCount(ctx context.Context) int {
	var n int
	_ = u.store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM providers WHERE enabled = 1`).Scan(&n)
	return n
}

// scanCount returns how many scan rows exist; drives the doctor →
// scan step gate.
func (u *UI) scanCount(ctx context.Context) int {
	var n int
	_ = u.store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM scans`).Scan(&n)
	return n
}

// setupEntry routes a bare GET /setup to whichever step the daemon's
// current state suggests. New install → welcome; provider configured
// but never probed → auth; probed green but no scans → scan.
func (u *UI) setupEntry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if u.enabledProviderCount(ctx) == 0 {
		http.Redirect(w, r, "/setup/welcome", http.StatusSeeOther)
		return
	}
	// At least one provider enabled — if it has an ok auth probe but
	// no scans yet, jump to the scan step. Otherwise the wizard is
	// effectively done.
	if u.scanCount(ctx) == 0 {
		http.Redirect(w, r, "/setup/scan", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/scans", http.StatusSeeOther)
}

func (u *UI) setupWelcome(w http.ResponseWriter, r *http.Request) {
	v := u.setupViewFor(r, stepWelcome, 1)
	u.render(w, "setup_welcome.html", v)
}

func (u *UI) setupProvider(w http.ResponseWriter, r *http.Request) {
	v := u.setupViewFor(r, stepProvider, 2)
	v.Providers = providerCatalog
	u.render(w, "setup_provider.html", v)
}

// setupProviderChoose accepts the picked provider id from step 2 and
// forwards to step 3 (auth) with the choice in the query string. The
// daemon doesn't persist anything yet — the operator can back out
// of the auth step without leaving a half-configured row behind.
func (u *UI) setupProviderChoose(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	id := r.PostForm.Get("provider")
	card, ok := findProviderCard(id)
	if !ok {
		http.Redirect(w, r, "/setup/provider?err=unknown", http.StatusSeeOther)
		return
	}
	if !card.Available {
		http.Redirect(w, r, "/setup/provider?err=unavailable", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/setup/auth?provider="+card.ID, http.StatusSeeOther)
}

func (u *UI) setupAuth(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("provider")
	card, ok := findProviderCard(id)
	if !ok || !card.Available {
		http.Redirect(w, r, "/setup/provider", http.StatusSeeOther)
		return
	}
	v := u.setupViewFor(r, stepAuth, 3)
	v.Provider = card
	v.Error = r.URL.Query().Get("err")
	u.render(w, "setup_auth.html", v)
}

// setupAuthSubmit takes the pasted token, persists it to the
// providers row, runs the per-provider probe, stores the auth status,
// and redirects to /setup/doctor with the outcome encoded for display.
func (u *UI) setupAuthSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	id := r.PostForm.Get("provider")
	card, ok := findProviderCard(id)
	if !ok || !card.Available {
		http.Redirect(w, r, "/setup/provider", http.StatusSeeOther)
		return
	}
	token := r.PostForm.Get("token")
	if token == "" {
		http.Redirect(w, r, "/setup/auth?provider="+card.ID+"&err=empty", http.StatusSeeOther)
		return
	}

	// Run the per-provider probe with a tight timeout so a wedged
	// remote doesn't hang the wizard.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	dur, perr := probeProvider(ctx, card.ID, token)

	// Persist the provider row regardless of probe outcome — the
	// operator may still want to retry with the same token, and the
	// stored last_auth_error helps the settings page surface "fix me"
	// hints in Phase 2.
	if err := u.upsertProvider(ctx, card.ID, token, perr); err != nil {
		http.Error(w, "persist provider: "+err.Error(), http.StatusInternalServerError)
		return
	}

	q := url.Values{"provider": []string{card.ID}}
	if perr != nil {
		q.Set("ok", "0")
		q.Set("detail", perr.Error())
	} else {
		q.Set("ok", "1")
		q.Set("ms", fmt.Sprintf("%d", dur.Milliseconds()))
	}
	http.Redirect(w, r, "/setup/doctor?"+q.Encode(), http.StatusSeeOther)
}

func (u *UI) setupDoctor(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id := q.Get("provider")
	card, ok := findProviderCard(id)
	if !ok {
		http.Redirect(w, r, "/setup/provider", http.StatusSeeOther)
		return
	}
	v := u.setupViewFor(r, stepDoctor, 4)
	v.Provider = card
	if q.Get("ok") == "1" {
		ms, _ := time.ParseDuration(q.Get("ms") + "ms")
		v.Probe = &setupProbeResult{OK: true, Duration: ms, Message: card.Name + " API reachable."}
	} else {
		v.Probe = &setupProbeResult{OK: false, Message: q.Get("detail")}
	}
	u.render(w, "setup_doctor.html", v)
}

func (u *UI) setupScan(w http.ResponseWriter, r *http.Request) {
	v := u.setupViewFor(r, stepScan, 5)
	// The auth step set last_auth_status on the providers row — surface
	// that here so the scan step shows the operator what they're about
	// to scan.
	id := r.URL.Query().Get("provider")
	if card, ok := findProviderCard(id); ok {
		v.Provider = card
	}
	u.render(w, "setup_scan.html", v)
}

// setupScanTrigger queues a scan row in the v1.3 worker pool's job
// queue. The wizard's job is to confirm the scan was enqueued; the
// /scans page renders the live (or just-completed) result.
func (u *UI) setupScanTrigger(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	id := r.PostForm.Get("provider")
	card, ok := findProviderCard(id)
	if !ok || !card.Available {
		http.Redirect(w, r, "/setup/provider", http.StatusSeeOther)
		return
	}
	if _, err := u.enqueueWizardScan(r.Context(), card.ID); err != nil {
		http.Error(w, "queue scan: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/scans?welcome=1", http.StatusSeeOther)
}

// setupViewFor stamps the chrome fields + the wizard's per-step
// progress payload onto a View. Builds on u.viewFor so the topbar /
// sidebar render correctly for the logged-in operator.
func (u *UI) setupViewFor(r *http.Request, step setupStep, stepNo int) setupView {
	base := u.viewFor(r, "Setup · compliancekit", "setup", View{})
	return setupView{
		View:       base,
		Step:       step,
		StepNumber: stepNo,
		TotalSteps: 5,
	}
}

// upsertProvider writes the operator-supplied credentials into the
// providers row + last_auth_* fields. The token lands inside
// config_json under {"token": "..."}; if probeErr is non-nil the
// last_auth_status records "failed" with the error string. The
// settings page (Phase 2) reads the same row.
func (u *UI) upsertProvider(ctx context.Context, id, token string, probeErr error) error {
	cfg := map[string]any{"token": token}
	cfgJSON, _ := json.Marshal(cfg)
	now := time.Now().UTC().Format(time.RFC3339)
	status := "ok"
	var lastErr string
	if probeErr != nil {
		status = "failed"
		lastErr = probeErr.Error()
	}
	q := `INSERT INTO providers (id, enabled, config_json, last_auth_check_at,
	                             last_auth_status, last_auth_error, created_at, updated_at)
	      VALUES (` + phList(u.store, 8) + `)
	      ON CONFLICT(id) DO UPDATE SET
	        enabled = excluded.enabled,
	        config_json = excluded.config_json,
	        last_auth_check_at = excluded.last_auth_check_at,
	        last_auth_status = excluded.last_auth_status,
	        last_auth_error = excluded.last_auth_error,
	        updated_at = excluded.updated_at`
	_, err := u.store.DB().ExecContext(ctx, q, id, 1, string(cfgJSON), now, status, lastErr, now, now)
	return err
}

// enqueueWizardScan inserts a scan row in 'queued' state for the
// worker pool to pick up. Mirrors what POST /api/v1/scans does, but
// here we want no JSON round-trip / no scope-token check. source is
// "daemon" to satisfy the schema's CHECK constraint (cli/daemon/
// webhook/schedule) — the wizard runs inside the daemon process.
func (u *UI) enqueueWizardScan(ctx context.Context, providerID string) (string, error) {
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339)
	providersJSON, _ := json.Marshal([]string{providerID})
	frameworksJSON := []byte("[]")
	q := `INSERT INTO scans (id, created_at, source, status, providers_scanned,
	                         frameworks_scanned, score, coverage, total_findings,
	                         actionable_findings)
	      VALUES (` + phList(u.store, 10) + `)`
	_, err := u.store.DB().ExecContext(ctx, q,
		id, now, "daemon", "queued",
		string(providersJSON), string(frameworksJSON),
		0, 0, 0, 0)
	return id, err
}

// findProviderCard returns the catalog entry for id and ok=true,
// or the zero value + ok=false if id isn't a known provider.
func findProviderCard(id string) (providerCard, bool) {
	for _, c := range providerCatalog {
		if c.ID == id {
			return c, true
		}
	}
	return providerCard{}, false
}

// probeProvider routes to the per-provider auth probe. v1.4 Phase 1
// MVP ships DigitalOcean only; the other catalog entries return
// errUnavailable and the wizard refuses to advance past auth for them.
func probeProvider(ctx context.Context, id, token string) (time.Duration, error) {
	switch id {
	case "digitalocean":
		return docollector.Probe(ctx, token)
	default:
		return 0, errUnavailable
	}
}

var errUnavailable = errors.New("provider not yet supported in the setup wizard — coming in v1.4 phase 2")

// phList returns the placeholder list for an n-column INSERT, picking
// the dialect via store.Driver. SQLite uses "?, ?, ?, ..."; Postgres
// uses "$1, $2, $3, ...". The single-placeholder helper in ui.go
// already covers the WHERE-clause case; this is for multi-arg inserts.
func phList(st *store.Store, n int) string {
	parts := make([]string, n)
	if st.Driver() == store.DriverPostgres {
		for i := 0; i < n; i++ {
			parts[i] = fmt.Sprintf("$%d", i+1)
		}
	} else {
		for i := 0; i < n; i++ {
			parts[i] = "?"
		}
	}
	return strings.Join(parts, ", ")
}
