package ui

// v1.4 Phase 2 — Settings page (provider management surface).
//
// /settings/providers is the interactive successor to the v1.3
// read-only /providers list. Lets the operator:
//
//	- See every provider compliancekit ships with auth status badges
//	  (configured-green / configured-red / unconfigured-muted) and
//	  the last-probed timestamp
//	- Open a per-provider detail page (/settings/providers/{id})
//	- "Test connection" — re-run the probe against the stored token
//	  without rotating credentials
//	- Rotate credentials — paste a new token; the server verifies the
//	  new token BEFORE replacing the old one (zero-downtime cred
//	  rotation; if the new probe fails the old token stays in effect)
//	- Toggle enabled (pause/resume a provider without losing its
//	  credentials)
//	- Edit per-provider settings (region filters / contexts /
//	  exclusions) — Phase 2 ships the DO surface and a scaffold for
//	  the rest; Phase 4 (granular per-service selector) extends this
//
// Phase 2 keeps the v1.3 /providers route working as a redirect to
// /settings/providers so existing bookmarks don't break.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// providerRow is what the settings list iterates over — the catalog
// card joined with the DB state (enabled flag, last probe outcome).
type providerRow struct {
	providerCard
	Configured     bool
	Enabled        bool
	LastStatus     string // "ok" / "failed" / "unknown" / ""
	LastError      string
	LastCheckAt    string
	LastCheckHuman string // "2m ago" / "—"

	// rawConfig stashes the providers.config_json string between
	// loadProviderRow and parsedConfig() so the detail handler can
	// hand the typed view to its template without re-querying.
	// Unexported so the list templates (which never call parsedConfig)
	// don't see it.
	rawConfig string
}

// providerDetail is the per-provider show page payload. Carries the
// row + the parsed config so the template renders the right form
// fields without doing JSON-parsing in the template layer.
type providerDetail struct {
	View
	Row    providerRow
	Config providerConfig
	Flash  string
	Error  string
}

// providerConfig is the typed view of providers.config_json. v1.4
// Phase 2 ships DO + the cross-provider Region / Exclusions / Tags
// shape; later phases add provider-specific extensions (K8s
// contexts, GCP projects, AWS assume-role-arn) without breaking the
// JSON column.
type providerConfig struct {
	Token      string   `json:"token,omitempty"`
	Region     string   `json:"region,omitempty"`
	Exclusions []string `json:"exclusions,omitempty"`
}

// mountSettingsRoutes registers the /settings/* surface. Called from
// (*UI).Mount inside the authenticated route group.
func (u *UI) mountSettingsRoutes(r chi.Router) {
	r.Get("/settings/providers", u.settingsListProviders)
	r.Get("/settings/providers/{id}", u.settingsShowProvider)
	r.Post("/settings/providers/{id}/test", u.settingsTestProvider)
	r.Post("/settings/providers/{id}/credentials", u.settingsRotateCredentials)
	r.Post("/settings/providers/{id}/config", u.settingsUpdateConfig)
	r.Post("/settings/providers/{id}/enabled", u.settingsToggleEnabled)
}

// settingsListProviders renders the providers list with auth-status
// badges. Joins the catalog with the DB rows so unconfigured
// providers still appear (with the muted "unconfigured" state).
func (u *UI) settingsListProviders(w http.ResponseWriter, r *http.Request) {
	rows, err := u.loadProviderRows(r.Context())
	if err != nil {
		u.fail(w, "load providers: "+err.Error())
		return
	}
	view := u.viewFor(r, "Providers · Settings", "settings", View{Items: rows})
	u.render(w, "settings_providers.html", view)
}

// settingsShowProvider renders the per-provider detail page.
func (u *UI) settingsShowProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row, err := u.loadProviderRow(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	detail := providerDetail{
		View:   u.viewFor(r, row.Name+" · Providers", "settings", View{}),
		Row:    row,
		Config: row.parsedConfig(),
		Flash:  r.URL.Query().Get("flash"),
		Error:  r.URL.Query().Get("err"),
	}
	u.render(w, "settings_provider_detail.html", detail)
}

// settingsTestProvider re-runs the auth probe using the stored token
// (no credential change). Refreshes last_auth_status + redirects
// back to the detail page with flash=tested.
func (u *UI) settingsTestProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row, err := u.loadProviderRow(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !row.Available {
		http.Redirect(w, r, "/settings/providers/"+id+"?err=unavailable", http.StatusSeeOther)
		return
	}
	cfg := row.parsedConfig()
	if cfg.Token == "" {
		http.Redirect(w, r, "/settings/providers/"+id+"?err=no-token", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	_, probeErr := probeProvider(ctx, id, cfg.Token)

	// Update only the last_auth_* columns — leave token + enabled
	// flag alone. A failing test should not silently disable a
	// previously-working provider.
	if err := u.updateProviderAuthStatus(ctx, id, probeErr); err != nil {
		u.fail(w, "persist status: "+err.Error())
		return
	}
	flash := "tested-ok"
	if probeErr != nil {
		flash = "tested-failed"
	}
	http.Redirect(w, r, "/settings/providers/"+id+"?flash="+flash, http.StatusSeeOther)
}

// settingsRotateCredentials accepts a new token, probes with it, and
// only persists if the probe succeeds. The old token remains valid
// until the new one is verified — zero-downtime rotation.
func (u *UI) settingsRotateCredentials(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row, err := u.loadProviderRow(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !row.Available {
		http.Redirect(w, r, "/settings/providers/"+id+"?err=unavailable", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	newToken := r.PostForm.Get("token")
	if newToken == "" {
		http.Redirect(w, r, "/settings/providers/"+id+"?err=empty-token", http.StatusSeeOther)
		return
	}

	// Probe with the new token first; if it fails, leave the existing
	// stored token in place. The operator sees the error inline.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if _, probeErr := probeProvider(ctx, id, newToken); probeErr != nil {
		http.Redirect(w, r,
			"/settings/providers/"+id+"?err=rotation-probe-failed",
			http.StatusSeeOther)
		return
	}

	// Probe passed — commit the new token + an ok status.
	cfg := row.parsedConfig()
	cfg.Token = newToken
	if err := u.writeProviderConfig(ctx, id, cfg, nil); err != nil {
		u.fail(w, "persist credentials: "+err.Error())
		return
	}
	http.Redirect(w, r, "/settings/providers/"+id+"?flash=rotated", http.StatusSeeOther)
}

// settingsUpdateConfig saves provider-specific settings (region,
// exclusions) without touching the token. Phase 4 (granular per-
// service selector) extends this with the service-level toggles.
func (u *UI) settingsUpdateConfig(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row, err := u.loadProviderRow(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	cfg := row.parsedConfig()
	cfg.Region = r.PostForm.Get("region")
	cfg.Exclusions = splitNonEmpty(r.PostForm.Get("exclusions"), "\n")
	if err := u.writeProviderConfig(r.Context(), id, cfg, errKeepExistingStatus); err != nil {
		u.fail(w, "persist config: "+err.Error())
		return
	}
	http.Redirect(w, r, "/settings/providers/"+id+"?flash=saved", http.StatusSeeOther)
}

// settingsToggleEnabled flips the enabled flag. Disabled providers
// keep their credentials; re-enabling skips a re-probe (the operator
// can hit Test Connection explicitly if they want).
func (u *UI) settingsToggleEnabled(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row, err := u.loadProviderRow(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	target := r.PostForm.Get("target") // "enable" or "disable"
	if target != targetEnable && target != targetDisable {
		http.Error(w, "bad target", http.StatusBadRequest)
		return
	}
	if !row.Configured && target == targetEnable {
		http.Redirect(w, r, "/settings/providers/"+id+"?err=no-token", http.StatusSeeOther)
		return
	}
	want := target == targetEnable
	now := time.Now().UTC().Format(time.RFC3339)
	enabledVal := 0
	if want {
		enabledVal = 1
	}
	q := `UPDATE providers SET enabled = ` + ph(u.store, 1) + `,
	                            updated_at = ` + ph(u.store, 2) + `
	      WHERE id = ` + ph(u.store, 3)
	if _, err := u.store.DB().ExecContext(r.Context(), q, enabledVal, now, id); err != nil {
		u.fail(w, "toggle: "+err.Error())
		return
	}
	flash := "enabled"
	if !want {
		flash = "disabled"
	}
	http.Redirect(w, r, "/settings/providers/"+id+"?flash="+flash, http.StatusSeeOther)
}

// loadProviderRows joins the catalog with the providers table. Every
// catalog entry appears (configured or not); rows for unknown
// catalog ids are dropped — the catalog is the source of truth for
// what compliancekit knows how to scan.
func (u *UI) loadProviderRows(ctx context.Context) ([]providerRow, error) {
	dbRows, err := u.queryProviderState(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]providerRow, 0, len(providerCatalog))
	for _, c := range providerCatalog {
		row := providerRow{providerCard: c}
		if state, ok := dbRows[c.ID]; ok {
			row.Configured = true
			row.Enabled = state.enabled
			row.LastStatus = state.lastStatus
			row.LastError = state.lastError
			row.LastCheckAt = state.lastCheckAt
			row.LastCheckHuman = humanizeAgo(state.lastCheckAt)
		}
		out = append(out, row)
	}
	return out, nil
}

func (u *UI) loadProviderRow(ctx context.Context, id string) (providerRow, error) {
	card, ok := findProviderCard(id)
	if !ok {
		return providerRow{}, errUnknownProvider
	}
	row := providerRow{providerCard: card}
	q := `SELECT enabled, COALESCE(last_auth_status,''), COALESCE(last_auth_error,''),
	             COALESCE(last_auth_check_at,''), COALESCE(config_json,'{}')
	      FROM providers WHERE id = ` + ph(u.store, 1)
	var enabled int
	var cfgJSON string
	err := u.store.DB().QueryRowContext(ctx, q, id).Scan(
		&enabled, &row.LastStatus, &row.LastError, &row.LastCheckAt, &cfgJSON)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return providerRow{}, err
	}
	if err == nil {
		row.Configured = true
		row.Enabled = enabled != 0
		row.LastCheckHuman = humanizeAgo(row.LastCheckAt)
		row.rawConfig = cfgJSON
	}
	return row, nil
}

// providerState is the subset of the providers row the list view
// needs. queryProviderState bulk-loads them keyed by id.
type providerState struct {
	enabled                            bool
	lastStatus, lastError, lastCheckAt string
}

func (u *UI) queryProviderState(ctx context.Context) (map[string]providerState, error) {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT id, enabled, COALESCE(last_auth_status,''),
		        COALESCE(last_auth_error,''), COALESCE(last_auth_check_at,'')
		 FROM providers`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]providerState{}
	for rows.Next() {
		var id string
		var enabled int
		s := providerState{}
		if err := rows.Scan(&id, &enabled, &s.lastStatus, &s.lastError, &s.lastCheckAt); err != nil {
			return nil, err
		}
		s.enabled = enabled != 0
		out[id] = s
	}
	return out, rows.Err()
}

// rawConfig is stashed on providerRow during single-row loads so
// parsedConfig() can decode it later. Not exposed on the catalog-
// only path (loadProviderRows) because the list view doesn't need
// the per-provider settings — those only matter on the detail page.
//
// We attach via a method-receiver field added below.

// updateProviderAuthStatus refreshes only the last_auth_* columns
// (no token or enabled changes). Used by the Test Connection flow.
func (u *UI) updateProviderAuthStatus(ctx context.Context, id string, probeErr error) error {
	now := time.Now().UTC().Format(time.RFC3339)
	status := authStatusOK
	var lastErr string
	if probeErr != nil {
		status = authStatusFailed
		lastErr = probeErr.Error()
	}
	q := `UPDATE providers SET last_auth_check_at = ` + ph(u.store, 1) + `,
	                            last_auth_status = ` + ph(u.store, 2) + `,
	                            last_auth_error = ` + ph(u.store, 3) + `,
	                            updated_at = ` + ph(u.store, 4) + `
	      WHERE id = ` + ph(u.store, 5)
	_, err := u.store.DB().ExecContext(ctx, q, now, status, lastErr, now, id)
	return err
}

// writeProviderConfig updates config_json + (optionally) the
// last_auth_* fields. If statusErr is errKeepExistingStatus the
// auth columns are left untouched; otherwise the same semantics as
// upsertProvider apply.
func (u *UI) writeProviderConfig(ctx context.Context, id string, cfg providerConfig, statusErr error) error {
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if errors.Is(statusErr, errKeepExistingStatus) {
		q := `UPDATE providers SET config_json = ` + ph(u.store, 1) + `,
		                            updated_at = ` + ph(u.store, 2) + `
		      WHERE id = ` + ph(u.store, 3)
		_, err = u.store.DB().ExecContext(ctx, q, string(cfgBytes), now, id)
		return err
	}
	status := authStatusOK
	var errText string
	if statusErr != nil {
		status = authStatusFailed
		errText = statusErr.Error()
	}
	q := `INSERT INTO providers (id, enabled, config_json, last_auth_check_at,
	                             last_auth_status, last_auth_error, created_at, updated_at)
	      VALUES (` + phList(u.store, 8) + `)
	      ON CONFLICT(id) DO UPDATE SET
	        config_json = excluded.config_json,
	        last_auth_check_at = excluded.last_auth_check_at,
	        last_auth_status = excluded.last_auth_status,
	        last_auth_error = excluded.last_auth_error,
	        updated_at = excluded.updated_at`
	_, err = u.store.DB().ExecContext(ctx, q, id, 1, string(cfgBytes), now, status, errText, now, now)
	return err
}

// parsedConfig decodes providers.config_json into a typed view. Bad
// JSON returns the zero value — the page renders empty form fields
// and the operator can fix them by re-saving.
func (p providerRow) parsedConfig() providerConfig {
	var cfg providerConfig
	if p.rawConfig == "" {
		return cfg
	}
	_ = json.Unmarshal([]byte(p.rawConfig), &cfg)
	return cfg
}

// humanizeAgo renders an RFC-3339 timestamp as "Nm ago" / "Nh ago" /
// "Nd ago" or "—" for the empty input. Tight enough that we keep
// it inline rather than reach for a dependency.
func humanizeAgo(ts string) string {
	if ts == "" {
		return "—"
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "—"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return formatAgo(d.Minutes(), "m")
	case d < 24*time.Hour:
		return formatAgo(d.Hours(), "h")
	default:
		return formatAgo(d.Hours()/24, "d")
	}
}

func formatAgo(n float64, unit string) string {
	return strconv.Itoa(int(n)) + unit + " ago"
}

// splitNonEmpty splits on sep and drops empty trimmed values. Used
// to turn a textarea ("one\ntwo\n\nthree") into a clean []string.
func splitNonEmpty(s, sep string) []string {
	if s == "" {
		return nil
	}
	out := []string{}
	for _, piece := range strings.Split(s, sep) {
		t := strings.TrimSpace(piece)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// authStatusOK / authStatusFailed mirror the schema CHECK on
// providers.last_auth_status. Kept as package-level constants so
// goconst is happy + a typo can't sneak in across the three
// settings code paths that write the column.
const (
	authStatusOK     = "ok"
	authStatusFailed = "failed"
)

// targetEnable / targetDisable are the two values the enable-toggle
// form posts. Same goconst rationale.
const (
	targetEnable  = "enable"
	targetDisable = "disable"
)

var (
	errUnknownProvider    = errors.New("provider not in catalog")
	errKeepExistingStatus = errors.New("keep existing last_auth_* columns")
)
