// Package ui mounts the v1.3 minimal UI shell on the daemon's chi
// router. Hand-written Go templates + inline CSS for the v1.3
// foundation; v1.4 phase 0 swaps in the Tailwind + Preline + htmx
// build pipeline.
//
// Routes (all session-auth gated except /login):
//
//	GET  /           → redirect to /scans (or /login)
//	GET  /login      → form
//	POST /logout     → destroy session + redirect to /login
//	GET  /scans      → paginated history
//	GET  /scans/{id} → the v1.2 HTML report served from DB findings
//	GET  /providers  → read-only provider+auth status table
//	GET  /checks     → catalog browser (read-only)
package ui

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/rules"
	"github.com/darpanzope/compliancekit/internal/server/assets"
	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/backups"
	"github.com/darpanzope/compliancekit/internal/server/collab"
	"github.com/darpanzope/compliancekit/internal/server/comments"
	"github.com/darpanzope/compliancekit/internal/server/dashboards"
	"github.com/darpanzope/compliancekit/internal/server/logs"
	"github.com/darpanzope/compliancekit/internal/server/plugins"
	"github.com/darpanzope/compliancekit/internal/server/push"
	srvrbac "github.com/darpanzope/compliancekit/internal/server/rbac"
	"github.com/darpanzope/compliancekit/internal/server/store"
	"github.com/darpanzope/compliancekit/internal/server/ui/design"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

//go:embed templates/*.html
var tmplFS embed.FS

// navItem is a single sidebar entry — href, label, the .Active key
// the page sets to highlight itself, and the inline SVG glyph (raw
// HTML, trusted at build time). New nav rows go here and base.html
// renders them automatically.
type navItem struct {
	Href, Key, Label string
	Icon             template.HTML
}

// defaultNav lists the v1.4 nav surface. v1.5+ extends with explorer,
// resource map, score-over-time. Add rows here, not in base.html, so
// every layout (including v1.4 Studio sub-pages later) renders the
// same chrome.
//
// v1.4 Phase 2: "Providers" replaced with "Settings" → /settings/providers
// (the v1.4 interactive settings page). The v1.3 read-only /providers
// route stays as a 302 → /settings/providers so any bookmarks survive.
var defaultNav = []navItem{
	{Href: "/scans", Key: "scans", Label: "Scans",
		Icon: template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>`)},
	{Href: "/findings", Key: "findings", Label: "Findings",
		Icon: template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`)},
	{Href: "/checks", Key: "checks", Label: "Checks",
		Icon: template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`)},
	{Href: "/rules", Key: "rules", Label: "Rules",
		Icon: template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`)},
	{Href: "/dashboards", Key: "dashboards", Label: "Dashboards",
		Icon: template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg>`)},
	{Href: "/settings/providers", Key: "settings", Label: "Settings",
		Icon: template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`)},
}

// templateFuncs are exposed to base.html + every content template.
// Keep this tiny — heavy logic stays in Go, templates stay layout-only.
var templateFuncs = template.FuncMap{
	"navItems":     func() []navItem { return defaultNav },
	"userInitials": initialsFromEmail,
	// list + add are tiny template-only helpers — list lets a template
	// declare an inline []string literal (avoids passing labels as
	// extra View fields for one-off panels); add is the 0-indexed
	// $i → 1-indexed step number converter the v1.4 setup wizard
	// progress bar uses.
	"list": func(items ...string) []string { return items },
	"add":  func(a, b int) int { return a + b },
	// first returns the first element of a []string or "" if the
	// slice is nil/empty. Lets templates safely echo the currently-
	// selected value of a single-select form control without
	// length-guards everywhere.
	"first": func(s []string) string {
		if len(s) == 0 {
			return ""
		}
		return s[0]
	},
	// contains reports whether `haystack` includes `needle`. Used by
	// Phase 4 service-selector checkboxes to mark previously-picked
	// services as checked.
	"contains": func(haystack []string, needle string) bool {
		for _, h := range haystack {
			if h == needle {
				return true
			}
		}
		return false
	},
	// chipGroupArgs packs the 4 fields filter_chip_group needs into
	// a struct the template can iterate against. Go html/template
	// forbids define-with-args, so the partial reads from a single
	// `.` payload — this helper builds that payload.
	"chipGroupArgs": func(label, name string, options []string, picked []string) any {
		return chipGroup{Label: label, Name: name, Options: options, Picked: picked}
	},
	// activeFilterCount sums every non-empty filter dimension for the
	// "N active filters" hint in the findings page footer.
	"activeFilterCount": activeFilterCount,
	// safeHTML promotes a string to template.HTML so it renders as
	// raw markup. v1.8 phase 1 — used by the comments_panel template
	// to emit goldmark-rendered body_html that was sanitized at
	// write time by bluemonday.
	"safeHTML": func(s string) template.HTML { return template.HTML(s) }, //nolint:gosec // sanitized at write time
	// joinCSV concatenates a []string with commas. v1.9 phase 3 —
	// used by the rule editor template to pass a kind list into a
	// data-attribute the Alpine factory parses.
	"joinCSV": func(s []string) string { return strings.Join(s, ",") },
	// mkInfoTooltip packs a string into a design.InfoTooltipArgs so
	// page-header + section partials can invoke ck-info-tooltip with
	// just a tooltip string. v1.18 phase 3.
	"mkInfoTooltip": func(text string) design.InfoTooltipArgs {
		return design.InfoTooltipArgs{Text: text}
	},
	// mkMetric builds a design.MetricCardArgs from the common
	// (title, value, variant) tuple + auto-attaches a severity glyph
	// when variant names a severity. v1.18 phase 4 — lets templates
	// render hero stat tiles with `{{ template "ck-metric-card"
	// (mkMetric "Critical" "12" "critical") }}` without constructing
	// the full struct or repeating the icon SVG per call site.
	"mkMetric": func(title, value, variant string) design.MetricCardArgs {
		return design.MetricCardArgs{
			Title:   title,
			Value:   value,
			Variant: variant,
			Tooltip: title,
			Icon:    severityMetricIcon(variant),
		}
	},
	// mkMetricTrend is mkMetric + a trend arrow. Direction is up|down|
	// flat; polarity is good|bad|neutral (colors the arrow). v1.18
	// phase 4.
	"mkMetricTrend": func(title, value, variant, delta, direction, polarity string) design.MetricCardArgs {
		return design.MetricCardArgs{
			Title:   title,
			Value:   value,
			Variant: variant,
			Tooltip: title,
			Icon:    severityMetricIcon(variant),
			Trend:   &design.MetricTrend{Delta: delta, Direction: direction, Polarity: polarity},
		}
	},
}

// severityMetricIcon returns the inline glyph for a MetricCard whose
// variant names a severity (critical/high/medium/low/info). Any other
// variant returns empty so the card renders without an icon. The SVGs
// are trusted (build-time literals) so template.HTML is safe. v1.18
// phase 4.
func severityMetricIcon(variant string) template.HTML {
	switch variant {
	case "critical":
		return template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`)
	case "high":
		return template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`)
	case "medium":
		return template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`)
	case "low":
		return template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>`)
	case "info":
		return template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>`)
	default:
		return ""
	}
}

// chipGroup is the partial-args struct filter_chip_group renders
// against.
type chipGroup struct {
	Label   string
	Name    string
	Options []string
	Picked  []string
}

// activeFilterCount returns the number of populated dimensions on
// findingFilters. Empty / zero-value dimensions don't count.
func activeFilterCount(f findingFilters) int {
	n := 0
	if len(f.Severities) > 0 {
		n++
	}
	if len(f.Statuses) > 0 {
		n++
	}
	if len(f.Providers) > 0 {
		n++
	}
	if len(f.Frameworks) > 0 {
		n++
	}
	if len(f.ResourceTypes) > 0 {
		n++
	}
	if len(f.CheckIDs) > 0 {
		n++
	}
	if f.NameQuery != "" {
		n++
	}
	if f.ScanID != "" {
		n++
	}
	if f.SinceDays > 0 {
		n++
	}
	return n
}

// initialsFromEmail returns up to 2 upper-case characters derived from
// the email's local part (before the @). "jane.doe@acme.com" → "JD";
// "alice@acme.com" → "A"; empty input → "?". Drives the gradient
// avatar in the topbar — no third-party avatar service.
func initialsFromEmail(email string) string {
	at := strings.IndexByte(email, '@')
	local := email
	if at >= 0 {
		local = email[:at]
	}
	if local == "" {
		return "?"
	}
	var out []byte
	prevWasSep := true
	for i := 0; i < len(local) && len(out) < 2; i++ {
		c := local[i]
		if c == '.' || c == '-' || c == '_' || c == '+' {
			prevWasSep = true
			continue
		}
		if prevWasSep {
			out = append(out, byteUpper(c))
			prevWasSep = false
		}
	}
	if len(out) == 0 {
		return "?"
	}
	return string(out)
}

func byteUpper(b byte) byte {
	if b >= 'a' && b <= 'z' {
		return b - 32
	}
	return b
}

// tmpl is parsed once at init with the shared funcmap so navItems +
// userInitials resolve inside base.html. Each render takes the
// page-specific content template name + the View payload. v1.18
// phase 3 composes design/components/*.html into the same tree so
// `{{ template "ck-button" .Args }}` works inside any daemon template.
var tmpl = template.Must(
	template.Must(template.New("ui").Funcs(templateFuncs).ParseFS(tmplFS, "templates/*.html")).
		ParseFS(design.ComponentsFS, design.ComponentsGlob),
)

// UI is the handler bundle. Constructed with the same store + auth
// dependencies the API layer uses.
type UI struct {
	store           *store.Store
	users           *auth.Users
	sessions        *auth.Sessions
	oidcProviders   []auth.OIDCProviderButton
	samlProviders   []auth.SAMLProviderButton // v1.12 phase 3
	logBuf          *logs.Buffer              // v1.6 phase 6 — nil-safe; route absent when nil
	comments        *comments.Repo            // v1.8 phase 1 — markdown comments on findings
	assignmentsRepo *collab.Assignments       // v1.8 phase 2 — per-finding assignees
	ownersRepo      *collab.Owners            // v1.8 phase 2 — per-resource owners
	activitiesRepo  *collab.Activities        // v1.8 phase 3 — chronological per-finding activity log
	teams           *collab.Teams             // v1.8 phase 8 — teams CRUD
	followersRepo   *collab.Followers         // v1.8 phase 8 — resource follower opt-in
	rulesRepo       *rules.Repo               // v1.9 phase 0 — rules engine persistence
	roles           *srvrbac.Store            // v1.12 phase 0 — role + permission grid
	tokensRepo      *auth.Tokens              // v1.12 phase 9 — API token UI
	pluginCatalog   *plugins.Catalog          // v1.13 phase 8 — installed-plugins UI
	dashboardsRepoH *dashboards.Store         // v1.14 phase 0 — dashboard storage
	backups         *backups.Manager          // v1.12 phase 8 — backup/restore
	backupDir       string
	backupDSN       string
	push            *push.Store // v1.16 phase 4 — Web Push subscriptions (nil = disabled)
}

// New constructs the UI handle.
func New(st *store.Store, users *auth.Users, sessions *auth.Sessions) *UI {
	return &UI{store: st, users: users, sessions: sessions, comments: comments.NewRepo(st)}
}

// SetOIDCProviders installs the list of upstream identity providers
// the daemon accepts logins from. Called by cli/serve.go after
// constructing each auth.OIDC handler so the /login template can
// render the right button set. Empty list → password-only login.
func (u *UI) SetOIDCProviders(providers []auth.OIDCProviderButton) {
	u.oidcProviders = providers
}

// SetSAMLProviders installs the v1.12 phase 3 SAML connection buttons.
// Same shape as SetOIDCProviders — the login template renders both
// alongside the local password form.
func (u *UI) SetSAMLProviders(providers []auth.SAMLProviderButton) {
	u.samlProviders = providers
}

// WithLogBuffer installs the v1.6 phase 6 log-tail buffer so the
// /admin/logs page + /admin/logs/stream SSE handler get mounted.
// nil-safe: callers can omit + the routes simply 404.
func (u *UI) WithLogBuffer(b *logs.Buffer) *UI {
	u.logBuf = b
	return u
}

// View is the layout-template payload. The Content sub-template
// reads .Items / .Total / .Providers / etc. — driver helpers below
// load the right shape per page.
type View struct {
	Title     string
	Active    string // nav highlight key — "scans" / "providers" / "checks" / ""
	LoginPage bool
	Flash     string
	Next      string
	User      *auth.User
	CSRFToken string

	// OIDCProviders enumerates the upstream identity providers the
	// daemon is configured for. The login template renders one button
	// per entry; empty slice → password-only login. v1.5.1 F15.
	OIDCProviders []auth.OIDCProviderButton

	// SAMLProviders enumerates the v1.12 phase 3 SAML connections. The
	// login template renders one "Sign in with X" button per entry.
	SAMLProviders []auth.SAMLProviderButton

	// Page-specific
	Items any
	Total int
}

// Mount installs the UI routes on r. Login is open; everything else
// gated by sessions.RequireAuth. /assets/* is unauthenticated by
// design — CSS + vendored JS that the login page needs before a
// session exists.
func (u *UI) Mount(r chi.Router) {
	r.Get("/assets/*", assetsHandler())

	// v1.16 phase 0 — PWA manifest at the web root so browsers find
	// it via the <link rel="manifest"> tag in base.html without
	// scoping to /assets/. Served unauthenticated because Chrome /
	// Safari fetch the manifest before the user has a session.
	r.Get("/manifest.webmanifest", manifestHandler())

	// v1.16 phase 1 — service worker at the root scope. Browsers
	// pin the SW's controlling scope to the path the script lived
	// at OR (with the Service-Worker-Allowed header) up to a parent
	// path. Serving from /sw.js gives us / scope and lets the SW
	// intercept every navigation. Unauthenticated for the same
	// reason as the manifest.
	r.Get("/sw.js", serviceWorkerHandler())
	r.Get("/offline", u.offlinePage)

	r.Get("/", u.rootRedirect)
	r.Get("/login", u.login)
	r.Post("/logout", u.logout)

	r.Group(func(r chi.Router) {
		r.Use(u.sessions.RequireAuth)
		// CSRF: chained after RequireAuth so the middleware can read
		// the session out of the request context. v1.5.1 F16 — every
		// UI form already renders <input name="csrf_token"> + every
		// htmx POST already mirrors ck_csrf into X-CSRF-Token, but
		// the middleware was never wired before this commit.
		r.Use(u.sessions.RequireCSRF)
		r.Get("/scans", u.listScans)
		r.Get("/scans/{id}", u.showScan)
		// v1.3 read-only /providers redirects to the v1.4 Phase 2
		// interactive settings page so existing bookmarks survive.
		r.Get("/providers", func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, "/settings/providers", http.StatusMovedPermanently)
		})
		// v1.15.1 phase 5 — bare /settings used to 404 because every
		// settings page registers a leaf route (/settings/providers,
		// /settings/frameworks, etc.) without a landing handler.
		// Audit caught it; redirect to the most-common landing (the
		// providers page) so the typed URL always works.
		r.Get("/settings", func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, "/settings/providers", http.StatusMovedPermanently)
		})
		u.mountChecksRoutes(r)
		u.mountSetupRoutes(r)
		u.mountSettingsRoutes(r)
		u.mountFrameworksRoutes(r)
		u.mountYAMLRoutes(r)
		u.mountCIRoutes(r)
		u.mountWaiversRoutes(r)
		u.mountWebhooksRoutes(r)
		u.mountScanNewRoutes(r)
		u.mountScheduleRoutes(r)
		u.mountAuditRoutes(r)
		u.mountFindingsRoutes(r)
		u.mountSavedViewRoutes(r)
		u.mountFindingDetailRoutes(r)
		u.mountCommentsRoutes(r)
		u.mountCollabRoutes(r)
		u.mountTeamsRoutes(r)
		u.mountRolesRoutes(r)
		u.mountSessionsRoutes(r)
		u.mountBackupsRoutes(r)
		u.mountTokensRoutes(r)
		u.mountNotifyTemplatesRoutes(r)
		u.mountPluginsRoutes(r)
		u.mountDashboardsRoutes(r)
		u.mountMultiscanRoutes(r)
		u.mountInboxV2Routes(r)
		u.mountRulesRoutes(r)
		u.mountRemediationRoutes(r)
		u.mountResourceMapRoutes(r)
		u.mountResourcesRoutes(r)
		u.mountDriftRoutes(r)
		u.mountScoresRoutes(r)
		u.mountDiffRoutes(r)
		u.mountSearchRoutes(r)
		u.mountNotificationsRoutes(r)
		u.mountQuickScanRoutes(r)
		// v1.6 phase 6 — admin-only log tail. Both routes nested
		// inside the existing RequireAuth + RequireCSRF group;
		// adminOnly adds an IsAdmin check on top.
		if u.logBuf != nil {
			r.Get("/admin/logs", u.adminOnly(u.adminLogsPage))
			r.Get("/admin/logs/stream", u.adminOnly(u.logBuf.StreamHandler()))
		}
	})
}

// adminOnly wraps a handler with an IsAdmin gate. Non-admin sessions
// get a 403 + a JSON error body (matches the v1.5.1 scopeGate
// convention from api.go).
func (u *UI) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !u.isAdmin(r.Context()) {
			http.Error(w, "admin required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// adminLogsPage renders the /admin/logs UI. Stream tap lives at
// /admin/logs/stream — the template opens an EventSource against
// that URL on load.
func (u *UI) adminLogsPage(w http.ResponseWriter, r *http.Request) {
	view := u.viewFor(r, "Daemon logs", "admin", View{})
	u.render(w, "admin_logs.html", view)
}

// manifestHandler serves the PWA web app manifest at the root path
// (browsers expect /manifest.webmanifest or similar at the document
// scope). Content-type matters — Chrome rejects manifests served as
// application/json. v1.16 phase 0.
func manifestHandler() http.HandlerFunc {
	body, err := assets.FS.ReadFile("manifest.webmanifest")
	return func(w http.ResponseWriter, r *http.Request) {
		if err != nil {
			http.Error(w, "manifest unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/manifest+json")
		// Modest cache so a manifest change picks up within an hour
		// without operators forcing a full DNS flush.
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(body)
	}
}

// serviceWorkerHandler serves the v1.16 service worker at /sw.js so
// it controls the entire / scope (browser pins SW scope to the
// served path or shallower via Service-Worker-Allowed). No cache —
// browsers compare byte-for-byte and re-install when sw.js changes,
// so a Cache-Control max-age delays new SW deployments. v1.16
// phase 1.
func serviceWorkerHandler() http.HandlerFunc {
	body, err := assets.FS.ReadFile("sw.js")
	return func(w http.ResponseWriter, r *http.Request) {
		if err != nil {
			http.Error(w, "sw unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Service-Worker-Allowed", "/")
		_, _ = w.Write(body)
	}
}

// offlinePage renders the static fallback shown by the service
// worker when both the network and the page cache miss. Rendered
// through the standard template pipeline so it inherits the v1.18
// layout + theme tokens; lives at /offline so the SW can precache
// it during install. v1.16 phase 1.
func (u *UI) offlinePage(w http.ResponseWriter, r *http.Request) {
	// viewFor reads the session for nav highlighting; offline mode
	// may not have one. Pass an unauthenticated View so the template
	// still renders cleanly.
	view := View{Title: "Offline"}
	u.render(w, "offline.html", view)
}

// assetsHandler serves the embedded UI bundle (Tailwind CSS + vendored
// htmx/Alpine/Preline). Strips the /assets/ prefix and delegates to
// http.FileServerFS. Sets a long Cache-Control because asset filenames
// are version-pinned at build time (the bundle changes only when
// `make ui` regenerates it, which means a daemon redeploy anyway).
func assetsHandler() http.HandlerFunc {
	sub, _ := fs.Sub(assets.FS, ".")
	fileServer := http.FileServerFS(sub)
	return func(w http.ResponseWriter, r *http.Request) {
		// chi strips the route prefix when using {pattern}, but the
		// catch-all (*) keeps it; trim manually so FileServerFS sees
		// the bare filename it expects under the embed root.
		r2 := r.Clone(r.Context())
		r2.URL.Path = strings.TrimPrefix(r.URL.Path, "/assets")
		w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
		fileServer.ServeHTTP(w, r2)
	}
}

func (u *UI) rootRedirect(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(u.sessions.CookieName()); err == nil {
		// v1.4 Phase 1 onboarding gate: a logged-in operator landing
		// on "/" with no providers configured goes through the
		// first-run wizard at /setup. Once any provider is enabled,
		// "/" routes to the scans list as before. The session itself
		// gets validated by the auth middleware on the destination
		// route — this is just routing.
		if u.enabledProviderCount(r.Context()) == 0 {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/scans", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (u *UI) login(w http.ResponseWriter, r *http.Request) {
	view := View{
		Title:         "Sign in",
		LoginPage:     true,
		Next:          r.URL.Query().Get("next"),
		Flash:         r.URL.Query().Get("flash"),
		OIDCProviders: u.oidcProviders,
		SAMLProviders: u.samlProviders,
	}
	u.render(w, "login.html", view)
}

func (u *UI) logout(w http.ResponseWriter, r *http.Request) {
	auth.LogoutHandler(u.sessions)(w, r)
}

// scanItem is the row shape the /scans page template iterates over.
type scanItem struct {
	ID                 string
	CreatedAt          string
	Status             string
	Source             string
	Trigger            string // v1.6 phase 9 — F21
	ProvidersScanned   string
	Score              int
	TotalFindings      int
	ActionableFindings int
	DurationMS         int
}

func (u *UI) listScans(w http.ResponseWriter, r *http.Request) {
	pageN, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if pageN < 1 {
		pageN = 1
	}
	per := 50
	offset := (pageN - 1) * per

	rows, err := u.store.DB().QueryContext(r.Context(),
		`SELECT id, created_at, status, source, COALESCE(trigger,''),
		        providers_scanned, COALESCE(score, 0), total_findings,
		        actionable_findings, COALESCE(duration_ms, 0)
		 FROM scans ORDER BY created_at DESC LIMIT `+strconv.Itoa(per)+` OFFSET `+strconv.Itoa(offset))
	if err != nil {
		u.fail(w, "list scans: "+err.Error())
		return
	}
	defer func() { _ = rows.Close() }()
	items := []scanItem{}
	for rows.Next() {
		var s scanItem
		if err := rows.Scan(&s.ID, &s.CreatedAt, &s.Status, &s.Source, &s.Trigger,
			&s.ProvidersScanned, &s.Score, &s.TotalFindings, &s.ActionableFindings, &s.DurationMS); err != nil {
			u.fail(w, "scan row: "+err.Error())
			return
		}
		items = append(items, s)
	}
	var total int
	_ = u.store.DB().QueryRowContext(r.Context(), `SELECT COUNT(*) FROM scans`).Scan(&total)

	u.render(w, "scans.html", u.viewFor(r, "Scans", "scans", View{Items: items, Total: total}))
}

// showScan re-renders the v1.2 HTML report against the findings
// rows for this scan, served inside the daemon chrome. v1.5 turns
// this into a richer explorer; v1.3 just hands back the static
// report.
func (u *UI) showScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")

	// v1.4 Phase 9: when the scan is still queued/running, render a
	// live-progress page that subscribes to /scans/{id}/stream and
	// flips to the report once the row hits a terminal status.
	var status string
	_ = u.store.DB().QueryRowContext(r.Context(),
		`SELECT status FROM scans WHERE id = `+ph(u.store, 1), scanID).Scan(&status)
	if status == "" {
		http.NotFound(w, r)
		return
	}
	if status == "queued" || status == "running" {
		v := struct {
			View
			ScanID string
			Status string
		}{
			View:   u.viewFor(r, "Scan running", "scans", View{}),
			ScanID: scanID,
			Status: status,
		}
		u.render(w, "scan_progress.html", v)
		return
	}

	findings, err := u.loadFindings(r.Context(), scanID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		u.fail(w, "load findings: "+err.Error())
		return
	}

	// Use the v1.2 HTML reporter — same single-file output served
	// inline. The browser navigates to /scans/{id}, the daemon
	// renders the same template the v1.2 release ships.
	rep := htmlReport{}
	rep.RenderInline(w, findings)
}

func (u *UI) loadCheckOverrides(ctx context.Context) map[string]bool {
	rows, err := u.store.DB().QueryContext(ctx, `SELECT check_id, enabled FROM checks_state`)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		var e int
		if err := rows.Scan(&id, &e); err != nil {
			return out
		}
		out[id] = e != 0
	}
	return out
}

// viewFor populates the common nav-chrome fields (User + CSRFToken)
// from the session in context. Used by every authenticated route.
func (u *UI) viewFor(r *http.Request, title, active string, v View) View {
	v.Title = title
	v.Active = active
	if sess := auth.FromContext(r.Context()); sess != nil {
		v.CSRFToken = sess.CSRFToken
		if usr, err := u.users.ByID(r.Context(), sess.UserID); err == nil {
			v.User = usr
		}
	}
	return v
}

// renderPartial executes one named template against view without
// wrapping in the "base" chrome. Used by htmx endpoints (side-panel
// detail / row sentinel) that swap into an existing page.
//
// Clones tmpl first so the cached parse stays untouched — html/template
// disallows Clone after Execute, and the chrome-wrapping render path
// relies on Cloning to inject the right content template per page.
func (u *UI) renderPartial(w http.ResponseWriter, partialName string, view any) {
	t, err := tmpl.Clone()
	if err != nil {
		http.Error(w, "render: clone: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, partialName, view); err != nil {
		http.Error(w, "render: "+err.Error(), http.StatusInternalServerError)
	}
}

// render takes any view payload. The base + content templates resolve
// embedded fields (e.g. setupView embeds View) the same as direct
// ones, so wizard pages render with both the chrome fields and the
// step-specific fields available under `.`.
func (u *UI) render(w http.ResponseWriter, contentTemplate string, view any) {
	// The base template references {{ template "content" . }} which
	// resolves to whichever content template defined it; we drop the
	// right one in by re-parsing on each call (cheap; ~10 KB of text).
	t, err := template.Must(tmpl.Clone()).ParseFS(tmplFS, "templates/"+contentTemplate)
	if err != nil {
		http.Error(w, "render: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "base", view); err != nil {
		// Headers already sent — log to wherever.
		_ = err
	}
}

func (u *UI) fail(w http.ResponseWriter, msg string) {
	http.Error(w, msg, http.StatusInternalServerError)
}

// loadFindings pulls the findings rows for a scan back into the
// compliancekit.Finding shape so the v1.2 report renderer can emit
// the same single-file HTML.
func (u *UI) loadFindings(ctx context.Context, scanID string) ([]compliancekit.Finding, error) {
	// v1.5.1 F20: project every column the v1.2 HTML report
	// + the v1.5 explorer depend on. The original 8-column SELECT
	// dropped provider, framework_ids, fingerprint, first_seen_at,
	// last_seen_at — which made the framework-coverage bars + the
	// severity-by-provider donut + drift sparklines render empty.
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT check_id, severity, status, COALESCE(provider,''),
		        resource_id, resource_name, resource_type,
		        COALESCE(message,''), COALESCE(framework_ids,'[]'),
		        COALESCE(fingerprint,''),
		        COALESCE(first_seen_at,''), COALESCE(last_seen_at,'')
		 FROM findings WHERE scan_id = `+ph(u.store, 1), scanID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []compliancekit.Finding
	for rows.Next() {
		var f compliancekit.Finding
		var sevStr, statusStr, provider, frameworksJSON, fingerprint string
		var firstSeen, lastSeen string
		if err := rows.Scan(&f.CheckID, &sevStr, &statusStr, &provider,
			&f.Resource.ID, &f.Resource.Name, &f.Resource.Type,
			&f.Message, &frameworksJSON, &fingerprint,
			&firstSeen, &lastSeen); err != nil {
			return nil, err
		}
		f.Severity = parseSeverity(sevStr)
		f.Status = compliancekit.Status(statusStr)
		f.Resource.Provider = provider
		// Carry the row-level timestamp into the finding so v1.2
		// drift sparklines can group by first-seen.
		if firstSeen != "" {
			if t, err := time.Parse(time.RFC3339, firstSeen); err == nil {
				f.Timestamp = t
			}
		}
		_ = frameworksJSON // framework refs ride the check registry —
		// the v1.2 report enriches via LookupCheck at render time.
		_ = lastSeen
		_ = fingerprint
		out = append(out, f)
	}
	return out, rows.Err()
}

func parseSeverity(s string) compliancekit.Severity {
	switch s {
	case "critical":
		return compliancekit.SeverityCritical
	case "high":
		return compliancekit.SeverityHigh
	case "medium":
		return compliancekit.SeverityMedium
	case "low":
		return compliancekit.SeverityLow
	default:
		return compliancekit.SeverityInfo
	}
}

func ph(st *store.Store, n int) string {
	if st.Driver() == store.DriverPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}
