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

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/assets"
	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/store"
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
	{Href: "/checks", Key: "checks", Label: "Checks",
		Icon: template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`)},
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
// page-specific content template name + the View payload.
var tmpl = template.Must(template.New("ui").Funcs(templateFuncs).ParseFS(tmplFS, "templates/*.html"))

// UI is the handler bundle. Constructed with the same store + auth
// dependencies the API layer uses.
type UI struct {
	store    *store.Store
	users    *auth.Users
	sessions *auth.Sessions
}

// New constructs the UI handle.
func New(st *store.Store, users *auth.Users, sessions *auth.Sessions) *UI {
	return &UI{store: st, users: users, sessions: sessions}
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

	r.Get("/", u.rootRedirect)
	r.Get("/login", u.login)
	r.Post("/logout", u.logout)

	r.Group(func(r chi.Router) {
		r.Use(u.sessions.RequireAuth)
		r.Get("/scans", u.listScans)
		r.Get("/scans/{id}", u.showScan)
		// v1.3 read-only /providers redirects to the v1.4 Phase 2
		// interactive settings page so existing bookmarks survive.
		r.Get("/providers", func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, "/settings/providers", http.StatusMovedPermanently)
		})
		u.mountChecksRoutes(r)
		u.mountSetupRoutes(r)
		u.mountSettingsRoutes(r)
	})
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
	if _, err := r.Cookie(auth.SessionCookieName); err == nil {
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
		Title:     "Sign in",
		LoginPage: true,
		Next:      r.URL.Query().Get("next"),
		Flash:     r.URL.Query().Get("flash"),
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
		`SELECT id, created_at, status, source, providers_scanned,
		        COALESCE(score, 0), total_findings, actionable_findings,
		        COALESCE(duration_ms, 0)
		 FROM scans ORDER BY created_at DESC LIMIT `+strconv.Itoa(per)+` OFFSET `+strconv.Itoa(offset))
	if err != nil {
		u.fail(w, "list scans: "+err.Error())
		return
	}
	defer func() { _ = rows.Close() }()
	items := []scanItem{}
	for rows.Next() {
		var s scanItem
		if err := rows.Scan(&s.ID, &s.CreatedAt, &s.Status, &s.Source, &s.ProvidersScanned,
			&s.Score, &s.TotalFindings, &s.ActionableFindings, &s.DurationMS); err != nil {
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
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT check_id, severity, status, resource_id, resource_name, resource_type,
		        COALESCE(message,''), first_seen_at
		 FROM findings WHERE scan_id = `+ph(u.store, 1), scanID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []compliancekit.Finding
	for rows.Next() {
		var f compliancekit.Finding
		var sevStr, statusStr string
		if err := rows.Scan(&f.CheckID, &sevStr, &statusStr, &f.Resource.ID,
			&f.Resource.Name, &f.Resource.Type, &f.Message, new(string)); err != nil {
			return nil, err
		}
		f.Severity = parseSeverity(sevStr)
		f.Status = compliancekit.Status(statusStr)
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
