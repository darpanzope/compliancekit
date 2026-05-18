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
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/store"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

//go:embed templates/*.html
var tmplFS embed.FS

// tmpl is parsed once at init. Each render takes the page-specific
// content template name + the View payload.
var tmpl = template.Must(template.ParseFS(tmplFS, "templates/*.html"))

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
	Items     any
	Total     int
	Providers []providerView
}

// Mount installs the UI routes on r. Login is open; everything else
// gated by sessions.RequireAuth.
func (u *UI) Mount(r chi.Router) {
	r.Get("/", u.rootRedirect)
	r.Get("/login", u.login)
	r.Post("/logout", u.logout)

	r.Group(func(r chi.Router) {
		r.Use(u.sessions.RequireAuth)
		r.Get("/scans", u.listScans)
		r.Get("/scans/{id}", u.showScan)
		r.Get("/providers", u.listProviders)
		r.Get("/checks", u.listChecks)
	})
}

func (u *UI) rootRedirect(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(auth.SessionCookieName); err == nil {
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

// listProviders renders the table from the providers table.
type providerView struct {
	ID              string
	Enabled         bool
	LastAuthStatus  string
	LastAuthError   string
	LastAuthCheckAt string
}

func (u *UI) listProviders(w http.ResponseWriter, r *http.Request) {
	rows, err := u.store.DB().QueryContext(r.Context(),
		`SELECT id, enabled, COALESCE(last_auth_status,''), COALESCE(last_auth_error,''), COALESCE(last_auth_check_at,'')
		 FROM providers ORDER BY id ASC`)
	if err != nil {
		u.fail(w, "list providers: "+err.Error())
		return
	}
	defer func() { _ = rows.Close() }()
	items := []providerView{}
	for rows.Next() {
		var p providerView
		var enabled int
		if err := rows.Scan(&p.ID, &enabled, &p.LastAuthStatus, &p.LastAuthError, &p.LastAuthCheckAt); err != nil {
			u.fail(w, "provider row: "+err.Error())
			return
		}
		p.Enabled = enabled != 0
		items = append(items, p)
	}
	u.render(w, "providers.html", u.viewFor(r, "Providers", "providers", View{Providers: items}))
}

type checkItem struct {
	ID       string
	Severity string
	Provider string
	Service  string
	Title    string
	Enabled  bool
}

func (u *UI) listChecks(w http.ResponseWriter, r *http.Request) {
	overrides := u.loadCheckOverrides(r.Context())
	checks := compliancekit.RegisteredChecks()
	items := make([]checkItem, 0, len(checks))
	for _, c := range checks {
		enabled := true
		if v, ok := overrides[c.ID]; ok {
			enabled = v
		}
		items = append(items, checkItem{
			ID: c.ID, Severity: c.Severity.String(),
			Provider: c.Provider, Service: c.Service,
			Title: c.Title, Enabled: enabled,
		})
	}
	u.render(w, "checks.html", u.viewFor(r, "Checks", "checks", View{Items: items, Total: len(items)}))
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

func (u *UI) render(w http.ResponseWriter, contentTemplate string, view View) {
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
