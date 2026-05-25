package ui

// v1.14 phase 1 — /dashboards: index + per-dashboard canvas + the
// drag-and-drop builder UI. The canvas is a 12-column CSS grid; each
// widget is positioned via inline grid-column / grid-row span based
// on the GridX/GridY/GridW/GridH columns persisted to
// dashboard_widgets. The "edit" mode toggles Alpine drag handlers
// that move tiles + persist on drop via POST /dashboards/{id}/widgets/{wid}.
//
// Widget bodies are rendered by partials under
// templates/widget_*.html — phase 3 swaps the stub bodies for the
// real SVG charts. Phase 0 ships the storage + this phase ships the
// scaffold; subsequent phases fill in the per-widget visualizations.

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/dashboards"
)

func (u *UI) dashboardsRepo() *dashboards.Store {
	if u.dashboardsRepoH == nil {
		u.dashboardsRepoH = dashboards.New(u.store)
	}
	return u.dashboardsRepoH
}

func (u *UI) mountDashboardsRoutes(r chi.Router) {
	r.Get("/dashboards", u.dashboardsList)
	r.Post("/dashboards", u.dashboardsCreate)
	r.Post("/dashboards/clone", u.dashboardsCloneTemplate)
	r.Get("/dashboards/{id}", u.dashboardsShow)
	r.Post("/dashboards/{id}", u.dashboardsUpdate)
	r.Post("/dashboards/{id}/delete", u.dashboardsDelete)
	r.Post("/dashboards/{id}/favorite", u.dashboardsToggleFavorite)
	r.Post("/dashboards/{id}/widgets", u.dashboardsAddWidget)
	r.Post("/dashboards/{id}/widgets/{wid}", u.dashboardsUpdateWidget)
	r.Post("/dashboards/{id}/widgets/{wid}/delete", u.dashboardsDeleteWidget)
}

type dashboardsListView struct {
	View
	Dashboards []dashboardRow
	Templates  []dashboards.Template
}

type dashboardRow struct {
	ID          string
	Name        string
	Description string
	Favorite    bool
	IsTeam      bool
	IsTemplate  bool
	WidgetCount int
	UpdatedAgo  string
}

func (u *UI) dashboardsList(w http.ResponseWriter, r *http.Request) {
	uid := userIDFromCtx(r.Context())
	items, err := u.dashboardsRepo().ListVisible(r.Context(), uid)
	if err != nil {
		u.fail(w, "list dashboards: "+err.Error())
		return
	}
	rows := make([]dashboardRow, 0, len(items))
	for _, d := range items {
		widgets, _ := u.dashboardsRepo().WidgetsFor(r.Context(), d.ID)
		rows = append(rows, dashboardRow{
			ID:          d.ID,
			Name:        d.Name,
			Description: d.Description,
			Favorite:    d.Favorite,
			IsTeam:      d.OwnerUserID == "",
			IsTemplate:  d.Template != "",
			WidgetCount: len(widgets),
			UpdatedAgo:  humanizeAgo(d.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z")),
		})
	}
	view := dashboardsListView{
		View:       u.viewFor(r, "Dashboards", "dashboards", View{Flash: r.URL.Query().Get("flash")}),
		Dashboards: rows,
		Templates:  dashboards.BuiltinTemplates(),
	}
	u.render(w, "dashboards_list.html", view)
}

func (u *UI) dashboardsCloneTemplate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	tmpl := strings.TrimSpace(r.FormValue("template"))
	name := strings.TrimSpace(r.FormValue("name"))
	teamShare := r.FormValue("team") == "1"
	owner := userIDFromCtx(r.Context())
	if teamShare && u.isAdmin(r.Context()) {
		owner = ""
	}
	d, err := u.dashboardsRepo().CloneTemplate(r.Context(), tmpl, owner, userIDFromCtx(r.Context()), name)
	if err != nil {
		http.Redirect(w, r, "/dashboards?flash=template-error", http.StatusSeeOther)
		return
	}
	u.AuditLog(r.Context(), "dashboard.clone_template", "dashboard", d.ID, map[string]any{
		"template": tmpl, "team": owner == "",
	})
	http.Redirect(w, r, "/dashboards/"+d.ID+"?flash=created", http.StatusSeeOther)
}

func (u *UI) dashboardsCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	desc := strings.TrimSpace(r.FormValue("description"))
	teamShare := r.FormValue("team") == "1"
	if name == "" {
		http.Redirect(w, r, "/dashboards?flash=missing-name", http.StatusSeeOther)
		return
	}
	owner := userIDFromCtx(r.Context())
	if teamShare && u.isAdmin(r.Context()) {
		owner = "" // team-wide
	}
	d, err := u.dashboardsRepo().CreateDashboard(r.Context(), owner, userIDFromCtx(r.Context()), name, desc, "")
	if err != nil {
		http.Redirect(w, r, "/dashboards?flash=error", http.StatusSeeOther)
		return
	}
	u.AuditLog(r.Context(), "dashboard.create", "dashboard", d.ID, map[string]any{
		"name": d.Name, "team": owner == "",
	})
	http.Redirect(w, r, "/dashboards/"+d.ID+"?flash=created", http.StatusSeeOther)
}

type dashboardShowView struct {
	View
	Dashboard *dashboards.Dashboard
	Edit      bool
	Palette   []paletteEntry
	CanEdit   bool
}

type paletteEntry struct {
	Kind  string
	Label string
}

var widgetPalette = []paletteEntry{
	{string(dashboards.KindScoreGauge), "Score gauge"},
	{string(dashboards.KindSeverityDonut), "Severity donut"},
	{string(dashboards.KindFrameworkBar), "Framework coverage bar"},
	{string(dashboards.KindFrameworkRadar), "Framework radar"},
	{string(dashboards.KindFindingList), "Finding list"},
	{string(dashboards.KindResourceTable), "Resource table"},
	{string(dashboards.KindSparkline), "Sparkline"},
	{string(dashboards.KindHeatmap), "Heatmap"},
	{string(dashboards.KindTreemap), "Treemap"},
	{string(dashboards.KindSankey), "Sankey"},
	{string(dashboards.KindMarkdown), "Markdown panel"},
	{string(dashboards.KindExecutiveSummary), "Executive summary"},
}

func (u *UI) dashboardsShow(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	d, err := u.dashboardsRepo().ByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	canEdit := u.canEditDashboard(r, d)
	view := dashboardShowView{
		View: u.viewFor(r, d.Name+" — Dashboard", "dashboards",
			View{Flash: r.URL.Query().Get("flash")}),
		Dashboard: d,
		Edit:      canEdit && r.URL.Query().Get("edit") == "1",
		Palette:   widgetPalette,
		CanEdit:   canEdit,
	}
	u.render(w, "dashboard_show.html", view)
}

func (u *UI) dashboardsUpdate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	d, err := u.dashboardsRepo().ByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !u.canEditDashboard(r, d) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	desc := strings.TrimSpace(r.FormValue("description"))
	if name == "" {
		http.Redirect(w, r, "/dashboards/"+id+"?flash=missing-name", http.StatusSeeOther)
		return
	}
	if err := u.dashboardsRepo().UpdateMetadata(r.Context(), id, name, desc); err != nil {
		u.fail(w, "update: "+err.Error())
		return
	}
	u.AuditLog(r.Context(), "dashboard.update", "dashboard", id, map[string]any{"name": name})
	http.Redirect(w, r, "/dashboards/"+id+"?flash=saved", http.StatusSeeOther)
}

func (u *UI) dashboardsDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	d, err := u.dashboardsRepo().ByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !u.canEditDashboard(r, d) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := u.dashboardsRepo().DeleteDashboard(r.Context(), id); err != nil {
		u.fail(w, "delete: "+err.Error())
		return
	}
	u.AuditLog(r.Context(), "dashboard.delete", "dashboard", id, nil)
	http.Redirect(w, r, "/dashboards?flash=deleted", http.StatusSeeOther)
}

func (u *UI) dashboardsToggleFavorite(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := u.dashboardsRepo().ToggleFavorite(r.Context(), id); err != nil {
		u.fail(w, "favorite: "+err.Error())
		return
	}
	u.AuditLog(r.Context(), "dashboard.favorite_toggle", "dashboard", id, nil)
	http.Redirect(w, r, "/dashboards/"+id, http.StatusSeeOther)
}

func (u *UI) dashboardsAddWidget(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	d, err := u.dashboardsRepo().ByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !u.canEditDashboard(r, d) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	kind := r.FormValue("kind")
	if kind == "" {
		http.Redirect(w, r, "/dashboards/"+id+"?edit=1&flash=missing-kind", http.StatusSeeOther)
		return
	}
	title := strings.TrimSpace(r.FormValue("title"))
	if title == "" {
		for _, p := range widgetPalette {
			if p.Kind == kind {
				title = p.Label
				break
			}
		}
	}
	gridW := atoiOr(r.FormValue("grid_w"), 6)
	gridH := atoiOr(r.FormValue("grid_h"), 4)
	if _, err := u.dashboardsRepo().AddWidget(r.Context(), &dashboards.Widget{
		DashboardID: id,
		Kind:        dashboards.Kind(kind),
		Title:       title,
		GridW:       gridW,
		GridH:       gridH,
		OrderIdx:    len(d.Widgets),
	}); err != nil {
		u.fail(w, "add widget: "+err.Error())
		return
	}
	u.AuditLog(r.Context(), "dashboard.widget_add", "dashboard", id, map[string]any{"kind": kind})
	http.Redirect(w, r, "/dashboards/"+id+"?edit=1&flash=widget-added", http.StatusSeeOther)
}

func (u *UI) dashboardsUpdateWidget(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	wid := chi.URLParam(r, "wid")
	d, err := u.dashboardsRepo().ByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !u.canEditDashboard(r, d) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	var widget *dashboards.Widget
	for _, wgt := range d.Widgets {
		if wgt.ID == wid {
			widget = wgt
			break
		}
	}
	if widget == nil {
		http.NotFound(w, r)
		return
	}
	widget.Title = strings.TrimSpace(r.FormValue("title"))
	widget.GridX = atoiOr(r.FormValue("grid_x"), widget.GridX)
	widget.GridY = atoiOr(r.FormValue("grid_y"), widget.GridY)
	widget.GridW = atoiOr(r.FormValue("grid_w"), widget.GridW)
	widget.GridH = atoiOr(r.FormValue("grid_h"), widget.GridH)
	if q := r.FormValue("query_json"); q != "" {
		widget.QueryJSON = q
	}
	if c := r.FormValue("config_json"); c != "" {
		widget.ConfigJSON = c
	}
	if err := u.dashboardsRepo().UpdateWidget(r.Context(), widget); err != nil {
		u.fail(w, "update widget: "+err.Error())
		return
	}
	// HTMX layout-saver: respond 204 so the JS doesn't reload.
	if r.Header.Get("HX-Request") == "true" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/dashboards/"+id+"?edit=1&flash=widget-saved", http.StatusSeeOther)
}

func (u *UI) dashboardsDeleteWidget(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	wid := chi.URLParam(r, "wid")
	d, err := u.dashboardsRepo().ByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !u.canEditDashboard(r, d) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := u.dashboardsRepo().DeleteWidget(r.Context(), wid); err != nil {
		u.fail(w, "delete widget: "+err.Error())
		return
	}
	u.AuditLog(r.Context(), "dashboard.widget_delete", "dashboard", id, map[string]any{"widget_id": wid})
	http.Redirect(w, r, "/dashboards/"+id+"?edit=1&flash=widget-deleted", http.StatusSeeOther)
}

// canEditDashboard: admins edit everything, owners edit their own;
// non-owner non-admin = read-only.
func (u *UI) canEditDashboard(r *http.Request, d *dashboards.Dashboard) bool {
	if u.isAdmin(r.Context()) {
		return true
	}
	uid := ""
	if sess := auth.FromContext(r.Context()); sess != nil {
		uid = sess.UserID
	}
	return d.OwnerUserID != "" && d.OwnerUserID == uid
}

func atoiOr(s string, def int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}
