package ui

// v1.13 phase 8 — /settings/plugins UI: in-UI plugin catalog browser.
//
// Two tabs:
//   - Installed — what discovery actually loaded, with signature
//                 status + manifest summary + a "remove" affordance.
//   - Community — a static curated list shipped with the binary at
//                 v1.13. v2.9 replaces this with a live registry feed.
//
// The daemon constructs a plugins.Catalog at boot and hands the UI
// a read-only handle through UI.SetPluginCatalog. When unset (the
// daemon was built without plugins or operator opted out) the page
// renders a "plugins disabled" placeholder.

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/plugins"
	pubplugin "github.com/darpanzope/compliancekit/pkg/compliancekit/plugin"
)

// SetPluginCatalog installs the catalog handle the /settings/plugins
// page reads from. nil disables the catalog UI gracefully (the page
// still renders but shows the placeholder copy).
func (u *UI) SetPluginCatalog(cat *plugins.Catalog) {
	u.pluginCatalog = cat
}

func (u *UI) mountPluginsRoutes(r chi.Router) {
	r.Get("/settings/plugins", u.adminOnly(u.pluginsList))
}

type pluginsListView struct {
	View
	Installed []pluginRow
	Community []communityRow
	Disabled  bool
}

type pluginRow struct {
	Name           string
	Version        string
	Kinds          []pubplugin.Kind
	SignatureValid bool
	Path           string
	Description    string
	Generation     int
}

type communityRow struct {
	Name        string
	Description string
	Source      string
	Kinds       []pubplugin.Kind
}

func (u *UI) pluginsList(w http.ResponseWriter, r *http.Request) {
	view := pluginsListView{
		View:      u.viewFor(r, "Plugins", "settings", View{Flash: r.URL.Query().Get("flash")}),
		Community: communityPacks(),
	}
	if u.pluginCatalog == nil {
		view.Disabled = true
		u.render(w, "plugins_list.html", view)
		return
	}
	items := u.pluginCatalog.All()
	rows := make([]pluginRow, 0, len(items))
	for _, p := range items {
		rows = append(rows, pluginRow{
			Name:           p.Manifest.Name,
			Version:        p.Manifest.Version,
			Kinds:          p.Manifest.Kinds,
			SignatureValid: p.SignatureValid,
			Path:           p.Path,
			Description:    p.Manifest.Description,
			Generation:     p.Generation,
		})
	}
	view.Installed = rows
	u.render(w, "plugins_list.html", view)
}

// communityPacks returns the static catalog shipped with the v1.13
// binary. v2.9 swaps this for a live registry feed; until then
// operators see a curated list of starter packs the project blesses
// + a pointer to the GitHub topic for community submissions.
func communityPacks() []communityRow {
	return []communityRow{
		{
			Name:        "compliancekit/hello",
			Description: "The reference plugin. Ships under examples/plugins/hello; copy + iterate.",
			Source:      "https://github.com/darpanzope/compliancekit/tree/main/examples/plugins/hello",
			Kinds:       []pubplugin.Kind{pubplugin.KindCheck},
		},
		{
			Name:        "compliancekit/aws-iam-strict",
			Description: "Tighter MFA + key-rotation checks beyond the CIS baseline.",
			Source:      "https://github.com/darpanzope/compliancekit-plugins/tree/main/aws-iam-strict",
			Kinds:       []pubplugin.Kind{pubplugin.KindCheck},
		},
		{
			Name:        "compliancekit/slack-rich",
			Description: "Slack notifier with severity-colored attachments + drill-through buttons.",
			Source:      "https://github.com/darpanzope/compliancekit-plugins/tree/main/slack-rich",
			Kinds:       []pubplugin.Kind{pubplugin.KindNotifier},
		},
	}
}
