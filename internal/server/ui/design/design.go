package design

import (
	"embed"
	"io/fs"
)

// ComponentsFS exposes the embedded component partials. ui.go composes
// these into the daemon's main template tree at init so
// `{{ template "ck-button" .Args }}` works from any daemon template.
//
//go:embed components/*.html
var ComponentsFS embed.FS

// ComponentsGlob is the glob ui.go passes to ParseFS.
const ComponentsGlob = "components/*.html"

// ComponentNames lists every partial shipped at v1.18 phase 3. The
// /design route handler (phase 7) iterates this list to render the
// live component zoo; new components add themselves here so any
// addition shows up in the visual-regression target.
var ComponentNames = []string{
	"ck-button",
	"ck-card",
	"ck-metric-card",
	"ck-pill",
	"ck-status-pill",
	"ck-info-tooltip",
	"ck-page-header",
	"ck-filter-card",
	"ck-toast",
	"ck-skeleton",
	"ck-avatar",
	"ck-empty-state",
	"ck-icon",
	"ck-tabs",
	"ck-dropdown",
	"ck-input",
	"ck-checkbox",
	"ck-select",
	"ck-textarea",
	"ck-modal",
	"ck-banner",
	"ck-section",
	"ck-divider",
	"ck-spinner",
	"ck-progress",
}

// Components returns the io/fs view rooted at the components directory.
// The /design route handler (phase 7) uses it to enumerate the on-disk
// partial files in the listing.
func Components() fs.FS {
	sub, err := fs.Sub(ComponentsFS, "components")
	if err != nil {
		// Cannot happen for a static embed glob.
		panic(err)
	}
	return sub
}
