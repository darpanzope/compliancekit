package design

import (
	"embed"
	"html/template"
	"io/fs"
	"sort"
	"strings"
)

// illustrationsFS holds the ~30 hand-drawn-style empty-state SVGs. Each
// uses stroke="currentColor" (no hardcoded colors) so it adapts to the
// active palette — light / dark / high-contrast — via the text color of
// the enclosing .ck-empty-illustration container. v1.18 phase 10.
//
//go:embed illustrations/*.svg
var illustrationsFS embed.FS

// IllustrationNames lists every shipped empty-state illustration, sorted.
var IllustrationNames = loadIllustrationNames()

func loadIllustrationNames() []string {
	entries, err := fs.ReadDir(illustrationsFS, "illustrations")
	if err != nil {
		panic(err) // cannot happen for a static embed glob
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, strings.TrimSuffix(e.Name(), ".svg"))
	}
	sort.Strings(names)
	return names
}

// Illustration returns the named empty-state SVG as trusted HTML, or an
// empty string if the name is unknown. The SVGs are build-time embedded
// literals (never user input) so promoting to template.HTML is safe.
func Illustration(name string) template.HTML {
	b, err := illustrationsFS.ReadFile("illustrations/" + name + ".svg")
	if err != nil {
		return ""
	}
	return template.HTML(b) //nolint:gosec // build-time embedded SVG, not user input
}
