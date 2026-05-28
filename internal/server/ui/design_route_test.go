package ui

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/server/ui/design"
)

// TestDesignZooCoversEveryComponent is the phase-7 CI gate: every entry
// in design.ComponentNames must have a `comp-<name>` section in the
// /design zoo. Catches a component added to the library without a zoo
// entry (the v1.18 plumbing requirement: any new component lands with
// a /design entry).
func TestDesignZooCoversEveryComponent(t *testing.T) {
	t.Parallel()
	out := renderDesignZoo(t)
	for _, name := range design.ComponentNames {
		anchor := `id="comp-` + name + `"`
		if !strings.Contains(out, anchor) {
			t.Errorf("/design zoo missing section %q — every component in design.ComponentNames must have a comp-<name> anchor", anchor)
		}
	}
}

// TestDesignZooRendersVariants spot-checks that the zoo actually renders
// the headline variants (not just the anchors).
func TestDesignZooRendersVariants(t *testing.T) {
	t.Parallel()
	out := renderDesignZoo(t)
	for _, want := range []string{
		"ck-metric-critical", // critical gradient MetricCard
		"ck-btn-destructive", // destructive button
		"ck-status-resolved", // resolved status pill
		"shadow-glass",       // glass shadow swatch
		"--ease-spring",      // spring easing preview
		"design-demo-modal",  // modal trigger + panel
		"gradient-primary",   // gradient palette swatch
		"brand-aws",          // provider brand swatch
	} {
		if !strings.Contains(out, want) {
			t.Errorf("/design zoo output missing %q", want)
		}
	}
}

// renderDesignZoo parses the base + components + zoo templates with the
// shared funcmap and renders the canned zoo view. Mirrors the render
// path UI.render uses without needing a *UI / DB.
func renderDesignZoo(t *testing.T) string {
	t.Helper()
	base, err := template.New("ui").Funcs(templateFuncs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		t.Fatalf("ParseFS templates: %v", err)
	}
	base, err = base.ParseFS(design.ComponentsFS, design.ComponentsGlob)
	if err != nil {
		t.Fatalf("ParseFS components: %v", err)
	}
	// Mirror UI.render: multiple templates define "content"; re-parsing
	// the target content template last makes its definition win.
	base, err = template.Must(base.Clone()).ParseFS(tmplFS, "templates/design_zoo.html")
	if err != nil {
		t.Fatalf("ParseFS design_zoo: %v", err)
	}
	var buf bytes.Buffer
	if err := base.ExecuteTemplate(&buf, "base", buildDesignZoo()); err != nil {
		t.Fatalf("ExecuteTemplate base: %v", err)
	}
	return buf.String()
}
