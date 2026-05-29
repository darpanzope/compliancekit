package design_test

import (
	"bytes"
	"html/template"
	"io/fs"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/server/ui/design"
)

// TestComponentsParse asserts every embedded partial parses cleanly.
// Catches malformed `{{ define }}` blocks at test time rather than at
// daemon startup.
func TestComponentsParse(t *testing.T) {
	t.Parallel()
	t.Helper()
	funcs := template.FuncMap{
		"mkInfoTooltip": func(s string) design.InfoTooltipArgs { return design.InfoTooltipArgs{Text: s} },
		"add":           func(a, b int) int { return a + b },
	}
	tmpl, err := template.New("design-test").Funcs(funcs).ParseFS(design.ComponentsFS, design.ComponentsGlob)
	if err != nil {
		t.Fatalf("ParseFS(components/*.html): %v", err)
	}
	for _, name := range design.ComponentNames {
		if tmpl.Lookup(name) == nil {
			t.Errorf("component %q missing from parsed tree", name)
		}
	}
}

// TestComponentsRender renders every component with a representative
// arg payload + checks the output contains its canonical ck-* class
// marker. Catches a partial that the parser accepts but that panics
// on the render path.
func TestComponentsRender(t *testing.T) {
	t.Parallel()
	t.Helper()
	funcs := template.FuncMap{
		"mkInfoTooltip": func(s string) design.InfoTooltipArgs { return design.InfoTooltipArgs{Text: s} },
		"add":           func(a, b int) int { return a + b },
	}
	tmpl, err := template.New("design-test").Funcs(funcs).ParseFS(design.ComponentsFS, design.ComponentsGlob)
	if err != nil {
		t.Fatalf("ParseFS: %v", err)
	}
	cases := []struct {
		name    string
		args    any
		wantSub string
	}{
		{"ck-button", design.ButtonArgs{Label: "Save", Variant: "primary"}, "ck-btn"},
		{"ck-card", design.CardArgs{Title: "Card", Body: template.HTML("<p>x</p>")}, "ck-card"},
		{"ck-metric-card", design.MetricCardArgs{Title: "Open findings", Value: "42", Variant: "critical"}, "ck-metric-card"},
		{"ck-pill", design.PillArgs{Variant: "severity-critical", Label: "critical"}, "ck-pill"},
		{"ck-status-pill", design.StatusPillArgs{Status: "open", Label: "open"}, "ck-status-pill"},
		{"ck-info-tooltip", design.InfoTooltipArgs{Text: "What this means"}, "ck-info-tooltip"},
		{"ck-page-header", design.PageHeaderArgs{Title: "Scans", Subtitle: "All runs"}, "ck-page-header"},
		{"ck-filter-card", design.FilterCardArgs{Title: "Filters", Body: template.HTML("<div/>")}, "ck-filter-card"},
		{"ck-toast", design.ToastArgs{Variant: "success", Title: "Saved", Message: "ok"}, "ck-toast"},
		{"ck-skeleton", design.SkeletonArgs{Variant: "text"}, "ck-skeleton"},
		{"ck-avatar", design.AvatarArgs{Initials: "DZ", Name: "Darpan"}, "ck-avatar"},
		{"ck-empty-state", design.EmptyStateArgs{Title: "No findings"}, "ck-empty-state"},
		{"ck-icon", design.IconArgs{Name: "search"}, "ck-icon"},
		{"ck-tabs", design.TabsArgs{Items: []design.TabItem{{Key: "a", Label: "A", Href: "/a"}}, Current: "a"}, "ck-tabs"},
		{"ck-dropdown", design.DropdownArgs{Trigger: template.HTML("Menu"), Items: []design.DropdownItem{{Label: "One", Href: "/1"}}}, "ck-dropdown"},
		{"ck-input", design.InputArgs{Name: "q", Label: "Query"}, "ck-input"},
		{"ck-checkbox", design.CheckboxArgs{Name: "remember", Label: "Remember me"}, "ck-checkbox"},
		{"ck-select", design.SelectArgs{Name: "size", Label: "Size", Options: []design.SelectOption{{Value: "sm", Label: "Small"}}}, "ck-select"},
		{"ck-textarea", design.TextareaArgs{Name: "note", Label: "Note"}, "ck-textarea"},
		{"ck-modal", design.ModalArgs{ID: "demo", Title: "Title", Body: template.HTML("body")}, "ck-modal-backdrop"},
		{"ck-banner", design.BannerArgs{Variant: "warning", Title: "Heads up", Message: "thing"}, "ck-banner"},
		{"ck-section", design.SectionArgs{Title: "Section", Body: template.HTML("<p/>")}, "ck-section"},
		{"ck-divider", design.DividerArgs{}, "ck-divider"},
		{"ck-spinner", design.SpinnerArgs{}, "ck-spinner"},
		{"ck-progress", design.ProgressArgs{Value: 42, Variant: "success"}, "ck-progress"},
	}
	if len(cases) != len(design.ComponentNames) {
		t.Fatalf("render-case count %d != ComponentNames count %d — keep them in sync", len(cases), len(design.ComponentNames))
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := tmpl.ExecuteTemplate(&buf, c.name, c.args); err != nil {
				t.Fatalf("ExecuteTemplate(%q): %v", c.name, err)
			}
			if !strings.Contains(buf.String(), c.wantSub) {
				t.Errorf("ExecuteTemplate(%q) output missing %q\n--- output ---\n%s", c.name, c.wantSub, buf.String())
			}
		})
	}
}

// TestMetricCardCriticalTrend pins the v1.18 phase 4 DoD: a critical-
// variant MetricCard with `trend up 12%` renders the gradient class +
// the trend arrow + the decorative circle.
func TestMetricCardCriticalTrend(t *testing.T) {
	t.Parallel()
	tmpl, err := template.New("metric-test").ParseFS(design.ComponentsFS, "components/ck-metric-card.html")
	if err != nil {
		t.Fatalf("ParseFS: %v", err)
	}
	args := design.MetricCardArgs{
		Title:   "Open critical",
		Value:   "12",
		Variant: "critical",
		Trend:   &design.MetricTrend{Delta: "12%", Direction: "up", Polarity: "bad"},
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "ck-metric-card", args); err != nil {
		t.Fatalf("ExecuteTemplate: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"ck-metric-critical",   // gradient variant class
		"ck-metric-decoration", // decorative top-right circle
		"ck-metric-trend",      // trend container
		"ck-trend-up",          // direction
		"ck-trend-bad",         // polarity → red arrow
		"&uarr;",               // up arrow glyph
		"12%",                  // delta text
	} {
		if !strings.Contains(out, want) {
			t.Errorf("critical+trend MetricCard missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestMetricCardInfoIsFlat asserts the info variant does NOT render the
// gradient decoration (info is a flat card per phase 4).
func TestMetricCardInfoIsFlat(t *testing.T) {
	t.Parallel()
	tmpl, err := template.New("metric-test").ParseFS(design.ComponentsFS, "components/ck-metric-card.html")
	if err != nil {
		t.Fatalf("ParseFS: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "ck-metric-card", design.MetricCardArgs{Title: "Info", Value: "3", Variant: "info"}); err != nil {
		t.Fatalf("ExecuteTemplate: %v", err)
	}
	if strings.Contains(buf.String(), "ck-metric-decoration") {
		t.Errorf("info MetricCard should be flat (no decoration circle)\n--- output ---\n%s", buf.String())
	}
}

// TestIllustrationsEmbedded asserts the empty-state illustration
// catalog is embedded + every name resolves to a non-empty <svg> that
// uses currentColor (so it's theme-aware). v1.18 phase 10.
func TestIllustrationsEmbedded(t *testing.T) {
	t.Parallel()
	if len(design.IllustrationNames) < 24 {
		t.Fatalf("expected ~30 illustrations, found %d", len(design.IllustrationNames))
	}
	for _, name := range design.IllustrationNames {
		svg := string(design.Illustration(name))
		if !strings.Contains(svg, "<svg") {
			t.Errorf("illustration %q is not an <svg>", name)
		}
		if !strings.Contains(svg, "currentColor") {
			t.Errorf("illustration %q must use currentColor to stay theme-aware", name)
		}
	}
	// Unknown name resolves to empty (no panic).
	if design.Illustration("definitely-not-a-real-illustration") != "" {
		t.Error("unknown illustration should return empty string")
	}
}

// TestAvatarGradientDeterministic asserts AvatarGradient is stable per
// name (same name → same gradient) + different names usually differ.
// v1.18 phase 11.
func TestAvatarGradientDeterministic(t *testing.T) {
	t.Parallel()
	a1 := design.AvatarGradient("Darpan Zope")
	a2 := design.AvatarGradient("Darpan Zope")
	if a1 != a2 {
		t.Errorf("AvatarGradient not deterministic: %q != %q", a1, a2)
	}
	if !strings.Contains(string(a1), "linear-gradient") {
		t.Errorf("AvatarGradient should be a linear-gradient, got %q", a1)
	}
	if design.AvatarGradient("") != "var(--gradient-primary)" {
		t.Error("empty name should fall back to the brand gradient")
	}
	// The palette has 12 hues, so the picker should produce more than
	// one distinct gradient across a spread of names (sanity check that
	// it isn't constant).
	seen := map[template.CSS]bool{}
	for _, n := range []string{"alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"} {
		seen[design.AvatarGradient(n)] = true
	}
	if len(seen) < 2 {
		t.Errorf("AvatarGradient produced only %d distinct gradients across 8 names — picker looks constant", len(seen))
	}
}

// TestComponentsFSRoots checks the embedded FS exposes the components
// directory at the expected path. Catches a go:embed glob change.
func TestComponentsFSRoots(t *testing.T) {
	t.Parallel()
	entries, err := fs.ReadDir(design.Components(), ".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) < len(design.ComponentNames) {
		t.Errorf("found %d component files in embed FS; expected >= %d", len(entries), len(design.ComponentNames))
	}
}
