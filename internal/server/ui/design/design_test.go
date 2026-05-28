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
