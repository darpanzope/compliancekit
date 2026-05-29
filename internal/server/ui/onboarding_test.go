package ui

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/server/ui/design"
)

// renderContentTemplate parses the base + component + the named content
// template (last, so its "content" definition wins) and executes "base"
// against view. Used by UI template tests that don't need a *UI / DB.
func renderContentTemplate(t *testing.T, name string, view any) string {
	t.Helper()
	base, err := template.New("ui").Funcs(templateFuncs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		t.Fatalf("ParseFS templates: %v", err)
	}
	base, err = base.ParseFS(design.ComponentsFS, design.ComponentsGlob)
	if err != nil {
		t.Fatalf("ParseFS components: %v", err)
	}
	base, err = template.Must(base.Clone()).ParseFS(tmplFS, "templates/"+name)
	if err != nil {
		t.Fatalf("ParseFS %s: %v", name, err)
	}
	var buf bytes.Buffer
	if err := base.ExecuteTemplate(&buf, "base", view); err != nil {
		t.Fatalf("ExecuteTemplate base: %v", err)
	}
	return buf.String()
}

// TestOnboardingPageRenders renders /onboarding via the template tree +
// asserts the tour catalog shows. Mirrors the design-zoo render path:
// re-parse the target content template last so its "content" wins.
func TestOnboardingPageRenders(t *testing.T) {
	t.Parallel()
	out := renderContentTemplate(t, "onboarding.html", onboardingView{
		View:      View{Title: "Onboarding", CSRFToken: "tok"},
		Tours:     tours,
		Dismissed: map[string]bool{"search": true},
	})
	for _, want := range []string{
		"Onboarding",
		"Welcome tour",
		"Global search",
		"/scans?tour=welcome", // replay link force-starts the tour
		"/onboarding/reset",
		"seen", // the dismissed "search" tour shows the seen pill
	} {
		if !strings.Contains(out, want) {
			t.Errorf("/onboarding output missing %q", want)
		}
	}
}

// renderComponent parses the component partials with the shared funcmap
// + executes one by name against args. Used to render a single design
// component without the full base chrome.
func renderComponent(t *testing.T, name string, args any) string {
	t.Helper()
	tmpl, err := template.New("c").Funcs(templateFuncs).ParseFS(design.ComponentsFS, design.ComponentsGlob)
	if err != nil {
		t.Fatalf("ParseFS components: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, args); err != nil {
		t.Fatalf("ExecuteTemplate(%q): %v", name, err)
	}
	return buf.String()
}

// TestFirstRunCoach asserts the phase-3 coaching card has the 3 deep-
// linked steps + renders them through ck-empty-state.
func TestFirstRunCoach(t *testing.T) {
	t.Parallel()
	c := firstRunCoach()
	if len(c.Steps) != 3 {
		t.Fatalf("firstRunCoach has %d steps, want 3", len(c.Steps))
	}
	for _, s := range c.Steps {
		if s.Text == "" || s.Href == "" || s.CTA == "" {
			t.Errorf("coaching step %+v has an empty field", s)
		}
	}
	out := renderComponent(t, "ck-empty-state", c)
	for _, want := range []string{"ck-empty-steps", "/setup", "/scans/new", "/findings", "Run scan →"} {
		if !strings.Contains(out, want) {
			t.Errorf("firstRunCoach render missing %q", want)
		}
	}
}

// TestTourCatalogStable guards the shipped tour ids — tour.js + the nav
// data-ck-tour attributes reference these by string.
func TestTourCatalogStable(t *testing.T) {
	t.Parallel()
	ids := map[string]bool{}
	for _, tr := range tours {
		if tr.ID == "" || tr.Title == "" || tr.Href == "" {
			t.Errorf("tour %+v has an empty required field", tr)
		}
		if ids[tr.ID] {
			t.Errorf("duplicate tour id %q", tr.ID)
		}
		ids[tr.ID] = true
	}
	if !ids["welcome"] {
		t.Error("the welcome tour must exist — base.html nav anchors data-ck-tour=\"welcome\"")
	}
}
