package ui

import (
	"strings"
	"testing"
)

func TestLatestChangelog(t *testing.T) {
	t.Parallel()
	entry, ok := latestChangelog()
	if !ok {
		t.Fatal("changelog catalog is empty")
	}
	if entry.Version != changelog[0].Version {
		t.Errorf("latestChangelog = %q, want newest %q", entry.Version, changelog[0].Version)
	}
	if changelogTourID(entry.Version) != "changelog-"+entry.Version {
		t.Errorf("changelogTourID(%q) = %q", entry.Version, changelogTourID(entry.Version))
	}
}

// TestChangelogModalRenders asserts base.html renders the modal +
// the dismiss form + deep links when ShowChangelog is set.
func TestChangelogModalRenders(t *testing.T) {
	t.Parallel()
	entry, _ := latestChangelog()
	out := renderContentTemplate(t, "onboarding.html", onboardingView{
		View: View{
			Title:         "Onboarding",
			CSRFToken:     "tok",
			ShowChangelog: true,
			Changelog:     entry,
		},
		Tours:     tours,
		Dismissed: map[string]bool{},
	})
	for _, want := range []string{
		"What's new",
		entry.Version,
		// Headline fragments only — html/template escapes "+" → "&#43;"
		// in HTML text, so the raw headline isn't a literal substring.
		"Onboarding 2.0",
		"table excellence",
		"/onboarding/tours/changelog-" + entry.Version + "/dismiss", // dismiss form action
		"Got it",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("changelog modal output missing %q", want)
		}
	}
}

// TestChangelogHiddenWhenNotSet asserts the modal does not render when
// ShowChangelog is false.
func TestChangelogHiddenWhenNotSet(t *testing.T) {
	t.Parallel()
	out := renderContentTemplate(t, "onboarding.html", onboardingView{
		View:  View{Title: "Onboarding", CSRFToken: "tok"},
		Tours: tours,
	})
	if strings.Contains(out, "What's new") {
		t.Error("changelog modal rendered with ShowChangelog=false")
	}
}
