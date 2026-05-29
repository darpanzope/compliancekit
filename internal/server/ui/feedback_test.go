package ui

import (
	"strings"
	"testing"
)

func TestFeedbackKindsClosed(t *testing.T) {
	t.Parallel()
	for _, k := range []string{"bug", "feature", "love"} {
		if !feedbackKinds[k] {
			t.Errorf("feedbackKinds missing %q", k)
		}
	}
	if feedbackKinds["spam"] {
		t.Error("feedbackKinds should be a closed set")
	}
}

func TestRandomIDUnique(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := randomID()
		if len(id) != 32 {
			t.Fatalf("randomID len = %d, want 32 hex chars", len(id))
		}
		if seen[id] {
			t.Fatalf("randomID collision on %q", id)
		}
		seen[id] = true
	}
}

// TestAdminFeedbackRenders renders the admin queue with a couple of
// rows + the empty state.
func TestAdminFeedbackRenders(t *testing.T) {
	t.Parallel()
	out := renderContentTemplate(t, "admin_feedback.html", adminFeedbackView{
		View: View{Title: "Feedback", CSRFToken: "tok"},
		Rows: []feedbackRow{
			{ID: "a1", UserEmail: "demo@x.dev", Kind: "bug", Message: "broke", PageURL: "/findings", Status: "new", CreatedAt: "2026-05-29T10:00:00Z"},
			{ID: "a2", UserEmail: "", Kind: "love", Message: "great", Status: "closed", CreatedAt: "2026-05-29T09:00:00Z"},
		},
	})
	for _, want := range []string{"Feedback", "demo@x.dev", "broke", "/admin/feedback/a1/status", "triaged"} {
		if !strings.Contains(out, want) {
			t.Errorf("admin feedback output missing %q", want)
		}
	}

	empty := renderContentTemplate(t, "admin_feedback.html", adminFeedbackView{
		View: View{Title: "Feedback", CSRFToken: "tok"},
	})
	if !strings.Contains(empty, "No feedback yet") {
		t.Error("empty feedback queue should render the empty state")
	}
}
