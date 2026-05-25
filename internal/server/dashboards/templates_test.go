package dashboards

import (
	"context"
	"testing"
)

func TestBuiltinTemplatesShape(t *testing.T) {
	got := BuiltinTemplates()
	want := []string{"exec", "aws", "k8s", "soc2"}
	if len(got) != len(want) {
		t.Fatalf("expected %d templates, got %d", len(want), len(got))
	}
	for i, w := range want {
		if got[i].ID != w {
			t.Errorf("template[%d].ID = %q want %q", i, got[i].ID, w)
		}
		if got[i].Name == "" || len(got[i].Widgets) == 0 {
			t.Errorf("template %q empty", w)
		}
	}
}

func TestTemplateByID(t *testing.T) {
	if _, ok := TemplateByID("exec"); !ok {
		t.Errorf("exec should be a known template")
	}
	if _, ok := TemplateByID("nope"); ok {
		t.Errorf("nope should not match a template")
	}
}

func TestCloneTemplate(t *testing.T) {
	ctx := context.Background()
	st, s := newTestStore(t)
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO users (id, email, display_name, is_admin, created_at) VALUES (?, ?, ?, 0, ?)`,
		"u-1", "alice@example.com", "Alice", "2026-05-25T00:00:00Z"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	d, err := s.CloneTemplate(ctx, "exec", "u-1", "u-1", "My exec board")
	if err != nil {
		t.Fatalf("CloneTemplate: %v", err)
	}
	if d.Template != "exec" {
		t.Errorf("template column = %q want exec", d.Template)
	}
	if d.Name != "My exec board" {
		t.Errorf("name = %q want My exec board", d.Name)
	}
	if len(d.Widgets) != len(BuiltinTemplates()[0].Widgets) {
		t.Errorf("widget count = %d want %d", len(d.Widgets), len(BuiltinTemplates()[0].Widgets))
	}
}

func TestCloneTemplate_UnknownReturnsError(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	if _, err := s.CloneTemplate(ctx, "nope", "", "", ""); err == nil {
		t.Errorf("expected unknown-template error")
	}
}
