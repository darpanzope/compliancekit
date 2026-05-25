package dashboards

import (
	"context"
	"testing"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

func newTestStore(t *testing.T) (*store.Store, *Store) {
	t.Helper()
	st, err := store.OpenSQLite(context.Background(),
		"file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.MigrateUp(context.Background()); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	return st, New(st)
}

func TestCreateAndLoadDashboard(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	d, err := s.CreateDashboard(ctx, "", "", "Executive overview", "Top-level snapshot", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if d.ID == "" {
		t.Errorf("expected ID set")
	}
	got, err := s.ByID(ctx, d.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.Name != "Executive overview" {
		t.Errorf("name = %q want Executive overview", got.Name)
	}
	if len(got.Widgets) != 0 {
		t.Errorf("expected empty widget list, got %d", len(got.Widgets))
	}
}

func TestAddWidget_ClampsGrid(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	d, _ := s.CreateDashboard(ctx, "", "", "x", "", "")
	w, err := s.AddWidget(ctx, &Widget{
		DashboardID: d.ID,
		Kind:        KindScoreGauge,
		Title:       "Score",
		GridW:       50, // exceeds 12 → clamp
		GridH:       100,
	})
	if err != nil {
		t.Fatalf("AddWidget: %v", err)
	}
	if w.GridW != 12 {
		t.Errorf("grid_w = %d want clamped to 12", w.GridW)
	}
	if w.GridH != 24 {
		t.Errorf("grid_h = %d want clamped to 24", w.GridH)
	}
	got, _ := s.ByID(ctx, d.ID)
	if len(got.Widgets) != 1 {
		t.Errorf("expected 1 widget, got %d", len(got.Widgets))
	}
}

func TestAddWidget_RejectsUnknownKind(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	d, _ := s.CreateDashboard(ctx, "", "", "x", "", "")
	if _, err := s.AddWidget(ctx, &Widget{
		DashboardID: d.ID,
		Kind:        Kind("frobnicator"),
	}); err == nil {
		t.Errorf("expected error for unknown kind")
	}
}

func TestSaveLoadLayout(t *testing.T) {
	ctx := context.Background()
	st, s := newTestStore(t)
	// Seed a user (FK requirement).
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO users (id, email, display_name, is_admin, created_at) VALUES (?, ?, ?, 1, ?)`,
		"u-1", "alice@example.com", "Alice", "2026-05-25T00:00:00Z"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	d, _ := s.CreateDashboard(ctx, "", "u-1", "x", "", "")
	want := `[{"widget_id":"w-1","x":0,"y":0,"w":6,"h":4}]`
	if err := s.SaveLayout(ctx, "u-1", d.ID, want); err != nil {
		t.Fatalf("SaveLayout: %v", err)
	}
	got, err := s.LayoutFor(ctx, "u-1", d.ID)
	if err != nil {
		t.Fatalf("LayoutFor: %v", err)
	}
	if got != want {
		t.Errorf("roundtrip: got %q want %q", got, want)
	}
}

func TestVisibilityFiltering(t *testing.T) {
	ctx := context.Background()
	st, s := newTestStore(t)
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO users (id, email, display_name, is_admin, created_at) VALUES (?, ?, ?, 0, ?), (?, ?, ?, 0, ?)`,
		"u-alice", "alice@x.com", "A", "2026-05-25T00:00:00Z",
		"u-bob", "bob@x.com", "B", "2026-05-25T00:00:00Z"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, _ = s.CreateDashboard(ctx, "", "", "Team-wide", "", "")
	_, _ = s.CreateDashboard(ctx, "u-alice", "u-alice", "Alice's private", "", "")
	_, _ = s.CreateDashboard(ctx, "u-bob", "u-bob", "Bob's private", "", "")

	alice, _ := s.ListVisible(ctx, "u-alice")
	if len(alice) != 2 {
		t.Errorf("alice should see team-wide + own: got %d", len(alice))
	}
	bob, _ := s.ListVisible(ctx, "u-bob")
	if len(bob) != 2 {
		t.Errorf("bob should see team-wide + own: got %d", len(bob))
	}
	team, _ := s.ListVisible(ctx, "")
	if len(team) != 1 {
		t.Errorf("anon should see only team-wide: got %d", len(team))
	}
}

func TestAllKindsCoverage(t *testing.T) {
	for _, k := range AllKinds {
		if !isKnownKind(k) {
			t.Errorf("kind %q in AllKinds but not isKnownKind", k)
		}
	}
}
