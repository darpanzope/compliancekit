package core

import (
	"context"
	"testing"
)

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()

	var called bool
	fn := func(_ context.Context, _ *ResourceGraph) ([]Finding, error) {
		called = true
		return nil, nil
	}

	r.Register("test-check", fn)

	got, ok := r.Get("test-check")
	if !ok {
		t.Fatal("Get(test-check) returned not found")
	}

	if _, err := got(context.Background(), NewResourceGraph()); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if !called {
		t.Error("retrieved CheckFunc was not invoked")
	}
}

func TestRegistry_GetMissing(t *testing.T) {
	r := NewRegistry()
	if _, ok := r.Get("missing"); ok {
		t.Error("Get on empty registry returned ok=true")
	}
}

func TestRegistry_DuplicateRegistrationPanics(t *testing.T) {
	r := NewRegistry()
	fn := func(_ context.Context, _ *ResourceGraph) ([]Finding, error) { return nil, nil }

	r.Register("dup", fn)

	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()
	r.Register("dup", fn)
}

func TestRegistry_IDsAreSorted(t *testing.T) {
	r := NewRegistry()
	fn := func(_ context.Context, _ *ResourceGraph) ([]Finding, error) { return nil, nil }

	r.Register("c-check", fn)
	r.Register("a-check", fn)
	r.Register("b-check", fn)

	ids := r.IDs()
	want := []string{"a-check", "b-check", "c-check"}
	if len(ids) != len(want) {
		t.Fatalf("IDs() length %d, want %d", len(ids), len(want))
	}
	for i, id := range ids {
		if id != want[i] {
			t.Errorf("IDs()[%d] = %q, want %q", i, id, want[i])
		}
	}
}

func TestRegistry_Count(t *testing.T) {
	r := NewRegistry()
	if r.Count() != 0 {
		t.Errorf("empty Count() = %d, want 0", r.Count())
	}

	fn := func(_ context.Context, _ *ResourceGraph) ([]Finding, error) { return nil, nil }
	r.Register("a", fn)
	r.Register("b", fn)

	if r.Count() != 2 {
		t.Errorf("Count() = %d, want 2", r.Count())
	}
}

func TestRegistry_IsolationFromDefault(t *testing.T) {
	// Test-local registries must not leak into the default registry.
	r := NewRegistry()
	fn := func(_ context.Context, _ *ResourceGraph) ([]Finding, error) { return nil, nil }
	r.Register("isolated-check", fn)

	if _, ok := Lookup("isolated-check"); ok {
		t.Error("isolated registration leaked into default registry")
	}
}
