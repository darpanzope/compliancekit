package compliancekit

import (
	"context"
	"testing"
)

// noopFn is a CheckFunc that does nothing. Used throughout these tests
// where the function body is irrelevant -- the registry doesn't care
// what the function does, only that it's stored alongside metadata.
func noopFn(_ context.Context, _ *ResourceGraph) ([]Finding, error) { return nil, nil }

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()

	var called bool
	fn := func(_ context.Context, _ *ResourceGraph) ([]Finding, error) {
		called = true
		return nil, nil
	}

	r.Register(Check{ID: "test-check", Severity: SeverityHigh}, fn)

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

	// Metadata side: Check() returns the registered struct.
	c, ok := r.Check("test-check")
	if !ok {
		t.Fatal("Check(test-check) returned not found")
	}
	if c.Severity != SeverityHigh {
		t.Errorf("Check.Severity = %s, want high", c.Severity)
	}
}

func TestRegistry_GetMissing(t *testing.T) {
	r := NewRegistry()
	if _, ok := r.Get("missing"); ok {
		t.Error("Get on empty registry returned ok=true")
	}
	if _, ok := r.Check("missing"); ok {
		t.Error("Check on empty registry returned ok=true")
	}
}

func TestRegistry_DuplicateRegistrationPanics(t *testing.T) {
	r := NewRegistry()
	r.Register(Check{ID: "dup"}, noopFn)

	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()
	r.Register(Check{ID: "dup"}, noopFn)
}

func TestRegistry_IDsAndChecks_Sorted(t *testing.T) {
	r := NewRegistry()
	r.Register(Check{ID: "c-check", Title: "C"}, noopFn)
	r.Register(Check{ID: "a-check", Title: "A"}, noopFn)
	r.Register(Check{ID: "b-check", Title: "B"}, noopFn)

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

	checks := r.Checks()
	if len(checks) != len(want) {
		t.Fatalf("Checks() length %d, want %d", len(checks), len(want))
	}
	for i, c := range checks {
		if c.ID != want[i] {
			t.Errorf("Checks()[%d].ID = %q, want %q", i, c.ID, want[i])
		}
	}
}

func TestRegistry_Count(t *testing.T) {
	r := NewRegistry()
	if r.Count() != 0 {
		t.Errorf("empty Count() = %d, want 0", r.Count())
	}
	r.Register(Check{ID: "a"}, noopFn)
	r.Register(Check{ID: "b"}, noopFn)
	if r.Count() != 2 {
		t.Errorf("Count() = %d, want 2", r.Count())
	}
}

func TestRegistry_IsolationFromDefault(t *testing.T) {
	// Test-local registries must not leak into the default registry.
	r := NewRegistry()
	r.Register(Check{ID: "isolated-check"}, noopFn)

	if _, ok := Lookup("isolated-check"); ok {
		t.Error("isolated registration leaked into default registry")
	}
	if _, ok := LookupCheck("isolated-check"); ok {
		t.Error("isolated metadata leaked into default registry")
	}
}
