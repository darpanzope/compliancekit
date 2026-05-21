package rbac

import "testing"

func TestRoleHas(t *testing.T) {
	r := &Role{
		Name: "editor",
		Permissions: []Permission{
			{Resource: ResourceScans, Action: ActionRead},
			{Resource: ResourceScans, Action: ActionWrite},
		},
	}
	if !r.Has(ResourceScans, ActionRead) {
		t.Errorf("expected scans:read grant")
	}
	if r.Has(ResourceScans, ActionDelete) {
		t.Errorf("did not expect scans:delete grant")
	}
	if r.Has(ResourceSettings, ActionRead) {
		t.Errorf("did not expect cross-resource leakage")
	}
}

func TestSetAddHas(t *testing.T) {
	s := NewSet("u-1")
	if s.Has(ResourceScans, ActionRead) {
		t.Errorf("empty set should not have any grants")
	}
	if s.HasAny(ResourceScans) {
		t.Errorf("empty set should not match HasAny")
	}
	s.Add(ResourceScans, ActionRead)
	s.Add(ResourceScans, ActionWrite)
	s.Add(ResourceFindings, ActionRead)
	// duplicate add is a no-op.
	s.Add(ResourceScans, ActionRead)
	if !s.Has(ResourceScans, ActionRead) {
		t.Errorf("expected scans:read after Add")
	}
	if !s.Has(ResourceFindings, ActionRead) {
		t.Errorf("expected findings:read after Add")
	}
	if s.Has(ResourceFindings, ActionWrite) {
		t.Errorf("did not Add findings:write")
	}
	if !s.HasAny(ResourceScans) || !s.HasAny(ResourceFindings) {
		t.Errorf("HasAny should match added resources")
	}
	if s.HasAny(ResourceUsers) {
		t.Errorf("HasAny should not match un-added resources")
	}
}

func TestNilSetSafe(t *testing.T) {
	var s *Set
	if s.Has(ResourceScans, ActionRead) {
		t.Errorf("nil Set.Has should be false, not panic")
	}
	if s.HasAny(ResourceScans) {
		t.Errorf("nil Set.HasAny should be false, not panic")
	}
}

func TestEnumIterationOrder(t *testing.T) {
	if len(AllResources) == 0 || len(AllActions) == 0 {
		t.Fatalf("enum iteration slices must be non-empty")
	}
	if AllResources[0] != ResourceScans {
		t.Errorf("AllResources should start with scans, got %s", AllResources[0])
	}
	if AllActions[0] != ActionRead {
		t.Errorf("AllActions should start with read, got %s", AllActions[0])
	}
}
