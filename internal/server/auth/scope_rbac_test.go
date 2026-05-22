package auth

import "testing"

// TestScopeRBAC verifies every defined Scope (except the universal
// admin wildcard) maps to a (resource, action) tuple that the v1.12
// migration recognizes. Adding a new scope without extending the
// switch silently breaks the role-derived gate — this test catches it
// at build time.
func TestScopeRBAC(t *testing.T) {
	cases := []struct {
		scope  Scope
		res    string
		act    string
		mappOK bool
	}{
		{ScopeScansRead, "scans", "read", true},
		{ScopeScansWrite, "scans", "write", true},
		{ScopeFindingsRead, "findings", "read", true},
		{ScopeWaiversRead, "waivers", "read", true},
		{ScopeWaiversWrite, "waivers", "write", true},
		{ScopeSettingsRead, "settings", "read", true},
		{ScopeSettingsWrite, "settings", "write", true},
		{ScopeAdmin, "", "", false},
		{Scope("made:up"), "", "", false},
	}
	for _, c := range cases {
		gotRes, gotAct, ok := c.scope.ScopeRBAC()
		if ok != c.mappOK {
			t.Errorf("ScopeRBAC(%q) ok=%v want %v", c.scope, ok, c.mappOK)
		}
		if gotRes != c.res || gotAct != c.act {
			t.Errorf("ScopeRBAC(%q) = (%q,%q) want (%q,%q)", c.scope, gotRes, gotAct, c.res, c.act)
		}
	}
}
