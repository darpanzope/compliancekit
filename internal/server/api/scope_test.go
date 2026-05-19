package api

import (
	"testing"

	"github.com/darpanzope/compliancekit/internal/server/auth"
)

// TestIsWriteScope guards the F18 (v1.5.1) policy that non-admin
// session users may hit :read endpoints but not :write or admin.
func TestIsWriteScope(t *testing.T) {
	cases := []struct {
		scope auth.Scope
		write bool
	}{
		{auth.ScopeScansRead, false},
		{auth.ScopeFindingsRead, false},
		{auth.ScopeWaiversRead, false},
		{auth.ScopeSettingsRead, false},
		{auth.ScopeScansWrite, true},
		{auth.ScopeWaiversWrite, true},
		{auth.ScopeSettingsWrite, true},
		{auth.ScopeAdmin, true},
	}
	for _, c := range cases {
		if got := isWriteScope(c.scope); got != c.write {
			t.Errorf("isWriteScope(%q) = %v, want %v", c.scope, got, c.write)
		}
	}
}
