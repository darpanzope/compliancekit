package ui

import "testing"

func TestTableIDValidation(t *testing.T) {
	t.Parallel()
	ok := []string{"findings", "resources", "scans", "a", "a-b_c", "abc123"}
	bad := []string{"", "Findings", "has space", "a/b", "tooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo-long-x"}
	for _, id := range ok {
		if !tableIDRe.MatchString(id) {
			t.Errorf("table id %q should be valid", id)
		}
	}
	for _, id := range bad {
		if tableIDRe.MatchString(id) {
			t.Errorf("table id %q should be rejected", id)
		}
	}
	// Guard against the regex drifting from the documented bound.
	if tableIDRe.String() != `^[a-z0-9_-]{1,64}$` {
		t.Errorf("tableIDRe drifted: %s", tableIDRe.String())
	}
}
