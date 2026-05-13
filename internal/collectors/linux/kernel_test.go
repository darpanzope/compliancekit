package linux

import "testing"

func TestParseSysctlNValues_HappyPath(t *testing.T) {
	output := `2
0
0
`
	got := parseSysctlNValues(output)
	if got[0] != 2 || got[1] != 0 || got[2] != 0 {
		t.Errorf("got %v, want {0:2, 1:0, 2:0}", got)
	}
}

func TestParseSysctlNValues_SkipsNonNumeric(t *testing.T) {
	// `sysctl -n -e` ignores unknown keys silently, but if any line
	// somehow emits a non-numeric value we just skip it. Subsequent
	// positions still hold the right value.
	output := `2
not-numeric
0
`
	got := parseSysctlNValues(output)
	if got[0] != 2 {
		t.Errorf("got[0] = %d, want 2", got[0])
	}
	if _, ok := got[1]; ok {
		t.Error("position 1 should be skipped (non-numeric)")
	}
	if got[2] != 0 {
		t.Errorf("got[2] = %d, want 0", got[2])
	}
}

func TestParseSysctlNValues_EmptyInput(t *testing.T) {
	if got := parseSysctlNValues(""); len(got) != 0 {
		t.Errorf("empty input should yield empty map, got %v", got)
	}
}
