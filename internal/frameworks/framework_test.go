package frameworks

import (
	"testing"
)

func TestLoadAll_BundledFrameworks(t *testing.T) {
	fws, err := LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if _, ok := fws["soc2"]; !ok {
		t.Error("soc2 framework not loaded")
	}
	if _, ok := fws["cis-v8"]; !ok {
		t.Error("cis-v8 framework not loaded")
	}
}

func TestLoadAll_ControlIDsBackfilled(t *testing.T) {
	fws, err := LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	soc2 := fws["soc2"]
	if soc2 == nil {
		t.Fatal("soc2 missing")
	}
	for id, ctrl := range soc2.Controls {
		if ctrl.ID != id {
			t.Errorf("control under key %q has ID = %q, want %q", id, ctrl.ID, id)
		}
		if ctrl.Name == "" {
			t.Errorf("control %s has empty Name", id)
		}
	}
}

func TestGet_Hit(t *testing.T) {
	reset()
	fw, ok := Get("soc2")
	if !ok {
		t.Fatal("Get(soc2) miss")
	}
	if fw.Name == "" {
		t.Error("loaded framework has empty Name")
	}
}

func TestGet_Miss(t *testing.T) {
	reset()
	if _, ok := Get("nonexistent"); ok {
		t.Error("Get(nonexistent) should return false")
	}
}

func TestResolveCheckControls(t *testing.T) {
	reset()
	resolved := ResolveCheckControls(map[string][]string{
		"soc2":   {"CC6.6", "A1.2"},
		"cis-v8": {"4.4", "11.2"},
	})

	if len(resolved) != 4 {
		t.Fatalf("got %d resolved controls, want 4", len(resolved))
	}

	// Every entry must have a populated Framework and a non-empty
	// Control name.
	for _, rc := range resolved {
		if rc.Framework == nil {
			t.Error("nil Framework in resolved entry")
			continue
		}
		if rc.Control.Name == "" {
			t.Errorf("resolved control %s.%s has empty name", rc.Framework.ID, rc.Control.ID)
		}
	}
}

func TestResolveCheckControls_UnknownFrameworkSkipped(t *testing.T) {
	reset()
	resolved := ResolveCheckControls(map[string][]string{
		"soc2":           {"CC6.6"},
		"nonexistent-fw": {"X.1"},
	})
	if len(resolved) != 1 {
		t.Errorf("got %d resolved, want 1 (only soc2.CC6.6)", len(resolved))
	}
	if resolved[0].Framework.ID != "soc2" {
		t.Errorf("got framework %q, want soc2", resolved[0].Framework.ID)
	}
}

func TestResolveCheckControls_UnknownControlSkipped(t *testing.T) {
	reset()
	resolved := ResolveCheckControls(map[string][]string{
		"soc2": {"CC6.6", "INVALID-ID"},
	})
	if len(resolved) != 1 {
		t.Errorf("got %d resolved, want 1 (only the valid CC6.6)", len(resolved))
	}
	if resolved[0].Control.ID != "CC6.6" {
		t.Errorf("got control %q, want CC6.6", resolved[0].Control.ID)
	}
}

func TestAll_CachesAcrossCalls(t *testing.T) {
	reset()
	first, err1 := All()
	second, err2 := All()
	if err1 != nil || err2 != nil {
		t.Fatalf("All errors: %v / %v", err1, err2)
	}
	// Same map identity confirms the cache returned the prior value.
	if &first != &second {
		// Map identity in Go is compared by header equality; comparing
		// pointer addresses to local variables is meaningless. Check
		// instead that subsequent calls return the same underlying
		// slice of framework pointers.
		for id, v := range first {
			if second[id] != v {
				t.Errorf("framework %q changed identity across All() calls", id)
			}
		}
	}
}

func TestEveryControlReferencedByOurChecks_Resolves(t *testing.T) {
	// Sanity check: every (framework, control) pair our own checks
	// use should resolve. If a future check adds a mapping for a
	// control that isn't in the bundled YAML, this test fires.
	//
	// We don't import the check packages here (would create an import
	// cycle); instead the test enumerates the controls we know exist
	// today. Phase 6's `checks list` command will hook the actual
	// check registry.
	expectedSOC2 := []string{"CC1.4", "CC6.1", "CC6.6", "CC7.1", "CC7.2", "CC7.3", "A1.2"}
	expectedCIS := []string{"1.1", "3.3", "3.10", "4.1", "4.4", "5.1", "5.2", "5.4",
		"6.5", "6.8", "7.5", "8.5", "8.10", "11.2", "12.2"}

	soc2, _ := Get("soc2")
	for _, id := range expectedSOC2 {
		if _, ok := soc2.Controls[id]; !ok {
			t.Errorf("soc2.yaml missing control %s referenced by a check", id)
		}
	}
	cis, _ := Get("cis-v8")
	for _, id := range expectedCIS {
		if _, ok := cis.Controls[id]; !ok {
			t.Errorf("cis-v8.yaml missing control %s referenced by a check", id)
		}
	}
}
