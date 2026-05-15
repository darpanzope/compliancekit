package frameworks

import (
	"testing"
)

func TestNewTailoring_RequiresAllFields(t *testing.T) {
	cases := []struct {
		name string
		rule TailoringRule
	}{
		{"missing framework", TailoringRule{Control: "CC1.4", Justification: "x"}},
		{"missing control", TailoringRule{Framework: "soc2", Justification: "x"}},
		{"missing justification", TailoringRule{Framework: "soc2", Control: "CC1.4"}},
		{"whitespace justification", TailoringRule{Framework: "soc2", Control: "CC1.4", Justification: "   "}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewTailoring([]TailoringRule{c.rule}); err == nil {
				t.Errorf("expected validation error for %s", c.name)
			}
		})
	}
}

func TestNewTailoring_AcceptsValid(t *testing.T) {
	rules := []TailoringRule{
		{Framework: "soc2", Control: "CC1.4", Justification: "Pre-audit; no compliance officer yet."},
		{Framework: "pci-dss-v4", Control: "10.6.1", Justification: "Out of scope — no PAN data."},
	}
	tl, err := NewTailoring(rules)
	if err != nil {
		t.Fatalf("NewTailoring: %v", err)
	}
	if tl.Count() != 2 {
		t.Errorf("Count = %d, want 2", tl.Count())
	}
}

func TestTailoring_LookupAndIsTailored(t *testing.T) {
	tl, err := NewTailoring([]TailoringRule{
		{Framework: "soc2", Control: "CC1.4", Justification: "reason A"},
	})
	if err != nil {
		t.Fatalf("NewTailoring: %v", err)
	}
	if just, ok := tl.Lookup("soc2", "CC1.4"); !ok || just != "reason A" {
		t.Errorf("Lookup hit: got (%q, %v)", just, ok)
	}
	if just, ok := tl.Lookup("soc2", "CC9.9"); ok || just != "" {
		t.Errorf("Lookup miss: got (%q, %v)", just, ok)
	}
	if !tl.IsTailored("soc2", "CC1.4") {
		t.Errorf("IsTailored hit: got false")
	}
	if tl.IsTailored("soc2", "CC9.9") {
		t.Errorf("IsTailored miss: got true")
	}

	var nilTL *Tailoring
	if nilTL.IsTailored("soc2", "CC1.4") {
		t.Errorf("nil Tailoring should report nothing tailored")
	}
	if nilTL.Count() != 0 {
		t.Errorf("nil Tailoring Count should be 0")
	}
}

func TestTailoring_Validate(t *testing.T) {
	reset()
	defer reset()

	// Existing soc2 framework has CC6.1 (verified by reading
	// internal/frameworks/soc2.yaml). Use a known-good + a known-bad
	// rule to exercise both paths in one call.
	tl, err := NewTailoring([]TailoringRule{
		{Framework: "soc2", Control: "CC6.1", Justification: "ok"},
		{Framework: "soc2", Control: "NOPE.999", Justification: "ok"},
		{Framework: "nonexistent-fw", Control: "CC1.1", Justification: "ok"},
	})
	if err != nil {
		t.Fatalf("NewTailoring: %v", err)
	}
	probs := tl.Validate()
	if len(probs) != 2 {
		t.Fatalf("Validate: got %d problems, want 2 (NOPE.999 + nonexistent-fw)", len(probs))
	}
}

func TestControl_HasTag(t *testing.T) {
	c := Control{Tags: []string{"ig1", "REQUIRED"}}
	for _, tag := range []string{"ig1", "IG1", "Ig1", "required", "REQUIRED"} {
		if !c.HasTag(tag) {
			t.Errorf("HasTag(%q) = false, want true (case-insensitive)", tag)
		}
	}
	if c.HasTag("ig2") {
		t.Errorf("HasTag(ig2) = true, want false")
	}
}

func TestFramework_IsThreatModel(t *testing.T) {
	cases := map[string]bool{
		CategoryCompliance:  false,
		CategoryThreatModel: true,
		"":                  false, // empty defaults to compliance
		"unknown":           false,
	}
	for cat, want := range cases {
		fw := &Framework{Category: cat}
		if got := fw.IsThreatModel(); got != want {
			t.Errorf("Category=%q: IsThreatModel = %v, want %v", cat, got, want)
		}
	}
}
