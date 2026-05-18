package policy

import (
	"context"
	"sort"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func builtinFixtureGraph() *compliancekit.ResourceGraph {
	g := compliancekit.NewResourceGraph()
	// Tagged "prod", not public.
	g.Add(compliancekit.Resource{
		ID:       "test.x.prod-only",
		Type:     "test.x",
		Name:     "prod-only",
		Provider: "test",
		Tags:     []string{"prod"},
		Attributes: map[string]any{
			"public":     false,
			"encryption": "AES256",
		},
	})
	// Public + has prod tag + AES256.
	g.Add(compliancekit.Resource{
		ID:       "test.x.both",
		Type:     "test.x",
		Name:     "both",
		Provider: "test",
		Tags:     []string{"prod"},
		Attributes: map[string]any{
			"public":     true,
			"encryption": "AES256",
		},
	})
	// Public, no prod tag, no encryption attr.
	g.Add(compliancekit.Resource{
		ID:       "test.x.public-only",
		Type:     "test.x",
		Name:     "public-only",
		Provider: "test",
		Tags:     []string{"staging"},
		Attributes: map[string]any{
			"public": true,
		},
	})
	return g
}

// TestBuiltins_ResolveAndEval verifies that each built-in is
// registered (no "unknown function" error at compile) and produces
// the right finding shape against the fixture graph.
func TestBuiltins_ResolveAndEval(t *testing.T) {
	m, err := LoadFile(context.Background(), "testdata/builtins.rego")
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	findings, err := m.Evaluate(context.Background(), builtinFixtureGraph())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// Sort for stable comparison — Rego list order is set order.
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })

	// Expected:
	//   test.x.both       — matches has_tag AND attr_bool=public
	//   test.x.prod-only  — matches has_tag only
	//   test.x.public-only — matches attr_bool=public only
	// So both "both" and "prod-only" hit the tag rule; "both" and
	// "public-only" hit the attr rule. test.x.both should produce
	// TWO findings (one per rule).
	if len(findings) != 4 {
		t.Fatalf("findings = %d, want 4 (2 tag matches + 2 attr matches)\n%+v", len(findings), findings)
	}

	bySeverity := map[string][]compliancekit.Finding{}
	for _, f := range findings {
		bySeverity[f.Severity.String()] = append(bySeverity[f.Severity.String()], f)
	}
	// CVSS 8.4 → high (per implCVSSBand). The two attr-rule findings
	// should override the rule-level medium with high.
	if len(bySeverity["high"]) != 2 {
		t.Errorf("attr-rule findings should be promoted to high via cvss_band(8.4), got %+v", bySeverity)
	}
	// Tag-rule findings should stay medium (rule-level default).
	if len(bySeverity["medium"]) != 2 {
		t.Errorf("tag-rule findings should remain medium, got %+v", bySeverity)
	}
}

// TestBuiltin_HasTag_MissingTagField returns false instead of
// erroring when a resource has no tags slice at all.
func TestBuiltin_HasTag_MissingTagField(t *testing.T) {
	body := `package x
metadata := {"id":"x","title":"x","description":"x","severity":"low","provider":"test"}
findings := [f |
  r := input.resources[_]
  compliancekit.has_tag(r, "prod")
  f := {"resource_id": r.id, "status": "fail"}
]
`
	m, err := Compile(context.Background(), "ad-hoc.rego", body)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	g := compliancekit.NewResourceGraph()
	g.Add(compliancekit.Resource{ID: "no-tags", Type: "test", Provider: "test"}) // no Tags field
	findings, err := m.Evaluate(context.Background(), g)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("missing tags should not match has_tag; got %+v", findings)
	}
}

// TestBuiltin_AttrBool_FalseWhenMissing returns false (not error)
// when the attribute key is absent.
func TestBuiltin_AttrBool_FalseWhenMissing(t *testing.T) {
	body := `package x
metadata := {"id":"x","title":"x","description":"x","severity":"low","provider":"test"}
findings := [f |
  r := input.resources[_]
  compliancekit.attr_bool(r, "missing_key") == true
  f := {"resource_id": r.id, "status": "fail"}
]
`
	m, err := Compile(context.Background(), "ad-hoc.rego", body)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	g := compliancekit.NewResourceGraph()
	g.Add(compliancekit.Resource{ID: "no-attrs", Type: "test", Provider: "test"})
	findings, err := m.Evaluate(context.Background(), g)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("attr_bool of missing key should be false; got %+v", findings)
	}
}

// TestBuiltin_CVSSBand spans every band.
func TestBuiltin_CVSSBand(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{9.5, "critical"},
		{9.0, "critical"},
		{8.9, "high"},
		{7.0, "high"},
		{6.9, "medium"},
		{4.0, "medium"},
		{3.9, "low"},
		{0.1, "low"},
		{0.0, "info"},
	}
	for _, c := range cases {
		body := `package x
metadata := {"id":"x","title":"x","description":"x","severity":"low","provider":"test"}
sev := compliancekit.cvss_band(` + sprintFloat(c.score) + `)
findings := [{"resource_id": "fixed", "status": "fail", "severity": sev}]
`
		m, err := Compile(context.Background(), "ad-hoc.rego", body)
		if err != nil {
			t.Errorf("score=%v Compile: %v", c.score, err)
			continue
		}
		g := compliancekit.NewResourceGraph()
		findings, err := m.Evaluate(context.Background(), g)
		if err != nil {
			t.Errorf("score=%v Evaluate: %v", c.score, err)
			continue
		}
		if len(findings) != 1 {
			t.Errorf("score=%v findings = %d", c.score, len(findings))
			continue
		}
		if findings[0].Severity.String() != c.want {
			t.Errorf("cvss_band(%v) → %q, want %q", c.score, findings[0].Severity, c.want)
		}
	}
}

// sprintFloat avoids a strconv import — keeps the test file's import
// graph minimal.
func sprintFloat(f float64) string {
	switch {
	case f == 0:
		return "0"
	case f == float64(int(f)):
		return formatInt(int(f))
	}
	// Two-decimal precision is enough for CVSS scores (X.Y).
	return formatFloat2(f)
}

func formatInt(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func formatFloat2(f float64) string {
	whole := int(f)
	frac := int((f - float64(whole)) * 10) // single-decimal precision
	return formatInt(whole) + "." + formatInt(frac)
}
