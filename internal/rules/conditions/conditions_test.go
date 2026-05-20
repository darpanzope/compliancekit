package conditions

import (
	"context"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/rules"
)

// fixturesEC builds an EvalContext seeded with the canonical
// happy-path values. Each test then mutates the relevant field.
func fixturesEC() *rules.EvalContext {
	return &rules.EvalContext{
		Now: time.Date(2026, 5, 20, 10, 30, 0, 0, time.UTC),
		Finding: rules.FindingFacts{
			Fingerprint:  "fp1",
			CheckID:      "iam.user.mfa-enabled",
			Severity:     "high",
			Status:       "fail",
			Provider:     "aws",
			ResourceType: "aws.iam.user",
			Frameworks:   []string{"soc2", "iso27001"},
			FirstSeenAt:  time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		},
		Resource: rules.ResourceFacts{
			Tags: []string{"prod", "tier:1"},
		},
		Extras: map[string]any{"baseline_score": 80},
		Scan:   rules.ScanFacts{Score: 65},
	}
}

func eval(t *testing.T, kind string, params map[string]any, ec *rules.EvalContext) bool {
	t.Helper()
	reg := rules.NewRegistry()
	Register(reg)
	fn, ok := reg.LookupCondition(kind)
	if !ok {
		t.Fatalf("condition %q not registered", kind)
	}
	got, err := fn(context.Background(), params, ec)
	if err != nil {
		t.Fatalf("eval %s: %v", kind, err)
	}
	return got
}

func TestSeverity(t *testing.T) {
	ec := fixturesEC()
	if !eval(t, "severity", map[string]any{"min": "high"}, ec) {
		t.Error("high >= high should match")
	}
	if eval(t, "severity", map[string]any{"min": "critical"}, ec) {
		t.Error("high >= critical should not match")
	}
	if !eval(t, "severity", map[string]any{"eq": "high"}, ec) {
		t.Error("severity eq high should match")
	}
}

func TestFramework(t *testing.T) {
	ec := fixturesEC()
	if !eval(t, "framework", map[string]any{"id": "soc2"}, ec) {
		t.Error("soc2 should match")
	}
	if eval(t, "framework", map[string]any{"id": "hipaa"}, ec) {
		t.Error("hipaa should not match")
	}
	if !eval(t, "framework", map[string]any{"any": []any{"hipaa", "iso27001"}}, ec) {
		t.Error("any iso27001 should match")
	}
}

func TestProvider(t *testing.T) {
	ec := fixturesEC()
	if !eval(t, "provider", map[string]any{"id": "aws"}, ec) {
		t.Error("aws should match")
	}
	if eval(t, "provider", map[string]any{"id": "gcp"}, ec) {
		t.Error("gcp should not match")
	}
}

func TestResourceType(t *testing.T) {
	ec := fixturesEC()
	if !eval(t, "resource_type", map[string]any{"prefix": "aws.iam"}, ec) {
		t.Error("prefix aws.iam should match aws.iam.user")
	}
	if !eval(t, "resource_type", map[string]any{"eq": "aws.iam.user"}, ec) {
		t.Error("eq aws.iam.user should match")
	}
}

func TestResourceTag(t *testing.T) {
	ec := fixturesEC()
	if !eval(t, "resource_tag", map[string]any{"has": []any{"prod"}}, ec) {
		t.Error("has prod should match")
	}
	if eval(t, "resource_tag", map[string]any{"has": []any{"dev"}}, ec) {
		t.Error("has dev should not match")
	}
}

func TestFindingAge(t *testing.T) {
	ec := fixturesEC()
	// FirstSeenAt 2026-04-01, Now 2026-05-20 → ~49 days
	if !eval(t, "finding_age", map[string]any{"min_days": 30}, ec) {
		t.Error("age 49d >= 30d should match")
	}
	if eval(t, "finding_age", map[string]any{"min_days": 60}, ec) {
		t.Error("age 49d >= 60d should not match")
	}
}

func TestDriftDelta(t *testing.T) {
	ec := fixturesEC()
	// baseline 80, now 65 → drop 15
	if !eval(t, "drift_delta", map[string]any{"min_drop": 10}, ec) {
		t.Error("drop 15 >= 10 should match")
	}
	if eval(t, "drift_delta", map[string]any{"min_drop": 20}, ec) {
		t.Error("drop 15 < 20 should not match")
	}
}

func TestTimeOfDay(t *testing.T) {
	ec := fixturesEC() // Now = 10:30
	if !eval(t, "time_of_day", map[string]any{"start": "09:00", "end": "17:00"}, ec) {
		t.Error("10:30 in 09–17 should match")
	}
	if eval(t, "time_of_day", map[string]any{"start": "18:00", "end": "22:00"}, ec) {
		t.Error("10:30 in 18–22 should not match")
	}
}

func TestDayOfWeek(t *testing.T) {
	ec := fixturesEC() // 2026-05-20 = Wednesday
	if !eval(t, "day_of_week", map[string]any{"days": []any{"wed"}}, ec) {
		t.Error("wed should match")
	}
	if eval(t, "day_of_week", map[string]any{"days": []any{"sat", "sun"}}, ec) {
		t.Error("weekend should not match")
	}
}

func TestStatus(t *testing.T) {
	ec := fixturesEC()
	if !eval(t, "status", map[string]any{"eq": "fail"}, ec) {
		t.Error("fail should match")
	}
	if eval(t, "status", map[string]any{"eq": "pass"}, ec) {
		t.Error("pass should not match")
	}
}

// TestDescribe smoke-checks the Describe helper for each kind.
func TestDescribe(t *testing.T) {
	cases := []struct {
		kind   string
		params map[string]any
		want   string
	}{
		{"severity", map[string]any{"min": "high"}, "severity ≥ high"},
		{"framework", map[string]any{"id": "soc2"}, "framework = soc2"},
		{"provider", map[string]any{"id": "aws"}, "provider = aws"},
		{"resource_type", map[string]any{"prefix": "aws.iam"}, "resource_type prefix = aws.iam"},
		{"finding_age", map[string]any{"min_days": 30}, "age ≥ 30 days"},
		{"day_of_week", map[string]any{"days": []any{"mon", "tue"}}, "weekday ∈ mon,tue"},
		{"unknown_kind", nil, "unknown_kind"},
	}
	for _, c := range cases {
		got := Describe(c.kind, c.params)
		if got != c.want {
			t.Errorf("Describe(%q) = %q, want %q", c.kind, got, c.want)
		}
	}
}
