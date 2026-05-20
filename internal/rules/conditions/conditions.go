// Package conditions ships the built-in condition library for the
// v1.9 rules engine. Each condition is one small Go function +
// fixture coverage; init() registers all of them into
// rules.DefaultRegistry so daemon startup carries the full set.
//
// Condition kinds shipped at v1.9.0:
//   - severity        — min/max severity comparison
//   - framework       — match by framework id (e.g. "soc2", "iso27001")
//   - provider        — match by provider id (e.g. "aws")
//   - resource_type   — match by resource.type prefix
//   - resource_tag    — match by tag presence
//   - check_id        — match by check id (exact or prefix)
//   - finding_age     — age threshold in days
//   - drift_delta     — score delta vs. baseline
//   - time_of_day     — within a daily HH:MM window
//   - day_of_week     — set of weekday names
//   - status          — pass/fail/skip/error
//
// Embedders compose these into rules.Condition trees; the engine
// looks each Kind up at evaluation time. Misconfigured params return
// (false, error) so rule_runs records the malformed-rule outcome
// instead of silently no-matching.
package conditions

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/rules"
)

// Register installs every built-in condition into reg. The
// daemon calls Register(rules.DefaultRegistry) from cmd/serve; tests
// install into an isolated registry.
func Register(reg *rules.Registry) {
	reg.RegisterCondition("severity", evalSeverity)
	reg.RegisterCondition("framework", evalFramework)
	reg.RegisterCondition("provider", evalProvider)
	reg.RegisterCondition("resource_type", evalResourceType)
	reg.RegisterCondition("resource_tag", evalResourceTag)
	reg.RegisterCondition("check_id", evalCheckID)
	reg.RegisterCondition("finding_age", evalFindingAge)
	reg.RegisterCondition("drift_delta", evalDriftDelta)
	reg.RegisterCondition("time_of_day", evalTimeOfDay)
	reg.RegisterCondition("day_of_week", evalDayOfWeek)
	reg.RegisterCondition("status", evalStatus)
}

// init wires the built-ins into the package-global default so the
// daemon's import-side-effect carries them. Tests that need an
// isolated registry call Register(reg) explicitly.
func init() { Register(rules.DefaultRegistry) }

// evalSeverity matches when the finding's severity meets a minimum
// or maximum threshold. Params:
//
//	{"min": "high"}   → fires when finding.severity ≥ high
//	{"max": "medium"} → fires when finding.severity ≤ medium
//	{"eq":  "critical"} → exact match
func evalSeverity(_ context.Context, params map[string]any, ec *rules.EvalContext) (bool, error) {
	sev := ec.Finding.Severity
	if minv, ok := stringParam(params, "min"); ok {
		return rules.SeverityAtLeast(sev, minv), nil
	}
	if maxv, ok := stringParam(params, "max"); ok {
		return !rules.SeverityAtLeast(sev, maxv) || sev == maxv, nil
	}
	if eq, ok := stringParam(params, "eq"); ok {
		return sev == eq, nil
	}
	return false, errors.New("severity: needs min, max, or eq")
}

// evalFramework matches when the finding's frameworks slice
// contains the given id. Params: {"id": "soc2"} or {"any": [...]}.
func evalFramework(_ context.Context, params map[string]any, ec *rules.EvalContext) (bool, error) {
	if id, ok := stringParam(params, "id"); ok {
		return stringSliceContains(ec.Finding.Frameworks, id), nil
	}
	if anyOf, ok := stringSliceParam(params, "any"); ok {
		for _, want := range anyOf {
			if stringSliceContains(ec.Finding.Frameworks, want) {
				return true, nil
			}
		}
		return false, nil
	}
	return false, errors.New("framework: needs id or any")
}

// evalProvider matches finding.provider against id or any.
func evalProvider(_ context.Context, params map[string]any, ec *rules.EvalContext) (bool, error) {
	if id, ok := stringParam(params, "id"); ok {
		return ec.Finding.Provider == id, nil
	}
	if anyOf, ok := stringSliceParam(params, "any"); ok {
		for _, want := range anyOf {
			if ec.Finding.Provider == want {
				return true, nil
			}
		}
		return false, nil
	}
	return false, errors.New("provider: needs id or any")
}

// evalResourceType matches finding.resource_type against an exact
// match, prefix, or set. Resource types are dotted ("aws.iam.user"),
// so prefix matches naturally cover service-level rules.
func evalResourceType(_ context.Context, params map[string]any, ec *rules.EvalContext) (bool, error) {
	rt := ec.Finding.ResourceType
	if eq, ok := stringParam(params, "eq"); ok {
		return rt == eq, nil
	}
	if prefix, ok := stringParam(params, "prefix"); ok {
		return strings.HasPrefix(rt, prefix), nil
	}
	if anyOf, ok := stringSliceParam(params, "any"); ok {
		for _, want := range anyOf {
			if rt == want {
				return true, nil
			}
		}
		return false, nil
	}
	return false, errors.New("resource_type: needs eq, prefix, or any")
}

// evalResourceTag returns true when the resource carries every tag
// listed in params.has, or any tag listed in params.any.
func evalResourceTag(_ context.Context, params map[string]any, ec *rules.EvalContext) (bool, error) {
	tags := ec.Resource.Tags
	if has, ok := stringSliceParam(params, "has"); ok {
		for _, want := range has {
			if !stringSliceContains(tags, want) {
				return false, nil
			}
		}
		return true, nil
	}
	if anyOf, ok := stringSliceParam(params, "any"); ok {
		for _, want := range anyOf {
			if stringSliceContains(tags, want) {
				return true, nil
			}
		}
		return false, nil
	}
	return false, errors.New("resource_tag: needs has or any")
}

// evalCheckID matches finding.check_id exact or prefix.
func evalCheckID(_ context.Context, params map[string]any, ec *rules.EvalContext) (bool, error) {
	id := ec.Finding.CheckID
	if eq, ok := stringParam(params, "eq"); ok {
		return id == eq, nil
	}
	if prefix, ok := stringParam(params, "prefix"); ok {
		return strings.HasPrefix(id, prefix), nil
	}
	if anyOf, ok := stringSliceParam(params, "any"); ok {
		for _, want := range anyOf {
			if id == want {
				return true, nil
			}
		}
		return false, nil
	}
	return false, errors.New("check_id: needs eq, prefix, or any")
}

// evalFindingAge fires when (Now - FirstSeenAt) crosses a threshold.
// Params: {"min_days": 30} or {"max_days": 7}.
func evalFindingAge(_ context.Context, params map[string]any, ec *rules.EvalContext) (bool, error) {
	if ec.Finding.FirstSeenAt.IsZero() {
		return false, nil
	}
	age := ec.Now.Sub(ec.Finding.FirstSeenAt)
	if v, ok := intParam(params, "min_days"); ok {
		return age >= time.Duration(v)*24*time.Hour, nil
	}
	if v, ok := intParam(params, "max_days"); ok {
		return age <= time.Duration(v)*24*time.Hour, nil
	}
	return false, errors.New("finding_age: needs min_days or max_days")
}

// evalDriftDelta fires when ec.Scan.Score deviates from a baseline
// score by at least min_drop or max_gain. Operators thread the
// baseline value through ec.Extras["baseline_score"]; absent =
// always-false (no baseline to compare against).
func evalDriftDelta(_ context.Context, params map[string]any, ec *rules.EvalContext) (bool, error) {
	baseline, ok := ec.Extras["baseline_score"].(int)
	if !ok {
		return false, nil
	}
	delta := ec.Scan.Score - baseline
	if v, ok := intParam(params, "min_drop"); ok {
		return delta <= -v, nil
	}
	if v, ok := intParam(params, "max_gain"); ok {
		return delta >= v, nil
	}
	return false, errors.New("drift_delta: needs min_drop or max_gain")
}

// evalTimeOfDay fires when ec.Now (in the rule's timezone, expected
// to be applied by the caller) falls inside [start, end). Params:
// {"start": "09:00", "end": "17:00"}.
func evalTimeOfDay(_ context.Context, params map[string]any, ec *rules.EvalContext) (bool, error) {
	start, ok1 := stringParam(params, "start")
	end, ok2 := stringParam(params, "end")
	if !ok1 || !ok2 {
		return false, errors.New("time_of_day: needs start + end (HH:MM)")
	}
	return rules.SilenceWindow(ec.Now, start, end), nil
}

// evalDayOfWeek fires when ec.Now.Weekday() is in the given set.
// Params: {"days": ["mon", "tue", "wed", "thu", "fri"]}.
func evalDayOfWeek(_ context.Context, params map[string]any, ec *rules.EvalContext) (bool, error) {
	days, ok := stringSliceParam(params, "days")
	if !ok {
		return false, errors.New("day_of_week: needs days []")
	}
	want := strings.ToLower(ec.Now.Weekday().String()[:3])
	for _, d := range days {
		if strings.ToLower(d)[:imin(3, len(d))] == want {
			return true, nil
		}
	}
	return false, nil
}

// evalStatus matches finding.status against eq or any.
func evalStatus(_ context.Context, params map[string]any, ec *rules.EvalContext) (bool, error) {
	if eq, ok := stringParam(params, "eq"); ok {
		return ec.Finding.Status == eq, nil
	}
	if anyOf, ok := stringSliceParam(params, "any"); ok {
		for _, want := range anyOf {
			if ec.Finding.Status == want {
				return true, nil
			}
		}
		return false, nil
	}
	return false, errors.New("status: needs eq or any")
}

// ─── helpers ───────────────────────────────────────────────────────────

func stringParam(p map[string]any, key string) (string, bool) {
	v, ok := p[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func intParam(p map[string]any, key string) (int, bool) {
	v, ok := p[key]
	if !ok {
		return 0, false
	}
	// JSON numbers decode as float64; YAML decodes as int.
	switch n := v.(type) {
	case int:
		return n, true
	case float64:
		return int(n), true
	case int64:
		return int(n), true
	}
	return 0, false
}

func stringSliceParam(p map[string]any, key string) ([]string, bool) {
	v, ok := p[key]
	if !ok {
		return nil, false
	}
	switch s := v.(type) {
	case []string:
		return s, true
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out, true
	}
	return nil, false
}

func stringSliceContains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// imin avoids redefining the Go 1.21+ built-in min().
func imin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Describe returns a one-line operator-visible string for a Term.
// Used by the rules-engine UI to summarize rule conditions in
// list views without re-walking the registry. Lives here (not in
// rules/) so adding a new condition kind is localized.
func Describe(kind string, params map[string]any) string {
	if desc, ok := describeSimple(kind, params); ok {
		return desc
	}
	if desc, ok := describeTime(kind, params); ok {
		return desc
	}
	return kind
}

// describeSimple handles the eq/id/min/prefix style conditions.
func describeSimple(kind string, params map[string]any) (string, bool) {
	switch kind {
	case "severity":
		if v, ok := stringParam(params, "min"); ok {
			return "severity ≥ " + v, true
		}
		if v, ok := stringParam(params, "max"); ok {
			return "severity ≤ " + v, true
		}
		if v, ok := stringParam(params, "eq"); ok {
			return "severity = " + v, true
		}
	case "framework":
		if v, ok := stringParam(params, "id"); ok {
			return "framework = " + v, true
		}
		if v, ok := stringSliceParam(params, "any"); ok {
			return "framework ∈ " + strings.Join(v, ","), true
		}
	case "provider":
		if v, ok := stringParam(params, "id"); ok {
			return "provider = " + v, true
		}
	case "resource_type":
		if v, ok := stringParam(params, "eq"); ok {
			return "resource_type = " + v, true
		}
		if v, ok := stringParam(params, "prefix"); ok {
			return "resource_type prefix = " + v, true
		}
	case "status":
		if v, ok := stringParam(params, "eq"); ok {
			return "status = " + v, true
		}
	}
	return "", false
}

// describeTime handles the time/age/weekday conditions.
func describeTime(kind string, params map[string]any) (string, bool) {
	switch kind {
	case "finding_age":
		if v, ok := intParam(params, "min_days"); ok {
			return fmt.Sprintf("age ≥ %d days", v), true
		}
	case "time_of_day":
		s, _ := stringParam(params, "start")
		e, _ := stringParam(params, "end")
		return "time " + s + "–" + e, true
	case "day_of_week":
		if v, ok := stringSliceParam(params, "days"); ok {
			return "weekday ∈ " + strings.Join(v, ","), true
		}
	}
	return "", false
}
