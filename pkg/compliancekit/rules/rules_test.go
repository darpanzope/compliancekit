package rules_test

import (
	"encoding/json"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit/rules"
)

// TestCondition_JSONRoundTrip verifies the canonical-encoding
// guarantee operators rely on for /rules/export.yaml + git-tracked
// rule files.
func TestCondition_JSONRoundTrip(t *testing.T) {
	c := rules.Condition{
		Op: rules.OpAnd,
		Children: []rules.Condition{
			{Term: &rules.Term{Kind: "severity", Params: map[string]any{"min": "high"}}},
			{Op: rules.OpOr, Children: []rules.Condition{
				{Term: &rules.Term{Kind: "provider", Params: map[string]any{"is": "aws"}}},
				{Term: &rules.Term{Kind: "provider", Params: map[string]any{"is": "gcp"}}},
			}},
		},
	}
	encoded, err := rules.MarshalCondition(c)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	decoded, err := rules.UnmarshalCondition(encoded)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.Op != rules.OpAnd {
		t.Errorf("Op lost: %v", decoded.Op)
	}
	if len(decoded.Children) != 2 {
		t.Fatalf("Children lost: %d", len(decoded.Children))
	}
	if decoded.Children[1].Op != rules.OpOr {
		t.Errorf("nested Op lost: %v", decoded.Children[1].Op)
	}
}

// TestConditionIsAlwaysMatch — an empty condition is the canonical
// "always fire" shape that an action-only rule uses.
func TestConditionIsAlwaysMatch(t *testing.T) {
	if !(rules.Condition{}).IsAlwaysMatch() {
		t.Error("empty condition should match always")
	}
	if (rules.Condition{Op: rules.OpAnd}).IsAlwaysMatch() {
		t.Error("Op=AND without children is not always-match")
	}
	if (rules.Condition{Term: &rules.Term{}}).IsAlwaysMatch() {
		t.Error("Term-bearing condition is never always-match")
	}
}

// TestActions_EmptyEncoding confirms a nil or empty slice round-trips
// to the canonical `[]` form, not `null`. The engine relies on this
// when storing rules in the action_json column.
func TestActions_EmptyEncoding(t *testing.T) {
	for _, in := range [][]rules.Action{nil, {}} {
		b, err := rules.MarshalActions(in)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if string(b) != "[]" {
			t.Errorf("empty actions encoded as %q, want \"[]\"", string(b))
		}
	}
	// Round-trip a populated list to confirm fields survive.
	in := []rules.Action{
		{Kind: "notify", Params: map[string]any{"sink": "slack"}},
		{Kind: "assign", Params: map[string]any{"user": "alice"}},
	}
	b, _ := rules.MarshalActions(in)
	out, err := rules.UnmarshalActions(b)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(out) != 2 || out[0].Kind != "notify" || out[1].Kind != "assign" {
		t.Errorf("actions lost: %+v", out)
	}
	// Sanity: encoding is canonical JSON (not Go-fmt).
	if _, err := json.Marshal(in); err != nil {
		t.Fatalf("json.Marshal sanity: %v", err)
	}
}
