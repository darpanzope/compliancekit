// Package rules is the v1.9+ public surface for the workflow
// automation rules engine. The types here describe a rule's shape
// (trigger + condition tree + action list) without committing to any
// particular built-in condition or action — those live under
// internal/rules/ and are loaded by ID at evaluation time.
//
// Embedders compose rules programmatically when they need to express
// their team's compliance ops as code; CLI / UI operators author
// rules through the v1.9 phase 3 builder, which serializes to the
// same shape.
//
// Like every type in pkg/compliancekit, the surface is covered by
// SemVer 2.0 and the api.txt CI gate. Additive changes only inside
// the v1.x line per ADR-014.
package rules

import (
	"encoding/json"
	"time"
)

// Trigger names the event class that fires a rule. The values mirror
// the v1.6 event bus topic set + a "cron" sentinel for scheduled
// rules. The CHECK constraint in migration 0014 enforces the same
// list at the storage layer.
type Trigger string

// Trigger constants — must match the CHECK list in migration 0014.
const (
	TriggerFindingCreated  Trigger = "finding.created"
	TriggerFindingResolved Trigger = "finding.resolved"
	TriggerScanCompleted   Trigger = "scan.completed"
	TriggerWaiverExpired   Trigger = "waiver.expired"
	TriggerCron            Trigger = "cron"
)

// Rule is the operator-authored unit of automation. Each rule
// carries a trigger that selects the firing event, an optional
// cron expression (when Trigger == TriggerCron), a Condition tree
// composed of typed terms, and an ordered Actions list dispatched
// when the conditions match.
//
// Priority orders rule execution within a single event (lowest
// first). Disabled rules survive in the DB but are skipped by the
// engine — useful for staging a change.
type Rule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Enabled     bool      `json:"enabled"`
	Priority    int       `json:"priority"`
	Trigger     Trigger   `json:"trigger"`
	CronExpr    string    `json:"cron_expr,omitempty"`
	Timezone    string    `json:"timezone,omitempty"`
	Condition   Condition `json:"condition"`
	Actions     []Action  `json:"actions"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

// Op is the boolean combinator at a Condition node. AND/OR compose
// child conditions; NONE marks a leaf carrying a typed Term.
type Op string

// Op constants. AND/OR are the only composition operators at v1.9 —
// NOT is achieved via per-condition negate flags on individual terms.
const (
	OpNone Op = ""    // leaf — Term is populated
	OpAnd  Op = "and" // every child must match
	OpOr   Op = "or"  // any child matches
)

// Condition is one node in the condition tree. Op + Children
// describe an internal node; Term describes a leaf. Mutually
// exclusive: an internal node has empty Term; a leaf has empty
// Children and Op == OpNone.
//
// The shape is recursive but goldmark/json.Marshal handle it
// transparently because we keep Children typed as []Condition.
type Condition struct {
	Op       Op          `json:"op,omitempty"`
	Children []Condition `json:"children,omitempty"`
	Term     *Term       `json:"term,omitempty"`
}

// Term is a single typed condition predicate. Kind selects the
// built-in evaluator under internal/rules/conditions/; Params is the
// kind-specific parameter bag (e.g. {"min_severity": "high"} for
// kind="severity"). Negate inverts the result.
//
// Embedders that want to predicate on something outside the
// built-in set can either author a v0.16 Rego policy and reference
// it via kind="rego" or wait for the v1.13 plugin slot.
type Term struct {
	Kind   string         `json:"kind"`
	Params map[string]any `json:"params,omitempty"`
	Negate bool           `json:"negate,omitempty"`
}

// Action is one entry in a rule's action list. Kind selects the
// dispatcher under internal/rules/actions/; Params is the
// kind-specific argument bag. Actions dispatch in slice order; a
// later action sees the mutations the earlier ones made (e.g. an
// assign followed by a notify renders the freshly-set assignee).
type Action struct {
	Kind   string         `json:"kind"`
	Params map[string]any `json:"params,omitempty"`
}

// Matches is a convenience predicate over a serialized Condition.
// Embedders that hold a *Condition can drive evaluation themselves
// by walking the tree; this helper centralizes the empty-tree case
// (treat as "always match" so an action-only rule fires
// unconditionally on every trigger event).
func (c Condition) IsAlwaysMatch() bool {
	return c.Op == OpNone && c.Term == nil
}

// MarshalCondition returns the canonical JSON representation of the
// condition tree. Used by the engine when persisting rules and by
// the simulator when replaying past events.
func MarshalCondition(c Condition) ([]byte, error) {
	return json.Marshal(c)
}

// UnmarshalCondition rebuilds a Condition from its JSON form. The
// engine calls this on every rule load.
func UnmarshalCondition(data []byte) (Condition, error) {
	var c Condition
	if len(data) == 0 {
		return c, nil
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, err
	}
	return c, nil
}

// MarshalActions / UnmarshalActions mirror MarshalCondition for the
// ordered action list. Encoded as a JSON array so empty lists
// round-trip cleanly.
func MarshalActions(a []Action) ([]byte, error) {
	if a == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(a)
}

// UnmarshalActions parses an action list. Empty / nil input returns
// an empty slice (not nil) so iteration code never has to nil-check.
func UnmarshalActions(data []byte) ([]Action, error) {
	if len(data) == 0 {
		return []Action{}, nil
	}
	var out []Action
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []Action{}
	}
	return out, nil
}
