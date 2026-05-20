package rules

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/darpanzope/compliancekit/pkg/compliancekit/rules"
)

// Engine evaluates rules against incoming events. Construct via New
// + Start; HandleEvent is the single entry point for upstream
// event-bus subscribers.
type Engine struct {
	repo     *Repo
	reg      *Registry
	simulate bool // when true, recorded outcomes are tagged simulated=1
}

// New builds an Engine over the given repo + registry. Pass
// DefaultRegistry in production wiring.
func New(repo *Repo, reg *Registry) *Engine {
	if reg == nil {
		reg = DefaultRegistry
	}
	return &Engine{repo: repo, reg: reg}
}

// WithSimulator returns a sibling engine that records every rule
// outcome with simulated=1 + suppresses every action dispatch. Used
// by the v1.9 phase 8 simulator.
func (e *Engine) WithSimulator() *Engine {
	clone := *e
	clone.simulate = true
	return &clone
}

// HandleEvent walks every enabled rule with the matching trigger
// and evaluates it against the EvalContext. Each rule's outcome is
// persisted via Repo.RecordRun.
//
// Returns the slice of matched rules (whether their actions
// succeeded or not) so callers can correlate the event with the
// downstream effects.
func (e *Engine) HandleEvent(ctx context.Context, ec *EvalContext) ([]Rule, error) {
	if ec == nil {
		return nil, errors.New("rules: nil EvalContext")
	}
	if ec.Now.IsZero() {
		ec.Now = nowFn()
	}
	if e.simulate {
		ec.Simulated = true
	}
	matchedRules, err := e.repo.ListByTrigger(ctx, ec.Trigger)
	if err != nil {
		return nil, err
	}
	out := make([]Rule, 0, len(matchedRules))
	for i := range matchedRules {
		rl := matchedRules[i]
		started := nowFn()
		matched, evalErr := e.evaluateCondition(ctx, rl.Condition, ec)
		// Even on evaluator error we record the run so the operator
		// sees a broken rule in the history pane.
		var actionResults []ActionResult
		if matched && evalErr == nil {
			actionResults = e.dispatchActions(ctx, &rl, ec)
		}
		_ = e.repo.RecordRun(ctx, RunRecord{
			RuleID:       rl.ID,
			TriggerEvent: string(ec.Trigger),
			Fingerprint:  ec.Finding.Fingerprint,
			Matched:      matched,
			Actions:      actionResults,
			Simulated:    e.simulate,
			Duration:     nowFn().Sub(started),
		})
		if matched {
			out = append(out, rl)
		}
		_ = evalErr // recorded shape only — operator sees it via UI
	}
	return out, nil
}

// evaluateCondition walks the recursive condition tree against the
// EvalContext. Leaf nodes dispatch to the registered evaluator;
// internal nodes combine results via AND/OR.
//
// An empty Condition (Op == OpNone, Term == nil) is "always match"
// per the docstring on rules.Condition.IsAlwaysMatch.
func (e *Engine) evaluateCondition(ctx context.Context, c rules.Condition, ec *EvalContext) (bool, error) {
	if c.IsAlwaysMatch() {
		return true, nil
	}
	if c.Term != nil {
		return e.evaluateTerm(ctx, *c.Term, ec)
	}
	switch c.Op {
	case rules.OpAnd:
		for _, child := range c.Children {
			ok, err := e.evaluateCondition(ctx, child, ec)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	case rules.OpOr:
		for _, child := range c.Children {
			ok, err := e.evaluateCondition(ctx, child, ec)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}
	return false, fmt.Errorf("rules: unsupported op %q", c.Op)
}

// evaluateTerm looks up the kind in the registry + invokes the
// evaluator. An unknown kind fails the predicate; a runtime error
// from the evaluator surfaces to the caller.
func (e *Engine) evaluateTerm(ctx context.Context, t rules.Term, ec *EvalContext) (bool, error) {
	fn, ok := e.reg.LookupCondition(t.Kind)
	if !ok {
		return false, fmt.Errorf("rules: unknown condition kind %q", t.Kind)
	}
	got, err := fn(ctx, t.Params, ec)
	if err != nil {
		return false, err
	}
	if t.Negate {
		got = !got
	}
	return got, nil
}

// dispatchActions runs every action in order. The slice of
// ActionResult travels into the rule_runs row so the operator can
// correlate "rule fired" with "what it did."
func (e *Engine) dispatchActions(ctx context.Context, rl *Rule, ec *EvalContext) []ActionResult {
	if len(rl.Actions) == 0 {
		return nil
	}
	out := make([]ActionResult, 0, len(rl.Actions))
	for _, a := range rl.Actions {
		fn, ok := e.reg.LookupAction(a.Kind)
		if !ok {
			out = append(out, ActionResult{
				Outcome: "skip",
				Error:   "unknown action kind: " + a.Kind,
			})
			continue
		}
		if e.simulate {
			out = append(out, ActionResult{
				Outcome: "would-fire",
				Data:    map[string]any{"kind": a.Kind},
			})
			continue
		}
		out = append(out, fn(ctx, rl, a.Params, ec))
	}
	return out
}

// ─── helpers ───────────────────────────────────────────────────────────

// Severity rank used by built-in conditions. Exposed so phase 1
// condition implementations can compare without re-deriving.
var severityRank = map[string]int{
	"info":     1,
	"low":      2,
	"medium":   3,
	"high":     4,
	"critical": 5,
}

// SeverityAtLeast returns true when have >= want using the canonical
// severity ranking. Unknown severity strings rank 0 (never reaches a
// real threshold).
func SeverityAtLeast(have, want string) bool {
	return severityRank[have] >= severityRank[want]
}

// SilenceWindow is a small helper for time-of-day style conditions.
// startHHMM / endHHMM are "HH:MM" strings. now is compared against
// the local time in the rule's timezone, which the caller is
// expected to have already loaded.
func SilenceWindow(now time.Time, startHHMM, endHHMM string) bool {
	hStart, mStart, ok1 := parseHHMM(startHHMM)
	hEnd, mEnd, ok2 := parseHHMM(endHHMM)
	if !ok1 || !ok2 {
		return false
	}
	h, m := now.Hour(), now.Minute()
	minsNow := h*60 + m
	minsStart := hStart*60 + mStart
	minsEnd := hEnd*60 + mEnd
	if minsStart == minsEnd {
		return false
	}
	if minsStart < minsEnd {
		return minsNow >= minsStart && minsNow < minsEnd
	}
	// Wraps midnight (e.g. 22:00 → 06:00).
	return minsNow >= minsStart || minsNow < minsEnd
}

func parseHHMM(s string) (h, m int, ok bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, 0, false
	}
	h = int(s[0]-'0')*10 + int(s[1]-'0')
	m = int(s[3]-'0')*10 + int(s[4]-'0')
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}
