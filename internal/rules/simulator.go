package rules

// v1.9 phase 8 — Rule simulator.
//
// The simulator replays a window of historical findings against a
// single rule (or every rule) without dispatching any side effects.
// Records the would-have-fired outcome to rule_runs with
// simulated=1 so operators can audit "if I enable this rule now,
// what would have happened over the past 30 days?"
//
// Implementation:
//   • Iterate findings WHERE created_at IN [start, end]
//   • For each finding, build the EvalContext + invoke
//     engine.WithSimulator().HandleEvent
//   • The simulator engine variant records simulated=1 +
//     suppresses action dispatch (see engine.go:WithSimulator).
//
// Aggregated outcome is returned for the UI's "would fire N times"
// summary; the raw rule_runs rows persist for drilldown.

import (
	"context"
	"errors"
	"fmt"
	"time"

	rsdk "github.com/darpanzope/compliancekit/pkg/compliancekit/rules"
)

// SimulateOptions controls the replay.
type SimulateOptions struct {
	// RuleIDs (optional) restricts the simulation to a subset of
	// rules. Empty means "every rule with trigger=finding.created".
	RuleIDs []string
	// Window is the (start, end) range to replay. Both inclusive.
	Start time.Time
	End   time.Time
	// Trigger names the synthetic event class. Defaults to
	// finding.created which is the most operator-useful target.
	Trigger rsdk.Trigger
	// Limit caps the number of findings replayed; 0 = no cap.
	// Default 10_000 to keep the rule_runs table bounded.
	Limit int
}

// SimulateResult is the per-rule summary returned to the UI.
type SimulateResult struct {
	RuleID             string
	RuleName           string
	FindingsConsidered int
	WouldFire          int
}

// Simulate runs the replay + returns one summary per matched rule.
// The detailed per-fingerprint outcomes land in rule_runs with
// simulated=1; callers can read them via Repo.RecentRuns.
func (e *Engine) Simulate(ctx context.Context, opts SimulateOptions) ([]SimulateResult, error) {
	if e.repo == nil {
		return nil, errors.New("rules: simulator needs repo")
	}
	opts = opts.normalise(nowFn())

	rls, err := e.loadSimulatedRules(ctx, opts)
	if err != nil {
		return nil, err
	}
	if len(rls) == 0 {
		return nil, nil
	}

	results := make(map[string]*SimulateResult, len(rls))
	for _, r := range rls {
		results[r.ID] = &SimulateResult{RuleID: r.ID, RuleName: r.Name}
	}
	if err := e.replayFindings(ctx, opts, results); err != nil {
		return nil, err
	}
	out := make([]SimulateResult, 0, len(results))
	for _, r := range results {
		out = append(out, *r)
	}
	return out, nil
}

// normalise fills in defaults for End/Start/Trigger/Limit.
func (o SimulateOptions) normalise(now time.Time) SimulateOptions {
	if o.End.IsZero() {
		o.End = now
	}
	if o.Start.IsZero() {
		o.Start = o.End.Add(-30 * 24 * time.Hour)
	}
	if o.Trigger == "" {
		o.Trigger = rsdk.TriggerFindingCreated
	}
	if o.Limit <= 0 {
		o.Limit = 10_000
	}
	return o
}

// loadSimulatedRules returns the rule set the simulator will replay
// against, filtered by RuleIDs if provided.
func (e *Engine) loadSimulatedRules(ctx context.Context, opts SimulateOptions) ([]Rule, error) {
	rls, err := e.repo.ListByTrigger(ctx, opts.Trigger)
	if err != nil {
		return nil, err
	}
	if len(opts.RuleIDs) == 0 {
		return rls, nil
	}
	want := map[string]bool{}
	for _, id := range opts.RuleIDs {
		want[id] = true
	}
	filtered := rls[:0]
	for _, r := range rls {
		if want[r.ID] {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}

// replayFindings streams findings from the window + evaluates each
// against the simulator engine, accumulating WouldFire counts into
// results.
func (e *Engine) replayFindings(ctx context.Context, opts SimulateOptions, results map[string]*SimulateResult) error {
	q := `SELECT fingerprint, check_id, severity, status, provider,
	             resource_id, resource_name, resource_type, COALESCE(message,''),
	             first_seen_at, last_seen_at
	      FROM findings
	      WHERE created_at >= ` + ph(e.repo.store, 1) +
		` AND created_at <= ` + ph(e.repo.store, 2) +
		` ORDER BY created_at ASC LIMIT ` + fmt.Sprint(opts.Limit)
	rows, err := e.repo.store.DB().QueryContext(ctx, q,
		opts.Start.UTC().Format(time.RFC3339),
		opts.End.UTC().Format(time.RFC3339))
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	sim := e.WithSimulator()
	for rows.Next() {
		fact, err := scanSimFinding(rows)
		if err != nil {
			return err
		}
		for _, res := range results {
			res.FindingsConsidered++
		}
		matched, err := sim.HandleEvent(ctx, &EvalContext{
			Trigger: opts.Trigger,
			Now:     opts.End,
			Finding: fact,
		})
		if err != nil {
			return err
		}
		for _, m := range matched {
			if r, ok := results[m.ID]; ok {
				r.WouldFire++
			}
		}
	}
	return rows.Err()
}

func scanSimFinding(rows rowScanner) (FindingFacts, error) {
	var (
		fact                         FindingFacts
		firstSeen, lastSeen, message string
	)
	if err := rows.Scan(&fact.Fingerprint, &fact.CheckID, &fact.Severity, &fact.Status,
		&fact.Provider, &fact.ResourceID, &fact.ResourceName, &fact.ResourceType,
		&message, &firstSeen, &lastSeen); err != nil {
		return fact, err
	}
	_ = message
	if t, err := time.Parse(time.RFC3339, firstSeen); err == nil {
		fact.FirstSeenAt = t
	}
	if t, err := time.Parse(time.RFC3339, lastSeen); err == nil {
		fact.LastSeenAt = t
	}
	return fact, nil
}
