// Package rules is the daemon-side workflow automation engine. It
// owns rule storage (the rules + rule_runs tables from migration
// 0014), evaluation (condition tree + action dispatch), and
// integration with the v1.6 event bus.
//
// The public surface for embedders lives at pkg/compliancekit/rules;
// this package converts to/from those types at the persistence
// boundary so internal evaluation can use richer Go types
// (registered evaluator functions, dispatcher closures) without
// leaking them onto the v1.x SemVer contract.
//
// Engine lifecycle:
//
//	eng := rules.New(store, registry)
//	eng.Start(ctx)        // subscribes to bus.Producer
//	defer eng.Stop()
//
// Per-event evaluation:
//
//	eng.HandleEvent(ctx, "finding.created", payload)
//
// The HandleEvent path is invoked by the v1.6 event-bus subscriber
// (Phase 7 wires that). For now this package only exposes the
// types + storage + registry; phase 1+ layers the condition / action
// implementations + bus integration on top.
package rules

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
	"github.com/darpanzope/compliancekit/pkg/compliancekit/rules"
)

// nowFn is the clock source. Tests pin it for deterministic
// triggered_at + duration_ms values.
var nowFn = func() time.Time { return time.Now().UTC() }

// SetClock overrides the package clock; returns the previous fn.
func SetClock(fn func() time.Time) func() time.Time {
	prev := nowFn
	nowFn = fn
	return prev
}

// Registry holds the named condition + action implementations the
// engine evaluates against. Registration is package-global by
// convention (one daemon, one rule set); tests may construct their
// own Registry to isolate fixtures.
type Registry struct {
	mu         sync.RWMutex
	conditions map[string]ConditionEvaluator
	actions    map[string]ActionDispatcher
}

// NewRegistry constructs an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		conditions: map[string]ConditionEvaluator{},
		actions:    map[string]ActionDispatcher{},
	}
}

// DefaultRegistry is the package-global registry the engine reads
// from by default. internal/rules/conditions + internal/rules/actions
// init() into this — same pattern as the v0.x check registry.
var DefaultRegistry = NewRegistry()

// EvalContext is the payload one rule sees during evaluation. The
// engine builds an EvalContext per trigger event + walks every
// matching rule against it.
type EvalContext struct {
	Trigger   rules.Trigger
	Now       time.Time
	Finding   FindingFacts   // populated for finding.* triggers
	Scan      ScanFacts      // populated for scan.* triggers
	Resource  ResourceFacts  // populated when the event names a resource
	Extras    map[string]any // free-form trigger-specific payload
	Simulated bool           // true under phase 8 simulator
}

// FindingFacts is the slice of a Finding the engine needs to
// evaluate conditions. Kept separate from compliancekit.Finding so
// the engine doesn't have to load the full graph on every event.
type FindingFacts struct {
	Fingerprint  string
	CheckID      string
	Severity     string // "critical"|"high"|...
	Status       string // "pass"|"fail"|"skip"|"error"
	Provider     string
	ResourceID   string
	ResourceType string
	ResourceName string
	Frameworks   []string
	Tags         []string
	FirstSeenAt  time.Time
	LastSeenAt   time.Time
}

// ScanFacts is the slice of a Scan the engine needs.
type ScanFacts struct {
	ID                 string
	Source             string
	Status             string
	Score              int
	Coverage           int
	TotalFindings      int
	ActionableFindings int
	FinishedAt         time.Time
}

// ResourceFacts is the slice of a Resource the engine needs.
type ResourceFacts struct {
	ID       string
	Type     string
	Provider string
	Tags     []string
}

// ConditionEvaluator is the signature every built-in condition
// implements. The bool return is the predicate value; the error
// return surfaces malformed Params so the engine can mark the rule
// as broken in the rule_runs table instead of silently no-matching.
type ConditionEvaluator func(ctx context.Context, params map[string]any, ec *EvalContext) (bool, error)

// ActionResult is what an action returns after dispatch. Outcome
// records human-readable text the audit log + simulator surface.
type ActionResult struct {
	Outcome string         `json:"outcome,omitempty"`
	Error   string         `json:"error,omitempty"`
	Data    map[string]any `json:"data,omitempty"`
}

// ActionDispatcher runs one action. The engine passes the matched
// rule for context (e.g. rule.ID is useful in audit lines) plus the
// EvalContext + the action's Params.
type ActionDispatcher func(ctx context.Context, rule *Rule, params map[string]any, ec *EvalContext) ActionResult

// RegisterCondition installs an evaluator under the given kind.
// Duplicate kinds overwrite (the second wins) — keeps tests simple;
// production wiring goes through init() and so naturally deduplicates.
func (r *Registry) RegisterCondition(kind string, fn ConditionEvaluator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.conditions[kind] = fn
}

// RegisterAction installs a dispatcher under the given kind.
func (r *Registry) RegisterAction(kind string, fn ActionDispatcher) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.actions[kind] = fn
}

// LookupCondition returns the evaluator + true, or nil + false.
func (r *Registry) LookupCondition(kind string) (ConditionEvaluator, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.conditions[kind]
	return fn, ok
}

// LookupAction returns the dispatcher + true, or nil + false.
func (r *Registry) LookupAction(kind string) (ActionDispatcher, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.actions[kind]
	return fn, ok
}

// ConditionKinds returns every registered condition kind, sorted.
// Used by the v1.9 phase 3 UI builder to populate the picker.
func (r *Registry) ConditionKinds() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.conditions))
	for k := range r.conditions {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// ActionKinds returns every registered action kind, sorted.
func (r *Registry) ActionKinds() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.actions))
	for k := range r.actions {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// Rule is the daemon-side representation of a rules.Rule including
// the parsed Condition + Actions. The Repo loads + saves these.
type Rule struct {
	rules.Rule
}

// Repo owns the rules + rule_runs tables.
type Repo struct {
	store *store.Store
}

// NewRepo wires a Repo against the given store.
func NewRepo(s *store.Store) *Repo { return &Repo{store: s} }

// Create persists a new rule. ID is auto-generated when empty.
func (r *Repo) Create(ctx context.Context, in Rule) (Rule, error) {
	if in.Name == "" {
		return Rule{}, errors.New("rules: name required")
	}
	if in.Trigger == "" {
		in.Trigger = rules.TriggerFindingCreated
	}
	if in.Trigger == rules.TriggerCron && in.CronExpr == "" {
		return Rule{}, errors.New("rules: cron trigger requires cron_expr")
	}
	if in.Timezone == "" {
		in.Timezone = "UTC"
	}
	if in.Priority == 0 {
		in.Priority = 100
	}
	if in.ID == "" {
		id, err := newRuleID()
		if err != nil {
			return Rule{}, err
		}
		in.ID = id
	}
	condJSON, err := rules.MarshalCondition(in.Condition)
	if err != nil {
		return Rule{}, fmt.Errorf("marshal condition: %w", err)
	}
	actJSON, err := rules.MarshalActions(in.Actions)
	if err != nil {
		return Rule{}, fmt.Errorf("marshal actions: %w", err)
	}
	now := nowFn().UTC().Format(time.RFC3339)
	in.CreatedAt = nowFn().UTC()
	in.UpdatedAt = in.CreatedAt
	q := "INSERT INTO rules (id, name, description, enabled, priority, trigger, cron_expr, timezone, condition_json, action_json, created_by_user_id, created_at, updated_at) VALUES (" +
		phList(r.store, 13) + ")"
	if _, err := r.store.DB().ExecContext(ctx, q,
		in.ID, in.Name, in.Description, boolInt(in.Enabled), in.Priority,
		string(in.Trigger), nullable(in.CronExpr), in.Timezone,
		string(condJSON), string(actJSON),
		nullable(in.CreatedBy), now, now); err != nil {
		return Rule{}, fmt.Errorf("insert rule: %w", err)
	}
	return in, nil
}

// Update rewrites every mutable column in place.
func (r *Repo) Update(ctx context.Context, in Rule) error {
	if in.ID == "" {
		return errors.New("rules: ID required")
	}
	condJSON, err := rules.MarshalCondition(in.Condition)
	if err != nil {
		return fmt.Errorf("marshal condition: %w", err)
	}
	actJSON, err := rules.MarshalActions(in.Actions)
	if err != nil {
		return fmt.Errorf("marshal actions: %w", err)
	}
	now := nowFn().UTC().Format(time.RFC3339)
	q := "UPDATE rules SET name = " + ph(r.store, 1) +
		", description = " + ph(r.store, 2) +
		", enabled = " + ph(r.store, 3) +
		", priority = " + ph(r.store, 4) +
		", trigger = " + ph(r.store, 5) +
		", cron_expr = " + ph(r.store, 6) +
		", timezone = " + ph(r.store, 7) +
		", condition_json = " + ph(r.store, 8) +
		", action_json = " + ph(r.store, 9) +
		", updated_at = " + ph(r.store, 10) +
		" WHERE id = " + ph(r.store, 11)
	res, err := r.store.DB().ExecContext(ctx, q,
		in.Name, in.Description, boolInt(in.Enabled), in.Priority,
		string(in.Trigger), nullable(in.CronExpr), in.Timezone,
		string(condJSON), string(actJSON), now, in.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Delete removes a rule. Cascade clears the rule_runs trail via FK.
func (r *Repo) Delete(ctx context.Context, id string) error {
	q := "DELETE FROM rules WHERE id = " + ph(r.store, 1)
	res, err := r.store.DB().ExecContext(ctx, q, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ByID loads a single rule by primary key.
func (r *Repo) ByID(ctx context.Context, id string) (Rule, error) {
	q := selectRule + " WHERE id = " + ph(r.store, 1)
	row := r.store.DB().QueryRowContext(ctx, q, id)
	return scanRule(row)
}

// ListByTrigger returns enabled rules with the given trigger, in
// priority order (lowest first). The engine subscribes on bus
// events + walks this list.
func (r *Repo) ListByTrigger(ctx context.Context, trigger rules.Trigger) ([]Rule, error) {
	q := selectRule + " WHERE trigger = " + ph(r.store, 1) +
		" AND enabled = 1 ORDER BY priority ASC, created_at ASC"
	rows, err := r.store.DB().QueryContext(ctx, q, string(trigger))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Rule
	for rows.Next() {
		rl, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rl)
	}
	return out, rows.Err()
}

// All returns every rule (enabled or not) sorted by name. Drives
// the /rules list view.
func (r *Repo) All(ctx context.Context) ([]Rule, error) {
	q := selectRule + " ORDER BY name"
	rows, err := r.store.DB().QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Rule
	for rows.Next() {
		rl, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rl)
	}
	return out, rows.Err()
}

// RecordRun persists one rule_runs row.
type RunRecord struct {
	RuleID       string
	TriggerEvent string
	Fingerprint  string
	Matched      bool
	Actions      []ActionResult
	Simulated    bool
	Duration     time.Duration
}

// RecordRun appends a row to rule_runs.
func (r *Repo) RecordRun(ctx context.Context, rec RunRecord) error {
	id, err := newRunID()
	if err != nil {
		return err
	}
	actJSON, _ := json.Marshal(rec.Actions)
	if len(actJSON) == 0 {
		actJSON = []byte("[]")
	}
	q := "INSERT INTO rule_runs (id, rule_id, triggered_at, trigger_event, fingerprint, matched, actions_json, simulated, duration_ms) VALUES (" +
		phList(r.store, 9) + ")"
	_, err = r.store.DB().ExecContext(ctx, q,
		id, rec.RuleID, nowFn().UTC().Format(time.RFC3339), rec.TriggerEvent,
		nullable(rec.Fingerprint), boolInt(rec.Matched), string(actJSON),
		boolInt(rec.Simulated), rec.Duration.Milliseconds())
	return err
}

// RecentRuns returns the most recent rule_runs entries for a rule.
// Drives the /rules/{id} history pane + the simulator preview.
func (r *Repo) RecentRuns(ctx context.Context, ruleID string, limit int) ([]RunRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	q := `SELECT rule_id, trigger_event, COALESCE(fingerprint,''), matched, actions_json, simulated, duration_ms
	      FROM rule_runs WHERE rule_id = ` + ph(r.store, 1) +
		` ORDER BY triggered_at DESC LIMIT ` + fmt.Sprint(limit)
	rows, err := r.store.DB().QueryContext(ctx, q, ruleID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []RunRecord
	for rows.Next() {
		var (
			rec       RunRecord
			matched   int
			simulated int
			actJSON   string
			durMs     int64
		)
		if err := rows.Scan(&rec.RuleID, &rec.TriggerEvent, &rec.Fingerprint,
			&matched, &actJSON, &simulated, &durMs); err != nil {
			return nil, err
		}
		rec.Matched = matched != 0
		rec.Simulated = simulated != 0
		rec.Duration = time.Duration(durMs) * time.Millisecond
		_ = json.Unmarshal([]byte(actJSON), &rec.Actions)
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ─── helpers ───────────────────────────────────────────────────────────

const selectRule = `SELECT id, name, description, enabled, priority, trigger,
       COALESCE(cron_expr, ''), timezone, condition_json, action_json,
       COALESCE(created_by_user_id, ''), created_at, updated_at
FROM rules`

type rowScanner interface{ Scan(dest ...any) error }

func scanRule(s rowScanner) (Rule, error) {
	var (
		rl                   Rule
		enabled, priority    int
		condJSON, actJSON    string
		trig                 string
		createdAt, updatedAt string
	)
	if err := s.Scan(&rl.ID, &rl.Name, &rl.Description, &enabled, &priority,
		&trig, &rl.CronExpr, &rl.Timezone, &condJSON, &actJSON, &rl.CreatedBy,
		&createdAt, &updatedAt); err != nil {
		return rl, err
	}
	rl.Enabled = enabled != 0
	rl.Priority = priority
	rl.Trigger = rules.Trigger(trig)
	if c, err := rules.UnmarshalCondition([]byte(condJSON)); err == nil {
		rl.Condition = c
	}
	if a, err := rules.UnmarshalActions([]byte(actJSON)); err == nil {
		rl.Actions = a
	}
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		rl.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, updatedAt); err == nil {
		rl.UpdatedAt = t
	}
	return rl, nil
}

func newRuleID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "rule_" + hex.EncodeToString(b[:]), nil
}

func newRunID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "rrun_" + hex.EncodeToString(b[:]), nil
}

func ph(s *store.Store, n int) string {
	if s.Driver() == store.DriverPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func phList(s *store.Store, n int) string {
	out := make([]byte, 0, 4*n)
	for i := 1; i <= n; i++ {
		if i > 1 {
			out = append(out, ',')
		}
		out = append(out, ph(s, i)...)
	}
	return string(out)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func sortStrings(s []string) {
	// Inline insertion sort to avoid the import — the slices we sort
	// have at most ~20 entries (conditions/actions). Stays simple
	// + zero-allocation.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
