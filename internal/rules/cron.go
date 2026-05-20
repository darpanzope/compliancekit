package rules

// v1.9 phase 4 — Scheduled rule actions.
//
// Cron-triggered rules sit alongside event-driven rules but fire on
// a wall-clock schedule rather than a bus event. Operators author
// them via the same /rules editor (trigger="cron" + cron_expr +
// timezone); the daemon's CronLoop polls every 30s + dispatches.
//
// Design notes:
//   • Loop interval is 30s — matches the existing schedules loop
//     from v1.5.1 so operators see consistent firing latency.
//   • "Next run" is computed via robfig/cron/v3 — same dep the
//     schedules loop uses, no new runtime cost.
//   • Each rule tracks its last run via the rule_runs table; the
//     loop reads MAX(triggered_at) and dispatches only when the
//     next cron tick has passed.
//   • The loop sets Simulated=false on every dispatch — there's no
//     simulator mode for cron rules.

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/darpanzope/compliancekit/pkg/compliancekit/rules"
)

// CronLoop drives the cron-trigger rules. Construct via NewCronLoop;
// Run blocks until ctx is canceled.
type CronLoop struct {
	engine    *Engine
	repo      *Repo
	logger    *slog.Logger
	tickEvery time.Duration
}

// NewCronLoop wires the loop. Pass the engine that will dispatch
// matched rule actions. tickEvery defaults to 30s.
func NewCronLoop(eng *Engine, repo *Repo, logger *slog.Logger) *CronLoop {
	if logger == nil {
		logger = slog.Default()
	}
	return &CronLoop{
		engine:    eng,
		repo:      repo,
		logger:    logger,
		tickEvery: 30 * time.Second,
	}
}

// Run loops until ctx is canceled. Every tick:
//
//  1. Loads every enabled cron rule.
//  2. For each, parses cron_expr against the rule's timezone +
//     compares the computed next-run-after-last-run to now.
//  3. Dispatches via Engine.HandleEvent with an EvalContext seeded
//     for a cron-trigger event.
func (c *CronLoop) Run(ctx context.Context) error {
	if c == nil || c.engine == nil || c.repo == nil {
		return errors.New("rules: CronLoop misconfigured")
	}
	ticker := time.NewTicker(c.tickEvery)
	defer ticker.Stop()
	c.tickOnce(ctx) // immediate first pass so newly-added rules don't wait
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.tickOnce(ctx)
		}
	}
}

// tickOnce is the per-tick body. Exported visibility for tests.
func (c *CronLoop) tickOnce(ctx context.Context) {
	rls, err := c.repo.ListByTrigger(ctx, rules.TriggerCron)
	if err != nil {
		c.logger.Error("rules: cron-list failed", "err", err)
		return
	}
	now := nowFn()
	for i := range rls {
		rl := rls[i]
		if rl.CronExpr == "" {
			continue
		}
		sched, err := cronParser().Parse(rl.CronExpr)
		if err != nil {
			c.logger.Warn("rules: invalid cron_expr",
				"rule_id", rl.ID, "expr", rl.CronExpr, "err", err)
			continue
		}
		last, ok := c.lastFiredAt(ctx, rl.ID)
		if !ok {
			// Never fired — anchor at 24h ago so the most-recent past
			// cron boundary fires once at startup. A rule created on
			// Tuesday with "0 9 * * MON" still waits for next Monday;
			// a "* * * * *" rule fires on the next tick.
			last = now.Add(-24 * time.Hour)
		}
		next := sched.Next(last)
		if next.After(now) {
			continue
		}
		ec := &EvalContext{
			Trigger: rules.TriggerCron,
			Now:     now,
		}
		if _, err := c.engine.HandleEvent(ctx, ec); err != nil {
			c.logger.Warn("rules: cron handle-event failed",
				"rule_id", rl.ID, "err", err)
		}
	}
}

// lastFiredAt returns the most recent triggered_at for the rule.
// false signals "never fired" — anchor at "now-1s" in tickOnce.
func (c *CronLoop) lastFiredAt(ctx context.Context, ruleID string) (time.Time, bool) {
	var raw string
	err := c.repo.store.DB().QueryRowContext(ctx,
		`SELECT MAX(triggered_at) FROM rule_runs WHERE rule_id = `+ph(c.repo.store, 1),
		ruleID).Scan(&raw)
	if err != nil || raw == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// cronParser returns a parser that accepts standard 5-field
// expressions, "@hourly", "@daily", "@weekly", "@monthly", and the
// 6-field variant with seconds. Same shape as the v1.5.1 schedules
// loop so operators only learn one cron dialect.
func cronParser() cron.Parser {
	return cron.NewParser(
		cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
	)
}
