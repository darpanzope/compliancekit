// Package expiry runs the v1.9 phase 6 waiver-expiry automation
// loop. Every interval the loop scans for waivers whose ExpiresAt
// has passed + flips status to "revoked", fires a waiver.expired
// event onto the rules engine, and emits an inbox row so the
// operator sees the lapse.
//
// Builds on the v1.5.1 waiver-expiry sweep that already fires the
// expiry inbox alert; v1.9 adds the rules-engine trigger so an
// operator can wire "when a waiver expires → re-notify the
// approver + reassign the finding".
package expiry

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/darpanzope/compliancekit/internal/rules"
	"github.com/darpanzope/compliancekit/internal/server/store"
	rsdk "github.com/darpanzope/compliancekit/pkg/compliancekit/rules"
)

// Loop polls the waivers table for expired rows.
type Loop struct {
	engine    *rules.Engine
	store     *store.Store
	logger    *slog.Logger
	tickEvery time.Duration
	notifyFn  func(ctx context.Context, userID, severity, title, body, href string)
}

// New wires the loop. tickEvery defaults to 5 minutes; production
// callers can override for shorter cycles in tests.
func New(eng *rules.Engine, st *store.Store, notify func(context.Context, string, string, string, string, string), logger *slog.Logger) *Loop {
	if logger == nil {
		logger = slog.Default()
	}
	return &Loop{
		engine:    eng,
		store:     st,
		logger:    logger,
		tickEvery: 5 * time.Minute,
		notifyFn:  notify,
	}
}

// Run loops until ctx is canceled.
func (l *Loop) Run(ctx context.Context) error {
	if l == nil || l.store == nil {
		return errors.New("expiry: Loop misconfigured")
	}
	ticker := time.NewTicker(l.tickEvery)
	defer ticker.Stop()
	l.tickOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			l.tickOnce(ctx)
		}
	}
}

// tickOnce is the per-tick body — also the per-test entry point.
func (l *Loop) tickOnce(ctx context.Context) {
	now := time.Now().UTC()
	rows, err := l.store.DB().QueryContext(ctx,
		`SELECT id, check_id, resource_id, COALESCE(expires_at, ''), approver
		 FROM waivers
		 WHERE status = 'active'
		   AND expires_at IS NOT NULL
		   AND expires_at < `+ph(l.store, 1),
		now.Format(time.RFC3339))
	if err != nil {
		l.logger.Warn("expiry: scan failed", "err", err)
		return
	}
	defer func() { _ = rows.Close() }()
	type expired struct {
		id, checkID, resourceID, approver string
	}
	var batch []expired
	for rows.Next() {
		var e expired
		var ignored string
		if err := rows.Scan(&e.id, &e.checkID, &e.resourceID, &ignored, &e.approver); err != nil {
			l.logger.Warn("expiry: scan-row failed", "err", err)
			continue
		}
		batch = append(batch, e)
	}
	for _, e := range batch {
		if _, err := l.store.DB().ExecContext(ctx,
			`UPDATE waivers SET status = 'revoked', revoked_at = `+ph(l.store, 1)+
				` WHERE id = `+ph(l.store, 2),
			now.Format(time.RFC3339), e.id); err != nil {
			l.logger.Warn("expiry: revoke failed", "waiver_id", e.id, "err", err)
			continue
		}
		title := "Waiver expired: " + e.checkID
		body := "On resource " + e.resourceID + ". Original approver: " + e.approver
		href := "/waivers"
		if l.notifyFn != nil {
			l.notifyFn(ctx, "", "warning", title, body, href)
		}
		// Fire waiver.expired on the rules engine so operator-authored
		// rules can react (re-notify, reassign, escalate).
		if l.engine != nil {
			ec := &rules.EvalContext{
				Trigger: rsdk.TriggerWaiverExpired,
				Now:     now,
				Finding: rules.FindingFacts{
					CheckID:    e.checkID,
					ResourceID: e.resourceID,
				},
				Extras: map[string]any{
					"waiver_id": e.id,
					"approver":  e.approver,
				},
			}
			if _, err := l.engine.HandleEvent(ctx, ec); err != nil {
				l.logger.Warn("expiry: engine-handle failed", "waiver_id", e.id, "err", err)
			}
		}
	}
}

func ph(s *store.Store, n int) string {
	if s.Driver() == store.DriverPostgres {
		// minimal — keeps the package store-agnostic
		switch n {
		case 1:
			return "$1"
		case 2:
			return "$2"
		}
	}
	return "?"
}
