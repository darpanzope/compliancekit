package worker

// v1.5.1 phase 6 — schedules cron loop (F4).
//
// The v1.4 Studio shipped /schedules with a form that writes
// rows to the schedules table + computes next_run_at via robfig
// /cron/v3 at insert time. ui/schedules.go:18 admits "the actual
// cron loop (poll schedules table for next_run_at <= now) is a
// future enhancement" — and that loop never landed. Schedules
// counted down on the UI; nothing ever fired.
//
// runCronLoop is the missing producer: every tickEvery seconds
// it SELECTs schedules whose next_run_at has passed + that are
// still enabled, enqueues a scan for each provider list, and
// rolls next_run_at forward via the schedule's own cron expr +
// timezone. The newly-queued scan rows are picked up by the
// existing worker pool + handed to RealRunner (phase 5).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
)

// cronParser matches the 5-field shape ui/schedules.go uses at
// insert time. Operators write "0 6 * * 1" (every Monday 6am)
// in the same syntax the daemon evaluates here.
var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// cronTickEvery is how often the loop polls the schedules table.
// 30 seconds is small enough that a "every-minute" cron schedule
// never drifts more than a minute past its fire time + big enough
// to keep DB churn negligible. A more aggressive operator can
// shorten this in v1.6 via a Pool.Config knob.
const cronTickEvery = 30 * time.Second

// startCronLoop kicks off the schedules-table polling goroutine.
// Returns when ctx is canceled; appends to the pool's WaitGroup
// so Stop() drains it cleanly.
//
// v1.5.1 phase 9 (F9) folds in a waiver-expiry sweep on the
// same tick: a separate counter tracks "every Nth tick run the
// expiry sweep" so the daily-resolution waiver-expiry alerts
// don't churn the inbox.
func (p *Pool) startCronLoop(ctx context.Context) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		t := time.NewTicker(cronTickEvery)
		defer t.Stop()
		// One immediate tick at start so a freshly-booted daemon
		// fires any schedules whose next_run_at already passed
		// during downtime.
		p.fireDueSchedules(ctx)
		p.sweepExpiringWaivers(ctx)
		// Run the waiver sweep once per ~hour (3600/30 = 120 ticks).
		var ticks int
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.fireDueSchedules(ctx)
				ticks++
				if ticks%120 == 0 {
					p.sweepExpiringWaivers(ctx)
				}
			}
		}
	}()
}

// sweepExpiringWaivers SELECTs waivers expiring within 14 days
// or already expired in the last 24h and fires one inbox alert
// per match (de-duped by waiver id stamped into the inbox
// row's href). v1.5.1 F9 inbox-producer #3.
func (p *Pool) sweepExpiringWaivers(ctx context.Context) {
	now := time.Now().UTC()
	soon := now.Add(14 * 24 * time.Hour).Format(time.RFC3339)
	yesterday := now.Add(-24 * time.Hour).Format(time.RFC3339)
	nowStr := now.Format(time.RFC3339)

	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, check_id, resource_id, expires_at FROM waivers
		 WHERE revoked_at IS NULL
		   AND expires_at IS NOT NULL
		   AND expires_at <= %s
		   AND expires_at >= %s`,
		p.ph(1), p.ph(2))
	rows, err := p.store.DB().QueryContext(ctx, q, soon, yesterday)
	if err != nil {
		p.log.Debug("cron: waiver expiry sweep query failed", "err", err)
		return
	}
	defer func() { _ = rows.Close() }()

	type expRow struct {
		id, checkID, resourceID, expiresAt string
	}
	var due []expRow
	for rows.Next() {
		var r expRow
		if err := rows.Scan(&r.id, &r.checkID, &r.resourceID, &r.expiresAt); err != nil {
			continue
		}
		due = append(due, r)
	}
	if err := rows.Close(); err != nil {
		p.log.Debug("cron: waiver expiry sweep close failed", "err", err)
	}

	for _, w := range due {
		// De-dup: skip if an inbox row already references this
		// waiver's href (single alert per waiver per expiry).
		var count int
		_ = p.store.DB().QueryRowContext(ctx,
			fmt.Sprintf(`SELECT COUNT(*) FROM inbox WHERE href = %s`, p.ph(1)),
			"/waivers#"+w.id).Scan(&count)
		if count > 0 {
			continue
		}
		expT, _ := time.Parse(time.RFC3339, w.expiresAt)
		title := fmt.Sprintf("Waiver expiring: %s", w.checkID)
		body := fmt.Sprintf("Waiver for %s / %s expires %s. Renew or let lapse.", w.checkID, w.resourceID, expT.Format("2006-01-02"))
		if expT.Before(now) {
			title = fmt.Sprintf("Waiver expired: %s", w.checkID)
			body = fmt.Sprintf("Waiver for %s / %s expired %s. Matching findings will refire on the next scan.", w.checkID, w.resourceID, expT.Format("2006-01-02"))
		}
		p.notifyInbox(ctx, "", inboxSevWarning, title, body, "/waivers#"+w.id, nowStr)
	}
}

// notifyInbox is the Pool-side variant of RealRunner.notifyInbox
// — duplicated here to avoid an import cycle (worker.Pool can't
// import RealRunner the way RealRunner imports Pool fields).
func (p *Pool) notifyInbox(ctx context.Context, userID, severity, title, body, href, nowStr string) {
	if severity == "" {
		severity = inboxSevInfo
	}
	id := uuid.NewString()
	var userArg any
	if userID != "" {
		userArg = userID
	}
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`INSERT INTO inbox (id, user_id, created_at, severity, title, body, href)
		 VALUES (%s, %s, %s, %s, %s, %s, %s)`,
		p.ph(1), p.ph(2), p.ph(3), p.ph(4), p.ph(5), p.ph(6), p.ph(7))
	if _, err := p.store.DB().ExecContext(ctx, q,
		id, userArg, nowStr, severity, title, body, href); err != nil {
		p.log.Debug("cron: inbox insert failed", "err", err)
	}
}

// fireDueSchedules selects every schedule whose next_run_at <= now
// + enabled = 1, enqueues a scan for each, and rolls next_run_at
// forward. Errors are logged + skipped so a single bad cron expr
// doesn't poison the loop.
func (p *Pool) fireDueSchedules(ctx context.Context) {
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, cron_expr, COALESCE(timezone,'UTC'), providers FROM schedules
		 WHERE enabled = 1 AND next_run_at <= %s`, p.ph(1))
	rows, err := p.store.DB().QueryContext(ctx, q, nowStr)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			p.log.Debug("cron: select due schedules failed", "err", err)
		}
		return
	}
	defer func() { _ = rows.Close() }()

	type dueRow struct {
		id, cronExpr, tz, providersJSON string
	}
	var due []dueRow
	for rows.Next() {
		var r dueRow
		if err := rows.Scan(&r.id, &r.cronExpr, &r.tz, &r.providersJSON); err != nil {
			p.log.Debug("cron: scan due row failed", "err", err)
			continue
		}
		due = append(due, r)
	}
	if err := rows.Err(); err != nil {
		p.log.Debug("cron: iterate due rows failed", "err", err)
	}
	if err := rows.Close(); err != nil {
		p.log.Debug("cron: close due rows failed", "err", err)
	}

	for _, d := range due {
		p.fireOneSchedule(ctx, d.id, d.cronExpr, d.tz, d.providersJSON, now)
	}
}

func (p *Pool) fireOneSchedule(ctx context.Context, schedID, cronExpr, tz, providersJSON string, now time.Time) {
	var providers []string
	if err := json.Unmarshal([]byte(providersJSON), &providers); err != nil {
		p.log.Warn("cron: bad providers json", "schedule", schedID, "err", err)
		return
	}
	if len(providers) == 0 {
		p.log.Debug("cron: schedule has empty providers, skipping", "schedule", schedID)
		_ = p.rollScheduleNextRun(ctx, schedID, "", cronExpr, tz, now)
		return
	}

	scanID, err := p.enqueueScheduledScan(ctx, providers, now)
	if err != nil {
		p.log.Warn("cron: enqueue scan failed", "schedule", schedID, "err", err)
		return
	}
	if err := p.rollScheduleNextRun(ctx, schedID, scanID, cronExpr, tz, now); err != nil {
		p.log.Warn("cron: roll next_run_at failed", "schedule", schedID, "err", err)
	}
	p.log.Info("cron: fired schedule", "schedule", schedID, "scan_id", scanID, "providers", providers)
}

// enqueueScheduledScan INSERTs a scan row matching the shape
// enqueueWizardScanMulti uses on the UI side — same source =
// 'daemon' label so the v1.5 explorer treats them identically.
// v1.6 may add a distinct source = 'schedule' so the /scans
// list can distinguish manual / scheduled / webhook origins.
func (p *Pool) enqueueScheduledScan(ctx context.Context, providers []string, now time.Time) (string, error) {
	js, _ := json.Marshal(providers)
	id := uuid.NewString()
	nowStr := now.Format(time.RFC3339)
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`INSERT INTO scans (id, created_at, source, status, providers_scanned,
		                    frameworks_scanned, score, coverage, total_findings,
		                    actionable_findings)
		 VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		p.ph(1), p.ph(2), p.ph(3), p.ph(4), p.ph(5), p.ph(6), p.ph(7), p.ph(8), p.ph(9), p.ph(10))
	if _, err := p.store.DB().ExecContext(ctx, q,
		id, nowStr, "schedule", "queued", string(js), "[]", 0, 0, 0, 0); err != nil {
		return "", err
	}
	return id, nil
}

// rollScheduleNextRun parses cronExpr, computes the next fire
// time after `now` in the schedule's timezone, and UPDATEs the
// schedules row. last_run_scan_id is set when scanID != "".
func (p *Pool) rollScheduleNextRun(ctx context.Context, schedID, scanID, cronExpr, tz string, now time.Time) error {
	sched, err := cronParser.Parse(cronExpr)
	if err != nil {
		return fmt.Errorf("parse cron %q: %w", cronExpr, err)
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		// Bad timezone falls back to UTC rather than blocking the
		// roll — the schedule keeps firing on UTC.
		p.log.Warn("cron: bad timezone, falling back to UTC", "schedule", schedID, "tz", tz)
		loc = time.UTC
	}
	next := sched.Next(now.In(loc)).UTC().Format(time.RFC3339)
	nowStr := now.UTC().Format(time.RFC3339)

	if scanID != "" {
		q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
			`UPDATE schedules SET last_run_at = %s, last_run_scan_id = %s, next_run_at = %s WHERE id = %s`,
			p.ph(1), p.ph(2), p.ph(3), p.ph(4))
		_, err = p.store.DB().ExecContext(ctx, q, nowStr, scanID, next, schedID)
		return err
	}
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`UPDATE schedules SET next_run_at = %s WHERE id = %s`,
		p.ph(1), p.ph(2))
	_, err = p.store.DB().ExecContext(ctx, q, next, schedID)
	return err
}
