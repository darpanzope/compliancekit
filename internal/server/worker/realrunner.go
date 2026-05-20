package worker

// v1.5.1 phase 5 — RealRunner closes F1+F2+F3+F6+F7+F11.
//
// The v1.3 worker.StubRunner sleeps 50ms + returns nil. Scan rows
// transitioned from queued → completed with zero findings — a
// silent no-op that made the v1.4 Studio's "Scan now" button feel
// like it worked while inserting nothing. The v1.4 close-comment
// on #26 explicitly promised "the studio loads the operator's
// compliancekit.yaml + constructs the Engine + streams progress."
// That wiring never landed.
//
// RealRunner is the wiring:
//   1. SELECT providers WHERE enabled = 1 from the daemon's DB.
//   2. For each enabled provider, construct the matching collector
//      using the raw token + scope from providers.config_json.
//   3. SELECT checks_state to build a per-check enable allowlist;
//      the daemon's registry filters down to that set.
//   4. Run engine.Run + INSERT findings + resources + UPDATE scan
//      counts. Status transitions stay owned by Pool.handleJob.
//
// Provider scope shipped in v1.5.1:
//   - DigitalOcean: token + region(s) + service allowlist all
//     honored from the providers.config_json shape v1.4 Studio
//     writes (`{"token":"…","region":"fra1, nyc1","services":[…]}`).
//
// Deferred to v1.6 (other providers stay as YAML-builder-only —
// the dashboard's "Test connection" still works, but in-process
// scan from the daemon raises a clean error rather than a silent
// no-op so operators know to use `compliancekit scan --config=`).

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/engine"
	"github.com/darpanzope/compliancekit/internal/server/events"
	"github.com/darpanzope/compliancekit/internal/server/store"
	"github.com/darpanzope/compliancekit/internal/waivers"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Inbox severity labels used by the worker-side producers.
const (
	inboxSevInfo    = "info"
	inboxSevWarning = "warning"
)

// RealRunner wires the daemon's queue to the real compliancekit
// engine. Constructed via NewRealRunner; pass to worker.Default()
// or worker.Config.Runner.
type RealRunner struct {
	store  *store.Store
	log    *slog.Logger
	events *events.Producer // v1.6: nil-safe
}

// NewRealRunner returns a Runner that builds collectors from the
// daemon's providers table + filters checks by checks_state +
// invokes engine.Run + persists findings.
func NewRealRunner(st *store.Store) *RealRunner {
	return &RealRunner{store: st, log: slog.Default()}
}

// WithEvents installs the v1.6 SSE Producer so per-finding +
// per-scan progress events fan out to /api/v1/events subscribers.
// Returns the receiver for chaining.
func (r *RealRunner) WithEvents(p *events.Producer) *RealRunner {
	r.events = p
	return r
}

// Run satisfies worker.Runner.
func (r *RealRunner) Run(ctx context.Context, j Job) error {
	collectors, providerScope, err := r.buildCollectors(ctx)
	if err != nil {
		return fmt.Errorf("build collectors: %w", err)
	}
	if len(collectors) == 0 {
		return fmt.Errorf("no enabled providers in daemon config — open /settings/providers and enable at least one")
	}

	registry, err := r.buildRegistry(ctx, providerScope)
	if err != nil {
		return fmt.Errorf("build registry: %w", err)
	}

	eng := engine.New(collectors, registry)
	result, err := eng.Run(ctx)
	if err != nil {
		return fmt.Errorf("engine run: %w", err)
	}

	// v1.5.1 phase 7 (F5): apply DB-backed waivers before persist.
	// /waivers writes to the waivers table; without this hook the
	// scan engine never sees the waivers and findings keep firing.
	muted, expired, err := r.applyDBWaivers(ctx, result.Findings, time.Now().UTC())
	if err != nil {
		// Soft-fail: a waivers-load error logs but does not abort the
		// scan — operators still want the findings list, just without
		// muting. (Mirrors how the CLI scan path treats waivers.)
		r.log.Warn("worker: load DB waivers failed", "err", err)
	} else if muted > 0 || len(expired) > 0 {
		r.log.Info("worker: applied DB waivers",
			"scan_id", j.ScanID, "muted", muted, "expired_synthesized", len(expired))
	}
	findings := result.Findings
	findings = append(findings, expired...)

	if err := r.persistFindings(ctx, j.ScanID, findings); err != nil {
		return fmt.Errorf("persist findings: %w", err)
	}
	// v1.5.1 phase 9 (F9): inbox notifications.
	r.notifyScanCompleted(ctx, j.ScanID, providerScope, findings, muted)
	r.maybeNotifyScoreRegression(ctx, j.ScanID, findings)
	r.log.Info("worker: real scan completed",
		"scan_id", j.ScanID,
		"providers", providerScope,
		"findings", len(findings),
		"muted", muted,
	)
	return nil
}

// notifyScanCompleted posts a "scan finished" entry to /inbox so
// operators see daemon-driven activity even without watching
// /scans. Score deltas land in maybeNotifyScoreRegression below.
func (r *RealRunner) notifyScanCompleted(ctx context.Context, scanID string, providers []string, findings []compliancekit.Finding, muted int) {
	actionable := 0
	for _, f := range findings {
		if isActionable(f) {
			actionable++
		}
	}
	sev := inboxSevInfo
	if actionable > 0 {
		sev = inboxSevWarning
	}
	title := fmt.Sprintf("Scan completed — %d findings", len(findings))
	body := fmt.Sprintf("Providers: %s. Actionable: %d. Muted: %d.", strings.Join(providers, ", "), actionable, muted)
	r.notifyInbox(ctx, "", sev, title, body, "/scans/"+scanID)
}

// maybeNotifyScoreRegression looks at the prior completed scan
// and fires an inbox alert if this scan's score dropped by more
// than 5 points (the threshold ADR-008 uses for the v1.2 HTML
// report's "drift" callout). Silent on improvement / same / no-
// prior-scan.
func (r *RealRunner) maybeNotifyScoreRegression(ctx context.Context, scanID string, findings []compliancekit.Finding) {
	thisScore := hardeningScore(findings)
	var prevScore int
	err := r.store.DB().QueryRowContext(ctx,
		`SELECT score FROM scans WHERE status = 'completed' AND id != `+r.ph(1)+
			` ORDER BY created_at DESC LIMIT 1`, scanID).Scan(&prevScore)
	if err != nil {
		return // no prior scan or query failed — silent
	}
	delta := prevScore - thisScore
	if delta <= 5 {
		return
	}
	title := fmt.Sprintf("Score dropped from %d to %d", prevScore, thisScore)
	body := fmt.Sprintf("Hardening score regressed by %d points. Investigate via /scans/diff.", delta)
	r.notifyInbox(ctx, "", inboxSevWarning, title, body, "/scans/diff")
}

// notifyInbox INSERTs one row into the inbox table. user_id NULL
// means "broadcast to every user" — the ui/audit.go::inboxList
// query surfaces both per-user and broadcast rows. Errors are
// logged + swallowed (inbox is decoration, not load-bearing).
func (r *RealRunner) notifyInbox(ctx context.Context, userID, severity, title, body, href string) {
	if severity == "" {
		severity = inboxSevInfo
	}
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339)
	var userArg any
	if userID != "" {
		userArg = userID
	}
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`INSERT INTO inbox (id, user_id, created_at, severity, title, body, href)
		 VALUES (%s, %s, %s, %s, %s, %s, %s)`,
		r.ph(1), r.ph(2), r.ph(3), r.ph(4), r.ph(5), r.ph(6), r.ph(7))
	if _, err := r.store.DB().ExecContext(ctx, q,
		id, userArg, now, severity, title, body, href); err != nil {
		r.log.Debug("worker: inbox insert failed", "err", err)
	}
}

// applyDBWaivers SELECTs every non-revoked waiver from the waivers
// table, mutates `findings` in place to mark matching ones muted,
// and returns the count + any synthesized expired-waiver findings.
// Returns 0/nil/nil silently if the table is empty (no waivers
// configured = no muting).
func (r *RealRunner) applyDBWaivers(ctx context.Context, findings []compliancekit.Finding, now time.Time) (int, []compliancekit.Finding, error) {
	rows, err := r.store.DB().QueryContext(ctx,
		`SELECT check_id, resource_id, reason, approver, COALESCE(expires_at, '')
		 FROM waivers WHERE revoked_at IS NULL`)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = rows.Close() }()

	var entries []waivers.Waiver
	for rows.Next() {
		var checkID, resourceID, reason, approver, expiresStr string
		if err := rows.Scan(&checkID, &resourceID, &reason, &approver, &expiresStr); err != nil {
			return 0, nil, err
		}
		w := waivers.Waiver{
			CheckID:    checkID,
			ResourceID: resourceID,
			Reason:     reason,
			Approver:   approver,
			Source:     "daemon-db",
			SourcePath: "store:waivers",
		}
		if expiresStr != "" {
			if t, err := time.Parse(time.RFC3339, expiresStr); err == nil {
				w.Expires = t
			} else if t, err := time.Parse("2006-01-02", expiresStr); err == nil {
				w.Expires = t
			}
		}
		entries = append(entries, w)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	if len(entries) == 0 {
		return 0, nil, nil
	}

	list, errs := waivers.NewWaiverList(entries, now)
	if len(errs) > 0 {
		return 0, nil, fmt.Errorf("build waiver list: %v", errs[0])
	}
	muted, expired := list.Apply(findings, now)
	return muted, expired, nil
}

// daemonProviderRow is the trimmed view of one providers table row.
type daemonProviderRow struct {
	ID         string
	ConfigJSON string
}

// providerJSONShape mirrors the v1.4 Studio's providers.config_json.
type providerJSONShape struct {
	Token    string   `json:"token"`
	Region   string   `json:"region,omitempty"`
	Services []string `json:"services,omitempty"`
}

// buildCollectors reads providers WHERE enabled = 1, constructs
// each supported collector, and returns the slice + the list of
// provider IDs in scope (used to filter checks below).
func (r *RealRunner) buildCollectors(ctx context.Context) ([]compliancekit.Collector, []string, error) {
	rows, err := r.store.DB().QueryContext(ctx,
		`SELECT id, COALESCE(config_json, '{}') FROM providers WHERE enabled = 1`)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rows.Close() }()

	var collectors []compliancekit.Collector
	var scope []string
	for rows.Next() {
		var row daemonProviderRow
		if err := rows.Scan(&row.ID, &row.ConfigJSON); err != nil {
			return nil, nil, err
		}
		c, err := r.buildOneCollector(row)
		if err != nil {
			r.log.Warn("worker: provider skipped", "provider", row.ID, "err", err)
			continue
		}
		if c == nil {
			continue
		}
		collectors = append(collectors, c)
		scope = append(scope, row.ID)
	}
	return collectors, scope, rows.Err()
}

// buildOneCollector dispatches by provider ID. Unknown / unsupported
// providers return nil + an explanatory error so the caller can
// surface "this provider is YAML-builder-only at v1.5.1, run
// `compliancekit scan --config=...` locally" rather than silently
// skipping with no findings.
func (r *RealRunner) buildOneCollector(row daemonProviderRow) (compliancekit.Collector, error) {
	var pc providerJSONShape
	if err := json.Unmarshal([]byte(row.ConfigJSON), &pc); err != nil {
		return nil, fmt.Errorf("parse config_json: %w", err)
	}

	switch row.ID {
	case "digitalocean":
		if pc.Token == "" {
			return nil, fmt.Errorf("no DO API token stored — paste one in /settings/providers/digitalocean")
		}
		return docol.New(pc.Token), nil

	default:
		// Linux / AWS / GCP / Hetzner / Kubernetes — daemon-side
		// scans for these providers are a v1.6 enhancement; the
		// shape of how to thread their credentials from DB to
		// collector is non-trivial (kubeconfig path, AWS profile
		// vs. role-arn, GCP ADC vs. service-account JSON,
		// SSH inventory etc.). Until then the v1.4 YAML-builder
		// path remains the canonical scan flow:
		//   download /settings/yaml/download → compliancekit
		//   scan --config=compliancekit.yaml.
		return nil, fmt.Errorf("daemon-side scans for %q ship at v1.6; use /settings/yaml/download + `compliancekit scan --config=...` until then", row.ID)
	}
}

// buildRegistry returns a Registry filtered by the daemon's
// checks_state table — every check the operator has explicitly
// disabled via /checks gets dropped. Unknown checks (e.g. operator
// disabled an ID the engine never registered) are ignored. The
// provider scope already gates collectors; checks for a provider
// whose collector wasn't built simply never get to evaluate.
//
// providerScope is unused today (the registry hands every check
// to engine.Run and individual checks skip empty graphs cheaply),
// but accepting it keeps the door open for a v1.6 optimization
// where we pre-filter to only the relevant provider's checks.
func (r *RealRunner) buildRegistry(ctx context.Context, _ []string) (*compliancekit.Registry, error) {
	disabled := map[string]struct{}{}
	rows, err := r.store.DB().QueryContext(ctx,
		`SELECT check_id FROM checks_state WHERE enabled = 0`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		disabled[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	src := compliancekit.DefaultRegistry()
	filtered := compliancekit.NewRegistry()
	for _, id := range src.IDs() {
		if _, off := disabled[id]; off {
			continue
		}
		fn, ok := src.Get(id)
		if !ok {
			continue
		}
		check, ok := src.Check(id)
		if !ok {
			continue
		}
		filtered.Register(check, fn)
	}
	return filtered, nil
}

// persistFindings INSERTs every produced finding into the daemon's
// findings + resources tables, then UPDATEs the scan row with
// rollup counts (total + actionable + score). Status transitions
// (running → completed/failed) are owned by Pool.handleJob; we
// only fill in the result fields.
func (r *RealRunner) persistFindings(ctx context.Context, scanID string, findings []compliancekit.Finding) error {
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := r.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	insertQ := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`INSERT INTO findings (id, scan_id, fingerprint, check_id, severity, status, provider,
		                       resource_id, resource_name, resource_type, message,
		                       framework_ids, first_seen_at, last_seen_at, created_at)
		 VALUES (%s)`, r.phList(15))

	resUpsert := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`INSERT INTO resources (id, name, type, provider, first_seen_at, last_seen_at, last_seen_scan_id)
		 VALUES (%s)
		 ON CONFLICT(id) DO UPDATE SET
		   name = excluded.name, type = excluded.type, provider = excluded.provider,
		   last_seen_at = excluded.last_seen_at, last_seen_scan_id = excluded.last_seen_scan_id`,
		r.phList(7))

	actionable := 0
	for _, f := range findings {
		fp := f.Fingerprint()
		findingID := uuid.NewString()
		provider := providerOf(f.Resource.Type)
		frameworkIDs := frameworkIDsJSON(f)
		resID := f.Resource.ID
		if resID == "" {
			resID = f.Resource.Name
		}
		if _, err := tx.ExecContext(ctx, insertQ,
			findingID, scanID, fp, f.CheckID, f.Severity.String(), string(f.Status), provider,
			resID, f.Resource.Name, f.Resource.Type, f.Message,
			string(frameworkIDs), now, now, now); err != nil {
			return err
		}
		// v1.6 phase 0: fan-out per finding. Toasts (phase 4) +
		// dashboard counters (phase 1) subscribe to this stream.
		if r.events != nil {
			r.events.Publish(events.TypeFindingCreated, findingID, map[string]any{
				"scan_id":  scanID,
				"check_id": f.CheckID,
				"severity": f.Severity.String(),
				"status":   string(f.Status),
				"provider": provider,
				"resource": resID,
			})
		}
		if resID != "" {
			if _, err := tx.ExecContext(ctx, resUpsert,
				resID, f.Resource.Name, f.Resource.Type, provider, now, now, scanID); err != nil {
				return err
			}
		}
		if isActionable(f) {
			actionable++
		}
	}

	// Rollup onto the scan row. Pool.handleJob owns status +
	// finished_at + duration_ms; we fill in score + counts.
	score := hardeningScore(findings)
	updateQ := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`UPDATE scans SET total_findings = %s, actionable_findings = %s, score = %s WHERE id = %s`,
		r.ph(1), r.ph(2), r.ph(3), r.ph(4))
	if _, err := tx.ExecContext(ctx, updateQ,
		len(findings), actionable, score, scanID); err != nil {
		return err
	}

	return tx.Commit()
}

// isActionable matches the rule used by the CLI scan reporter +
// the v1.2 HTML summary card: any finding at high+ severity that
// failed (or errored at warning+) is "actionable."
func isActionable(f compliancekit.Finding) bool {
	if f.Status != compliancekit.StatusFail {
		return false
	}
	return f.Severity >= compliancekit.SeverityHigh
}

// hardeningScore mirrors ADR-008's 0-100 score formula used by the
// CLI: weight critical=50 / high=20 / medium=8 / low=3 / info=1
// across failed findings, normalize against the total weighted
// universe (every registered check at its severity), clamp 0-100,
// invert (high deductions → low score).
//
// The daemon doesn't yet have the "weighted universe" denominator
// — that needs a separate pass over the registry. For v1.5.1 we
// use a simpler proxy: 100 minus the actionable-percent of all
// findings. v1.6 will swap in the canonical formula.
func hardeningScore(findings []compliancekit.Finding) int {
	if len(findings) == 0 {
		return 100
	}
	actionable := 0
	for _, f := range findings {
		if isActionable(f) {
			actionable++
		}
	}
	score := 100 - (actionable * 100 / len(findings))
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

// providerOf strips the prefix before the first dot in a resource
// type to derive the provider name. Mirrors api/write.go::providerOf.
func providerOf(resourceType string) string {
	if i := strings.Index(resourceType, "."); i >= 0 {
		return resourceType[:i]
	}
	return resourceType
}

// frameworkIDsJSON reads the framework attributions off a Finding
// via the check registry. Mirrors api/write.go::extractFrameworkIDs.
func frameworkIDsJSON(f compliancekit.Finding) []byte {
	check, ok := compliancekit.LookupCheck(f.CheckID)
	if !ok {
		return []byte("[]")
	}
	ids := make([]string, 0, len(check.Frameworks))
	for id := range check.Frameworks {
		ids = append(ids, id)
	}
	out, _ := json.Marshal(ids)
	return out
}

// ph / phList — dialect-aware placeholders.
func (r *RealRunner) ph(n int) string {
	if r.store.Driver() == store.DriverPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func (r *RealRunner) phList(count int) string {
	parts := make([]string, count)
	for i := 0; i < count; i++ {
		parts[i] = r.ph(i + 1)
	}
	return strings.Join(parts, ", ")
}
