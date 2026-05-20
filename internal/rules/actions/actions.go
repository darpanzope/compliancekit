// Package actions ships the built-in action library for the v1.9
// rules engine. Each action is one dispatcher function the engine
// invokes when a rule's conditions match; init() registers them all
// into rules.DefaultRegistry so daemon startup wires the full set.
//
// Action kinds shipped at v1.9.0:
//   - notify      — emit an inbox row + optionally fan out to a v0.17 sink
//   - assign      — set a finding's assignee
//   - waive       — create a waiver (single-approver by default; phase 5
//     adds multi-approver gating)
//   - comment     — post a comment on the finding (often paired with notify)
//   - tag         — add/remove a tag on the finding (carried via metadata)
//   - audit_only  — record the would-have-fired into rule_runs without
//     dispatching any side effect; useful for testing rules
//
// Heavyweight integrations (Jira/Linear/PagerDuty/Slack PostMessage)
// land via the "notify" sink-routing action once the v0.17 sink
// registry is wired through rules.Hooks. The minimal v1.9.0 ships
// the inbox path + the daemon-internal side effects (assign / waive
// / comment / tag); cross-system push is on the v1.9.x deferred
// list per the issue.
package actions

import (
	"context"
	"fmt"
	"strings"

	"github.com/darpanzope/compliancekit/internal/rules"
	"github.com/darpanzope/compliancekit/internal/server/collab"
	"github.com/darpanzope/compliancekit/internal/server/comments"
	"github.com/darpanzope/compliancekit/internal/server/store"
)

// Hooks bundles the daemon-side handles every action dispatcher may
// need. Callers construct a Hooks once at daemon startup + pass it
// into Register. Nil entries are skipped — tests can install a
// partial Hooks and the actions that need an absent handle return
// an Outcome="skip" ActionResult instead of crashing.
type Hooks struct {
	Comments    *comments.Repo
	Assignments *collab.Assignments
	Activities  *collab.Activities
	Store       *store.Store
	NotifyInbox func(ctx context.Context, userID, severity, title, body, href string)

	// Notifiers maps v0.17 sink names (slack/discord/teams/email/
	// webhook/github-pr/jira/linear/pagerduty) to their Notifier
	// instance. v1.9 phase 7 — populating this enables conditional
	// notification routing: the "notify" action's `sink` param
	// selects which sink fires. Nil map = inbox-only path.
	Notifiers map[string]Notifier
}

// Notifier is the minimal slice of internal/notify.Notifier the
// rules engine needs. Kept local to avoid importing internal/notify
// here (which would create a circular dep via the v0.17 helpers).
// The daemon wires its compliancekit-side Notifier implementations
// through Hooks.Notifiers as values satisfying this interface.
type Notifier interface {
	Name() string
	Configured() bool
	Send(ctx context.Context, n []Notification) error
}

// Notification mirrors internal/notify.Notification slimly. Daemon
// wiring converts between the two at the Hooks boundary.
type Notification struct {
	Title       string
	Body        string
	URL         string
	Tags        []string
	Severity    string
	Fingerprint string
}

// Register installs every built-in action into reg using the
// supplied Hooks for the daemon-side side effects.
func Register(reg *rules.Registry, h Hooks) {
	reg.RegisterAction("notify", h.dispatchNotify)
	reg.RegisterAction("assign", h.dispatchAssign)
	reg.RegisterAction("waive", h.dispatchWaive)
	reg.RegisterAction("comment", h.dispatchComment)
	reg.RegisterAction("tag", h.dispatchTag)
	reg.RegisterAction("audit_only", dispatchAuditOnly)
}

// dispatchNotify drops one inbox row per matched finding + (when a
// sink param is provided) fans out to a v0.17 Notifier.
// Params:
//
//	{"severity": "warning", "title": "...", "body": "..."}        — inbox-only
//	{"sink": "slack", "title": "...", "body": "..."}             — Slack only
//	{"sink": "pagerduty", "severity": "critical", ...}           — PD only
//
// When sink is "inbox" or empty the inbox path runs; any other value
// looks up Hooks.Notifiers[sink] + calls Send. Sink-not-configured =
// Outcome="skip" with a descriptive Error so rule_runs surfaces the
// misconfig.
func (h Hooks) dispatchNotify(ctx context.Context, rl *rules.Rule, params map[string]any, ec *rules.EvalContext) rules.ActionResult {
	severity := getString(params, "severity", "info")
	title := getString(params, "title", "Rule fired: "+rl.Name)
	body := getString(params, "body", "")
	if body == "" && ec.Finding.CheckID != "" {
		body = ec.Finding.CheckID + " on " + ec.Finding.ResourceName
	}
	href := getString(params, "href", "")
	if href == "" && ec.Finding.Fingerprint != "" {
		href = "/findings?focus=" + ec.Finding.Fingerprint
	}
	sink := getString(params, "sink", "inbox")
	if sink != "inbox" {
		return h.dispatchSinkNotify(ctx, sink, severity, title, body, href, ec)
	}
	if h.NotifyInbox == nil {
		return rules.ActionResult{Outcome: "skip", Error: "NotifyInbox hook unset"}
	}
	user := getString(params, "user_id", "")
	h.NotifyInbox(ctx, user, severity, title, body, href)
	return rules.ActionResult{
		Outcome: "ok",
		Data: map[string]any{
			"sink":     "inbox",
			"title":    title,
			"severity": severity,
			"user_id":  user,
		},
	}
}

// dispatchSinkNotify looks up the named v0.17 sink + fires Send.
func (h Hooks) dispatchSinkNotify(ctx context.Context, sink, severity, title, body, href string, ec *rules.EvalContext) rules.ActionResult {
	if h.Notifiers == nil {
		return rules.ActionResult{Outcome: "skip", Error: "Notifiers map unset"}
	}
	n, ok := h.Notifiers[sink]
	if !ok {
		return rules.ActionResult{Outcome: "skip", Error: "unknown sink: " + sink}
	}
	if !n.Configured() {
		return rules.ActionResult{Outcome: "skip", Error: sink + " not configured"}
	}
	if err := n.Send(ctx, []Notification{{
		Title:       title,
		Body:        body,
		URL:         href,
		Severity:    severity,
		Fingerprint: ec.Finding.Fingerprint + "|rule",
	}}); err != nil {
		return rules.ActionResult{Outcome: "error", Error: err.Error()}
	}
	return rules.ActionResult{
		Outcome: "ok",
		Data: map[string]any{
			"sink":     sink,
			"title":    title,
			"severity": severity,
		},
	}
}

// dispatchAssign sets the finding's assignee.
// Params: {"user_id": "..."} OR {"team_lead_of": "<team_slug>"}.
func (h Hooks) dispatchAssign(ctx context.Context, _ *rules.Rule, params map[string]any, ec *rules.EvalContext) rules.ActionResult {
	if h.Assignments == nil {
		return rules.ActionResult{Outcome: "skip", Error: "Assignments hook unset"}
	}
	userID := getString(params, "user_id", "")
	if userID == "" {
		return rules.ActionResult{Outcome: "skip", Error: "assign needs user_id"}
	}
	if ec.Finding.Fingerprint == "" {
		return rules.ActionResult{Outcome: "skip", Error: "no fingerprint in event"}
	}
	// assignedByID stays empty so the FK to users(id) becomes NULL —
	// the rules engine is not a user. The activity row below records
	// the engine attribution via ActorSource=engine.
	if _, err := h.Assignments.Set(ctx, ec.Finding.Fingerprint, userID, ""); err != nil {
		return rules.ActionResult{Outcome: "error", Error: err.Error()}
	}
	if h.Activities != nil {
		_, _ = h.Activities.Record(ctx, ec.Finding.Fingerprint, collab.ActivityAssigned, collab.RecordOptions{
			ActorSource: collab.ActorEngine,
			Metadata:    map[string]any{"assignee_user_id": userID, "rule_engine": true},
		})
	}
	return rules.ActionResult{Outcome: "ok", Data: map[string]any{"assignee": userID}}
}

// dispatchWaive creates a waiver row. v1.9 phase 5 will gate this
// behind a multi-approver threshold for severities above a
// configurable line; the v1.9.0 dispatcher writes the row directly
// (single-approver default) so phase 5 is purely additive.
// Params: {"reason": "...", "approver": "...", "expires_days": 30}.
func (h Hooks) dispatchWaive(ctx context.Context, _ *rules.Rule, params map[string]any, ec *rules.EvalContext) rules.ActionResult {
	if h.Store == nil {
		return rules.ActionResult{Outcome: "skip", Error: "Store hook unset"}
	}
	reason := getString(params, "reason", "Rule-engine auto-waiver")
	approver := getString(params, "approver", "rules-engine")
	if len(reason) < 17 {
		return rules.ActionResult{Outcome: "skip", Error: "waive reason must be ≥17 chars"}
	}
	if ec.Finding.CheckID == "" || ec.Finding.ResourceID == "" {
		return rules.ActionResult{Outcome: "skip", Error: "missing check_id or resource_id"}
	}
	expiresDays := getInt(params, "expires_days", 30)
	expiresAt := ec.Now.AddDate(0, 0, expiresDays).UTC().Format("2006-01-02T15:04:05Z07:00")
	now := ec.Now.UTC().Format("2006-01-02T15:04:05Z07:00")
	id := "wv_" + ec.Finding.Fingerprint[:imin(16, len(ec.Finding.Fingerprint))]
	driver := h.Store.Driver()
	q := buildWaiverInsert(driver)
	if _, err := h.Store.DB().ExecContext(ctx, q,
		id, ec.Finding.CheckID, ec.Finding.ResourceID, reason, approver, now, expiresAt); err != nil {
		return rules.ActionResult{Outcome: "error", Error: err.Error()}
	}
	if h.Activities != nil {
		_, _ = h.Activities.Record(ctx, ec.Finding.Fingerprint, collab.ActivityWaiverApplied, collab.RecordOptions{
			ActorSource: collab.ActorEngine,
			Metadata:    map[string]any{"waiver_id": id, "reason": reason, "expires_at": expiresAt},
		})
	}
	return rules.ActionResult{Outcome: "ok", Data: map[string]any{"waiver_id": id, "expires_at": expiresAt}}
}

// dispatchComment posts a comment on the finding. Useful as a
// "this fired" trail or as a paired audit alongside notify.
// Params: {"body": "..."}.
func (h Hooks) dispatchComment(ctx context.Context, rl *rules.Rule, params map[string]any, ec *rules.EvalContext) rules.ActionResult {
	if h.Comments == nil {
		return rules.ActionResult{Outcome: "skip", Error: "Comments hook unset"}
	}
	body := getString(params, "body", "")
	if body == "" {
		body = "Rule **" + rl.Name + "** fired."
	}
	if ec.Finding.Fingerprint == "" {
		return rules.ActionResult{Outcome: "skip", Error: "no fingerprint in event"}
	}
	id, err := h.Comments.Add(ctx, ec.Finding.Fingerprint, "", body, comments.AddOptions{
		Source: comments.SourceUI, // engine == bot; UI sink-name is the closest existing value
	})
	if err != nil {
		return rules.ActionResult{Outcome: "error", Error: err.Error()}
	}
	if h.Activities != nil {
		_, _ = h.Activities.Record(ctx, ec.Finding.Fingerprint, collab.ActivityCommentAdded, collab.RecordOptions{
			ActorSource: collab.ActorEngine,
			Metadata:    map[string]any{"comment_id": id, "rule_id": rl.ID},
		})
	}
	return rules.ActionResult{Outcome: "ok", Data: map[string]any{"comment_id": id}}
}

// dispatchTag mutates the finding's tag set via metadata. The
// engine doesn't reach into the findings table directly — instead
// it records the intent in rule_runs and the v1.9 phase 7 routing
// layer (when shipped) consumes it. For v1.9.0 the action is a
// no-op-but-recorded so operators can author rules that the next
// minor version can lift into real mutations.
func (h Hooks) dispatchTag(_ context.Context, _ *rules.Rule, params map[string]any, ec *rules.EvalContext) rules.ActionResult {
	add := stringSliceFromAny(params["add"])
	rm := stringSliceFromAny(params["remove"])
	return rules.ActionResult{
		Outcome: "recorded",
		Data: map[string]any{
			"add":         add,
			"remove":      rm,
			"fingerprint": ec.Finding.Fingerprint,
		},
	}
}

// dispatchAuditOnly is the explicit "do nothing but record" action,
// used by operators staging a rule + watching what would fire.
func dispatchAuditOnly(_ context.Context, _ *rules.Rule, _ map[string]any, ec *rules.EvalContext) rules.ActionResult {
	return rules.ActionResult{
		Outcome: "audit-only",
		Data:    map[string]any{"fingerprint": ec.Finding.Fingerprint},
	}
}

// ─── helpers ───────────────────────────────────────────────────────────

func getString(p map[string]any, key, dflt string) string {
	if v, ok := p[key].(string); ok {
		return v
	}
	return dflt
}

func getInt(p map[string]any, key string, dflt int) int {
	if v, ok := p[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		}
	}
	return dflt
}

func stringSliceFromAny(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

func imin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// buildWaiverInsert returns a parameter-list-ready INSERT for the
// waivers table. revoked_at + created_by_user_id stay NULL — the
// rules engine isn't a user but the existing schema allows a NULL
// FK to users(id).
func buildWaiverInsert(driver store.Driver) string {
	if driver == store.DriverPostgres {
		return `INSERT INTO waivers (id, check_id, resource_id, reason, approver, created_at, expires_at)
		        VALUES ($1, $2, $3, $4, $5, $6, $7)`
	}
	return `INSERT INTO waivers (id, check_id, resource_id, reason, approver, created_at, expires_at)
	        VALUES (?, ?, ?, ?, ?, ?, ?)`
}

// Describe returns a one-line summary of an action for the list
// view. Mirrors conditions.Describe.
func Describe(kind string, params map[string]any) string {
	switch kind {
	case "notify":
		sink := getString(params, "sink", "inbox")
		title := getString(params, "title", "")
		if title != "" {
			return "notify " + sink + ": " + title
		}
		return "notify " + sink
	case "assign":
		if u := getString(params, "user_id", ""); u != "" {
			return "assign → " + u
		}
		return "assign (unset)"
	case "waive":
		days := getInt(params, "expires_days", 30)
		return fmt.Sprintf("waive %dd", days)
	case "comment":
		body := getString(params, "body", "")
		if body != "" && len(body) > 32 {
			return "comment: " + body[:32] + "…"
		}
		return "comment: " + body
	case "tag":
		add := stringSliceFromAny(params["add"])
		if len(add) > 0 {
			return "tag +" + strings.Join(add, ",")
		}
		return "tag"
	case "audit_only":
		return "audit only (no dispatch)"
	}
	return kind
}
