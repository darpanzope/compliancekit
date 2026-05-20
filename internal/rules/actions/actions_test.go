package actions

import (
	"context"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/rules"
	"github.com/darpanzope/compliancekit/internal/server/collab"
	"github.com/darpanzope/compliancekit/internal/server/comments"
	"github.com/darpanzope/compliancekit/internal/server/store"
	rsdk "github.com/darpanzope/compliancekit/pkg/compliancekit/rules"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.OpenSQLite(context.Background(),
		"file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	if err := s.MigrateUp(context.Background()); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seedUser(t *testing.T, s *store.Store, id, email string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.DB().ExecContext(context.Background(),
		`INSERT INTO users (id, email, display_name, password_hash, is_admin, created_at)
		 VALUES (?, ?, ?, ?, 0, ?)`, id, email, email, "x", now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func fixturesEC() *rules.EvalContext {
	return &rules.EvalContext{
		Now: time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC),
		Finding: rules.FindingFacts{
			Fingerprint:  "fp-aaaaaaaaaaaaaaaaaaaaaaaaa",
			CheckID:      "iam.user.mfa-enabled",
			Severity:     "critical",
			Provider:     "aws",
			ResourceID:   "aws.iam.user.alice",
			ResourceName: "alice",
		},
	}
}

// TestNotifyAction drops an inbox row through the hook.
func TestNotifyAction(t *testing.T) {
	var got struct {
		userID, severity, title, body, href string
	}
	hooks := Hooks{
		NotifyInbox: func(_ context.Context, u, s, t, b, h string) {
			got.userID, got.severity, got.title, got.body, got.href = u, s, t, b, h
		},
	}
	reg := rules.NewRegistry()
	Register(reg, hooks)
	fn, _ := reg.LookupAction("notify")

	rl := &rules.Rule{Rule: rsdk.Rule{ID: "rule1", Name: "test rule"}}
	res := fn(context.Background(), rl, map[string]any{
		"severity": "warning",
		"title":    "Hello",
		"user_id":  "u-1",
	}, fixturesEC())
	if res.Outcome != "ok" {
		t.Errorf("Outcome = %q, want ok", res.Outcome)
	}
	if got.title != "Hello" || got.severity != "warning" || got.userID != "u-1" {
		t.Errorf("hook call lost args: %+v", got)
	}
}

// TestAssignAction sets the finding's assignee.
func TestAssignAction(t *testing.T) {
	s := openTestStore(t)
	seedUser(t, s, "u-target", "target@example.com")
	hooks := Hooks{Assignments: collab.NewAssignments(s)}
	reg := rules.NewRegistry()
	Register(reg, hooks)
	fn, _ := reg.LookupAction("assign")

	ec := fixturesEC()
	res := fn(context.Background(), &rules.Rule{}, map[string]any{"user_id": "u-target"}, ec)
	if res.Outcome != "ok" {
		t.Fatalf("Outcome = %q: %s", res.Outcome, res.Error)
	}
	got, err := hooks.Assignments.Get(context.Background(), ec.Finding.Fingerprint)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AssigneeID != "u-target" {
		t.Errorf("Assignee = %q, want u-target", got.AssigneeID)
	}
}

// TestWaiveAction writes a waivers row.
func TestWaiveAction(t *testing.T) {
	s := openTestStore(t)
	hooks := Hooks{Store: s}
	reg := rules.NewRegistry()
	Register(reg, hooks)
	fn, _ := reg.LookupAction("waive")

	ec := fixturesEC()
	res := fn(context.Background(), &rules.Rule{}, map[string]any{
		"reason":       "auto-waive for known-false-positive control",
		"approver":     "ci",
		"expires_days": 7,
	}, ec)
	if res.Outcome != "ok" {
		t.Fatalf("Outcome = %q: %s", res.Outcome, res.Error)
	}
	var n int
	_ = s.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM waivers WHERE check_id = ?`, ec.Finding.CheckID).Scan(&n)
	if n != 1 {
		t.Errorf("waivers rows = %d, want 1", n)
	}
}

// TestCommentAction posts a comment.
func TestCommentAction(t *testing.T) {
	s := openTestStore(t)
	hooks := Hooks{Comments: comments.NewRepo(s)}
	reg := rules.NewRegistry()
	Register(reg, hooks)
	fn, _ := reg.LookupAction("comment")

	ec := fixturesEC()
	res := fn(context.Background(), &rules.Rule{Rule: rsdk.Rule{Name: "auto-tag"}},
		map[string]any{"body": "**triage** this fired"}, ec)
	if res.Outcome != "ok" {
		t.Fatalf("Outcome = %q: %s", res.Outcome, res.Error)
	}
	var n int
	_ = s.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM comments WHERE finding_fingerprint = ?`, ec.Finding.Fingerprint).Scan(&n)
	if n != 1 {
		t.Errorf("comments rows = %d, want 1", n)
	}
}

// fakeNotifier implements actions.Notifier for tests.
type fakeNotifier struct {
	name       string
	configured bool
	sent       []Notification
	err        error
}

func (f *fakeNotifier) Name() string     { return f.name }
func (f *fakeNotifier) Configured() bool { return f.configured }
func (f *fakeNotifier) Send(_ context.Context, n []Notification) error {
	f.sent = append(f.sent, n...)
	return f.err
}

// TestNotify_SinkRouting verifies the v1.9 phase 7 sink param
// dispatches through the Notifiers map.
func TestNotify_SinkRouting(t *testing.T) {
	slackSink := &fakeNotifier{name: "slack", configured: true}
	pdSink := &fakeNotifier{name: "pagerduty", configured: true}
	hooks := Hooks{
		Notifiers: map[string]Notifier{"slack": slackSink, "pagerduty": pdSink},
	}
	reg := rules.NewRegistry()
	Register(reg, hooks)
	fn, _ := reg.LookupAction("notify")

	rl := &rules.Rule{Rule: rsdk.Rule{ID: "rule1", Name: "crit"}}
	res := fn(context.Background(), rl, map[string]any{
		"sink": "slack", "title": "Hello", "severity": "critical",
	}, fixturesEC())
	if res.Outcome != "ok" {
		t.Fatalf("Outcome = %q: %s", res.Outcome, res.Error)
	}
	if len(slackSink.sent) != 1 {
		t.Errorf("slack sent = %d, want 1", len(slackSink.sent))
	}
	if len(pdSink.sent) != 0 {
		t.Errorf("pd sent = %d, want 0", len(pdSink.sent))
	}

	// Unknown sink → skip.
	res = fn(context.Background(), rl, map[string]any{"sink": "ghost"}, fixturesEC())
	if res.Outcome != "skip" || res.Error == "" {
		t.Errorf("ghost sink should skip with error, got %+v", res)
	}

	// Unconfigured sink → skip.
	hooks.Notifiers["slack"] = &fakeNotifier{name: "slack", configured: false}
	Register(reg, hooks)
	fn, _ = reg.LookupAction("notify")
	res = fn(context.Background(), rl, map[string]any{"sink": "slack"}, fixturesEC())
	if res.Outcome != "skip" {
		t.Errorf("unconfigured slack should skip, got %+v", res)
	}
}

// TestAuditOnlyAction returns "audit-only" without touching anything.
func TestAuditOnlyAction(t *testing.T) {
	reg := rules.NewRegistry()
	Register(reg, Hooks{})
	fn, _ := reg.LookupAction("audit_only")
	res := fn(context.Background(), &rules.Rule{}, nil, fixturesEC())
	if res.Outcome != "audit-only" {
		t.Errorf("Outcome = %q, want audit-only", res.Outcome)
	}
}

func TestDescribe(t *testing.T) {
	cases := []struct {
		kind   string
		params map[string]any
		want   string
	}{
		{"notify", map[string]any{"sink": "slack", "title": "test"}, "notify slack: test"},
		{"assign", map[string]any{"user_id": "u-1"}, "assign → u-1"},
		{"waive", map[string]any{"expires_days": 14}, "waive 14d"},
		{"audit_only", nil, "audit only (no dispatch)"},
		{"unknown", nil, "unknown"},
	}
	for _, c := range cases {
		if got := Describe(c.kind, c.params); got != c.want {
			t.Errorf("Describe(%q) = %q, want %q", c.kind, got, c.want)
		}
	}
}
