package notify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// stubSink is a minimal Notifier used to exercise the registry +
// dispatcher behavior without hitting the network.
type stubSink struct {
	name       string
	configured bool
	threshold  compliancekit.Severity
	received   []Notification
	sendErr    error
	sendResult Result
}

func (s *stubSink) Name() string                      { return s.name }
func (s *stubSink) Configured() bool                  { return s.configured }
func (s *stubSink) Threshold() compliancekit.Severity { return s.threshold }
func (s *stubSink) Send(_ context.Context, n []Notification) (Result, error) {
	s.received = append(s.received, n...)
	return s.sendResult, s.sendErr
}

func sampleFinding(id, severity string) compliancekit.Finding {
	sev, _ := compliancekit.ParseSeverity(severity)
	return compliancekit.Finding{
		CheckID:  id,
		Status:   compliancekit.StatusFail,
		Severity: sev,
		Resource: compliancekit.ResourceRef{
			ID:       "aws.s3.bucket." + id,
			Name:     id,
			Type:     "aws.s3.bucket",
			Provider: "aws",
			Region:   "us-east-1",
		},
		Message: "bucket " + id + " is non-compliant",
		Tags:    []string{"s3", "data-exposure"},
	}
}

func TestRegistry_RegisterAndLookup(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubSink{name: "slack", configured: true})
	r.Register(&stubSink{name: "discord", configured: true})

	if _, ok := r.Lookup("slack"); !ok {
		t.Errorf("Lookup(slack) failed")
	}
	if _, ok := r.Lookup("nonexistent"); ok {
		t.Errorf("Lookup(nonexistent) should fail")
	}
	if names := r.Names(); len(names) != 2 || names[0] != "discord" || names[1] != "slack" {
		t.Errorf("Names = %v, want sorted [discord slack]", names)
	}
}

func TestRegistry_DuplicatePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("duplicate Register should panic")
		}
	}()
	r := NewRegistry()
	r.Register(&stubSink{name: "dup"})
	r.Register(&stubSink{name: "dup"})
}

func TestBuildNotifications_FiltersNonActionable(t *testing.T) {
	findings := []compliancekit.Finding{
		sampleFinding("fail-one", "high"),
		{CheckID: "passing", Status: compliancekit.StatusPass, Severity: compliancekit.SeverityLow}, // filtered
		sampleFinding("fail-two", "critical"),
	}
	got := BuildNotifications(findings, BuildOptions{})
	if len(got) != 2 {
		t.Fatalf("got %d notifications, want 2 (passes filtered)", len(got))
	}
	seen := map[string]bool{}
	for _, n := range got {
		seen[n.Finding.CheckID] = true
	}
	if !seen["fail-one"] || !seen["fail-two"] {
		t.Errorf("expected fail-one + fail-two in output; got %v", seen)
	}
	if seen["passing"] {
		t.Errorf("passing finding leaked through actionable gate")
	}
}

func TestBuildNotifications_DefaultRendering(t *testing.T) {
	n := BuildNotifications([]compliancekit.Finding{sampleFinding("aws-s3-public-access-block", "critical")}, BuildOptions{
		URLPrefix: "https://compliance.example.com",
		Project:   "acme-prod",
	})[0]

	if !strings.Contains(n.Title, "[CRITICAL]") {
		t.Errorf("title missing severity prefix: %q", n.Title)
	}
	if !strings.Contains(n.Title, "aws-s3-public-access-block") {
		t.Errorf("title missing CheckID: %q", n.Title)
	}
	if !strings.Contains(n.Body, "Severity:") || !strings.Contains(n.Body, "critical") {
		t.Errorf("body missing severity detail: %q", n.Body)
	}
	if !strings.Contains(n.Body, "Project:** acme-prod") {
		t.Errorf("body missing project: %q", n.Body)
	}
	if n.URL == "" || !strings.Contains(n.URL, "https://compliance.example.com/findings/") {
		t.Errorf("URL missing or wrong shape: %q", n.URL)
	}
	if n.Fingerprint == "" {
		t.Errorf("Fingerprint not populated")
	}
}

func TestDispatch_SeverityGate(t *testing.T) {
	// Three notifications across severities; two sinks with different
	// thresholds. Verify each sink receives only what passes its gate.
	notifications := BuildNotifications([]compliancekit.Finding{
		sampleFinding("low-one", "low"),
		sampleFinding("medium-one", "medium"),
		sampleFinding("critical-one", "critical"),
	}, BuildOptions{})

	slack := &stubSink{name: "slack", configured: true, threshold: compliancekit.SeverityMedium}
	pager := &stubSink{name: "pager", configured: true, threshold: compliancekit.SeverityCritical}

	r := NewRegistry()
	r.Register(slack)
	r.Register(pager)

	res, errs := Dispatch(context.Background(), r, notifications)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(slack.received) != 2 {
		t.Errorf("slack received %d (want 2: medium + critical)", len(slack.received))
	}
	if len(pager.received) != 1 {
		t.Errorf("pager received %d (want 1: critical-only)", len(pager.received))
	}
	_ = res
}

func TestDispatch_SkipsUnconfiguredSinks(t *testing.T) {
	notifications := BuildNotifications([]compliancekit.Finding{sampleFinding("x", "critical")}, BuildOptions{})

	off := &stubSink{name: "off", configured: false}
	on := &stubSink{name: "on", configured: true, threshold: compliancekit.SeverityInfo}

	r := NewRegistry()
	r.Register(off)
	r.Register(on)

	_, errs := Dispatch(context.Background(), r, notifications)
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(off.received) != 0 {
		t.Errorf("unconfigured sink should not be called")
	}
	if len(on.received) != 1 {
		t.Errorf("configured sink should receive 1 notification")
	}
}

func TestDispatch_PerSinkErrorsDoNotBlock(t *testing.T) {
	notifications := BuildNotifications([]compliancekit.Finding{sampleFinding("x", "critical")}, BuildOptions{})

	failing := &stubSink{name: "failing", configured: true, threshold: compliancekit.SeverityInfo, sendErr: errors.New("transport error")}
	working := &stubSink{name: "working", configured: true, threshold: compliancekit.SeverityInfo}

	r := NewRegistry()
	r.Register(failing)
	r.Register(working)

	_, errs := Dispatch(context.Background(), r, notifications)
	if len(errs) != 1 {
		t.Errorf("expected exactly 1 error (failing sink), got %d: %v", len(errs), errs)
	}
	if !strings.Contains(errs[0].Error(), "failing:") {
		t.Errorf("error not wrapped with sink name: %v", errs[0])
	}
	if len(working.received) != 1 {
		t.Errorf("working sink should still receive the notification despite failing peer")
	}
}

func TestResult_Add(t *testing.T) {
	a := Result{Sent: 1, Skipped: 2, Errors: 0, Messages: []string{"first"}}
	a.Add(Result{Sent: 3, Skipped: 1, Errors: 1, Messages: []string{"second"}})
	if a.Sent != 4 || a.Skipped != 3 || a.Errors != 1 || len(a.Messages) != 2 {
		t.Errorf("Result.Add accumulator wrong: %+v", a)
	}
}

func TestRegister_PanicsOnNil(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Register(nil) should panic")
		}
	}()
	NewRegistry().Register(nil)
}

func TestRegister_PanicsOnEmptyName(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Register with empty Name() should panic")
		}
	}()
	NewRegistry().Register(&stubSink{name: ""})
}
