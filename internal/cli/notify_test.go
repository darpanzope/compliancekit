package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

const sampleFindingsJSON = `{
  "findings": [
    {"check_id":"aws-s3-public-access-block","status":"fail","severity":"high",
     "resource":{"id":"aws.s3.bucket.prod","type":"aws.s3.bucket","name":"prod","provider":"aws"},
     "message":"bucket is public","tags":["s3"]},
    {"check_id":"aws-iam-root-mfa","status":"fail","severity":"critical",
     "resource":{"id":"aws.account.123","type":"aws.account","name":"123","provider":"aws"},
     "message":"root MFA missing","tags":["iam"]}
  ]
}`

func writeNotifyFindingsFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write findings: %v", err)
	}
	return path
}

func TestNotify_ListShowsAllRegisteredSinks(t *testing.T) {
	var out bytes.Buffer
	if err := runNotifyList(&out, plainStyler()); err != nil {
		t.Fatalf("runNotifyList: %v", err)
	}
	s := out.String()
	for _, sink := range []string{"slack", "discord", "teams", "webhook", "email", "github-pr", "jira", "pagerduty"} {
		if !strings.Contains(s, sink) {
			t.Errorf("missing sink in --list output: %q\n%s", sink, s)
		}
	}
	if !strings.Contains(s, "8 sink(s) registered") {
		t.Errorf("missing summary line in:\n%s", s)
	}
}

func TestNotify_DryRunSkipsUnconfigured(t *testing.T) {
	path := writeNotifyFindingsFile(t, sampleFindingsJSON)
	var out bytes.Buffer
	err := runNotify(context.Background(), &out, plainStyler(), notifyOptions{in: path, dryRun: true})
	if err != nil {
		t.Fatalf("runNotify: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "Dry run — 2 notification(s) prepared") {
		t.Errorf("dry-run prep line missing: %s", s)
	}
	if !strings.Contains(s, "[skip ] slack — not configured") {
		t.Errorf("unconfigured sink should appear as skip: %s", s)
	}
}

func TestNotify_GlobalSeverityFloorFilters(t *testing.T) {
	path := writeNotifyFindingsFile(t, sampleFindingsJSON)
	var out bytes.Buffer
	err := runNotify(context.Background(), &out, plainStyler(), notifyOptions{
		in: path, severity: "critical", dryRun: true,
	})
	if err != nil {
		t.Fatalf("runNotify: %v", err)
	}
	s := out.String()
	// 2 findings → 1 after critical-only filter (the high-severity one drops).
	if !strings.Contains(s, "Global severity floor=critical: 2 → 1") {
		t.Errorf("severity filter line wrong: %s", s)
	}
	if !strings.Contains(s, "Dry run — 1 notification(s) prepared") {
		t.Errorf("dry-run line should show 1 after filter: %s", s)
	}
}

func TestNotify_OnlyNewMode(t *testing.T) {
	path := writeNotifyFindingsFile(t, sampleFindingsJSON)

	// Build a baseline that ALREADY contains both findings — only-new
	// mode should drop everything.
	var env struct {
		Findings []compliancekit.Finding `json:"findings"`
	}
	_ = json.Unmarshal([]byte(sampleFindingsJSON), &env)
	baselineBody, _ := json.Marshal(env)
	baselinePath := writeNotifyFindingsFile(t, string(baselineBody))

	var out bytes.Buffer
	err := runNotify(context.Background(), &out, plainStyler(), notifyOptions{
		in: path, baseline: baselinePath, dryRun: true,
	})
	if err != nil {
		t.Fatalf("runNotify: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "Only-new-findings mode: 2 → 0") {
		t.Errorf("baseline-subtraction line wrong: %s", s)
	}
	if !strings.Contains(s, "Dry run — 0 notification(s) prepared") {
		t.Errorf("dry-run with zero notifications:\n%s", s)
	}
}

func TestNotify_InvalidSeverity(t *testing.T) {
	path := writeNotifyFindingsFile(t, sampleFindingsJSON)
	var out bytes.Buffer
	err := runNotify(context.Background(), &out, plainStyler(), notifyOptions{in: path, severity: "bogus"})
	if err == nil || !strings.Contains(err.Error(), "severity") {
		t.Errorf("expected severity parse error; got %v", err)
	}
}

func TestNotify_RequiresIn(t *testing.T) {
	var out bytes.Buffer
	err := runNotify(context.Background(), &out, plainStyler(), notifyOptions{})
	if err == nil || !strings.Contains(err.Error(), "--in is required") {
		t.Errorf("expected --in required error; got %v", err)
	}
}
