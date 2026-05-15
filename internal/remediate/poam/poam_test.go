package poam

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

func fixedTime() time.Time {
	return time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
}

func TestWrite_ProducesValidJSON(t *testing.T) {
	dir := t.TempDir()
	snippets := []remediate.Snippet{
		{
			CheckID:  "aws-iam-root-mfa",
			Resource: core.ResourceRef{ID: "aws.account.123", Type: "aws.account", Name: "123"},
			Risk:     remediate.RiskManual,
			Notes:    "Root MFA must be enabled via console.",
		},
	}
	unmatched := []core.Finding{
		{
			CheckID:  "ingest.trivy.AVD-AWS-9999",
			Resource: core.ResourceRef{ID: "trivy:image:foo"},
			Severity: core.SeverityHigh,
			Message:  "vulnerable package — manual review",
		},
	}
	path, err := Write(dir, snippets, unmatched, Options{GeneratedAt: fixedTime(), Project: "test-acme"})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if filepath.Base(path) != "poam.oscal.json" {
		t.Errorf("unexpected filename: %s", path)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	root, ok := doc["plan-of-action-and-milestones"].(map[string]any)
	if !ok {
		t.Fatalf("top-level missing plan-of-action-and-milestones")
	}
	if _, ok := root["uuid"].(string); !ok {
		t.Errorf("missing UUID")
	}
	items, ok := root["poam-items"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("expected 2 poam-items, got %v", items)
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	snippets := []remediate.Snippet{
		{CheckID: "x", Resource: core.ResourceRef{ID: "r1"}, Risk: remediate.RiskManual, Notes: "note"},
	}
	opts := Options{GeneratedAt: fixedTime(), Project: "p", Period: "2026-Q2"}
	first := build(snippets, nil, opts)
	second := build(snippets, nil, opts)
	if first.PlanOfActionAndMilestones.UUID != second.PlanOfActionAndMilestones.UUID {
		t.Errorf("non-deterministic doc UUID")
	}
	if first.PlanOfActionAndMilestones.Items[0].UUID != second.PlanOfActionAndMilestones.Items[0].UUID {
		t.Errorf("non-deterministic item UUID")
	}
}

func TestSkipNonManualSnippets(t *testing.T) {
	// A RiskSafe snippet must not appear in the POA&M.
	snippets := []remediate.Snippet{
		{CheckID: "safe", Resource: core.ResourceRef{ID: "r"}, Risk: remediate.RiskSafe},
		{CheckID: "manual", Resource: core.ResourceRef{ID: "r"}, Risk: remediate.RiskManual, Notes: "manual"},
	}
	doc := build(snippets, nil, Options{GeneratedAt: fixedTime()})
	if len(doc.PlanOfActionAndMilestones.Items) != 1 {
		t.Fatalf("expected 1 item (manual only), got %d", len(doc.PlanOfActionAndMilestones.Items))
	}
	if doc.PlanOfActionAndMilestones.Items[0].Title == "" || !strings.Contains(doc.PlanOfActionAndMilestones.Items[0].Title, "manual") {
		t.Errorf("title should include CheckID: %q", doc.PlanOfActionAndMilestones.Items[0].Title)
	}
}

func TestSortStable(t *testing.T) {
	// Same checks given in scrambled order produce sorted output.
	snippets := []remediate.Snippet{
		{CheckID: "z-check", Resource: core.ResourceRef{ID: "r-2"}, Risk: remediate.RiskManual},
		{CheckID: "a-check", Resource: core.ResourceRef{ID: "r-1"}, Risk: remediate.RiskManual},
	}
	doc := build(snippets, nil, Options{GeneratedAt: fixedTime()})
	if len(doc.PlanOfActionAndMilestones.Items) != 2 {
		t.Fatalf("len=%d", len(doc.PlanOfActionAndMilestones.Items))
	}
	if doc.PlanOfActionAndMilestones.Items[0].Title[strings.Index(doc.PlanOfActionAndMilestones.Items[0].Title, ":")+2:strings.Index(doc.PlanOfActionAndMilestones.Items[0].Title, " on")] != "a-check" {
		t.Errorf("items not sorted by CheckID: %s", doc.PlanOfActionAndMilestones.Items[0].Title)
	}
}

func TestPeriodDefault(t *testing.T) {
	got := periodOrDefault("", fixedTime())
	if got != "2026-Q2" {
		t.Errorf("periodOrDefault default = %q, want 2026-Q2", got)
	}
	if periodOrDefault("custom", fixedTime()) != "custom" {
		t.Errorf("explicit period should pass through")
	}
}
