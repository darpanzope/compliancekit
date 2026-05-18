package report

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Compile-time assertion.
var _ compliancekit.Reporter = (*SARIFReporter)(nil)

func TestSARIF_Format(t *testing.T) {
	if got := NewSARIF().Format(); got != "sarif" {
		t.Errorf("Format() = %q, want sarif", got)
	}
}

func TestSARIF_RenderEmptyProducesValidShape(t *testing.T) {
	var buf bytes.Buffer
	if err := NewSARIF().Render(context.Background(), nil, nil, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, buf.String())
	}
	if doc["version"] != sarifVersion {
		t.Errorf("version = %v, want %s", doc["version"], sarifVersion)
	}
	if doc["$schema"] != sarifSchemaURI {
		t.Errorf("schema = %v, want %s", doc["$schema"], sarifSchemaURI)
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %v, want exactly 1 run", doc["runs"])
	}
}

func TestSARIF_RenderEmitsRulesAndResults(t *testing.T) {
	findings := []compliancekit.Finding{
		{
			CheckID:  "a-check",
			Status:   compliancekit.StatusFail,
			Severity: compliancekit.SeverityHigh,
			Resource: compliancekit.ResourceRef{ID: "do.droplet.1", Name: "web", Type: "digitalocean.droplet"},
			Message:  "exposed",
		},
		{
			CheckID:  "b-check",
			Status:   compliancekit.StatusPass, // passes are NOT emitted as results
			Severity: compliancekit.SeverityLow,
			Resource: compliancekit.ResourceRef{ID: "x"},
		},
	}

	var buf bytes.Buffer
	if err := NewSARIF().Render(context.Background(), findings, nil, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}

	var decoded struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID                   string `json:"id"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}

	run := decoded.Runs[0]

	// Rules: every distinct check ID, regardless of result status.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("len(rules) = %d, want 2 (a-check + b-check)", len(run.Tool.Driver.Rules))
	}
	// Rules sorted alphabetically by ID.
	if run.Tool.Driver.Rules[0].ID != "a-check" || run.Tool.Driver.Rules[1].ID != "b-check" {
		t.Errorf("rules not alphabetical: %v", run.Tool.Driver.Rules)
	}
	// Severity -> level mapping.
	if run.Tool.Driver.Rules[0].DefaultConfiguration.Level != "error" {
		t.Errorf("a-check level = %q, want error (high severity)", run.Tool.Driver.Rules[0].DefaultConfiguration.Level)
	}

	// Results: only actionable (fail/error).
	if len(run.Results) != 1 {
		t.Fatalf("len(results) = %d, want 1 (only the failing finding)", len(run.Results))
	}
	if run.Results[0].RuleID != "a-check" {
		t.Errorf("RuleID = %q, want a-check", run.Results[0].RuleID)
	}
	if run.Results[0].Level != "error" {
		t.Errorf("Level = %q, want error", run.Results[0].Level)
	}
	if run.Results[0].Message.Text != "exposed" {
		t.Errorf("Message.Text = %q, want exposed", run.Results[0].Message.Text)
	}
	// RuleIndex must point at the right rule.
	if got, want := run.Results[0].RuleIndex, 0; got != want {
		t.Errorf("RuleIndex = %d, want %d (a-check is rules[0])", got, want)
	}
}

func TestSARIF_SeverityLevelMapping(t *testing.T) {
	cases := map[compliancekit.Severity]string{
		compliancekit.SeverityCritical: "error",
		compliancekit.SeverityHigh:     "error",
		compliancekit.SeverityMedium:   "warning",
		compliancekit.SeverityLow:      "note",
		compliancekit.SeverityInfo:     "note",
	}
	for sev, want := range cases {
		if got := sarifLevelFor(sev); got != want {
			t.Errorf("sarifLevelFor(%s) = %q, want %q", sev, got, want)
		}
	}
}

func TestSARIF_FactoryNew(t *testing.T) {
	r, err := New("sarif")
	if err != nil {
		t.Fatalf("New(sarif): %v", err)
	}
	if r.Format() != "sarif" {
		t.Errorf("got %q, want sarif", r.Format())
	}
}
