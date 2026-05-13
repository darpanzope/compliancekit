package report

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
)

// Compile-time assertion that *JSONReporter satisfies core.Reporter.
var _ core.Reporter = (*JSONReporter)(nil)

func TestJSON_Format(t *testing.T) {
	r := NewJSON()
	if got := r.Format(); got != "json" {
		t.Errorf("Format() = %q, want json", got)
	}
}

func TestJSON_RenderEmpty(t *testing.T) {
	r := NewJSON()
	var buf bytes.Buffer
	if err := r.Render(context.Background(), nil, nil, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}

	var env map[string]any
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, buf.String())
	}

	if env["schema"] != schemaVersion {
		t.Errorf("schema = %v, want %s", env["schema"], schemaVersion)
	}
	if env["findings"] != nil {
		t.Errorf("findings = %v, want nil", env["findings"])
	}
	s, ok := env["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary missing: %v", env["summary"])
	}
	if s["total"].(float64) != 0 {
		t.Errorf("total = %v, want 0", s["total"])
	}
}

func TestJSON_RenderFindings(t *testing.T) {
	findings := []core.Finding{
		{
			CheckID:   "do-test-1",
			Status:    core.StatusFail,
			Severity:  core.SeverityHigh,
			Resource:  core.ResourceRef{ID: "do.droplet.1", Type: "do.droplet", Name: "web", Provider: "digitalocean"},
			Message:   "test message",
			Timestamp: time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC),
		},
		{
			CheckID:  "do-test-2",
			Status:   core.StatusPass,
			Severity: core.SeverityLow,
			Resource: core.ResourceRef{ID: "do.droplet.2"},
		},
		{
			CheckID:  "do-test-3",
			Status:   core.StatusFail,
			Severity: core.SeverityCritical,
			Resource: core.ResourceRef{ID: "do.droplet.3"},
		},
	}

	r := NewJSON()
	var buf bytes.Buffer
	if err := r.Render(context.Background(), findings, nil, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}

	var decoded struct {
		Findings []core.Finding `json:"findings"`
		Summary  summary        `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}

	if got, want := len(decoded.Findings), 3; got != want {
		t.Errorf("len(findings) = %d, want %d", got, want)
	}
	if got, want := decoded.Summary.Total, 3; got != want {
		t.Errorf("Summary.Total = %d, want %d", got, want)
	}
	if got, want := decoded.Summary.ByStatus["fail"], 2; got != want {
		t.Errorf("ByStatus[fail] = %d, want %d", got, want)
	}
	if got, want := decoded.Summary.ByStatus["pass"], 1; got != want {
		t.Errorf("ByStatus[pass] = %d, want %d", got, want)
	}
	if got, want := decoded.Summary.BySeverity["high"], 1; got != want {
		t.Errorf("BySeverity[high] = %d, want %d", got, want)
	}
	if got, want := decoded.Summary.BySeverity["critical"], 1; got != want {
		t.Errorf("BySeverity[critical] = %d, want %d", got, want)
	}
}

func TestJSON_RenderIsIndented(t *testing.T) {
	r := NewJSON()
	var buf bytes.Buffer
	_ = r.Render(context.Background(), nil, nil, &buf)
	if !strings.Contains(buf.String(), "\n  ") {
		t.Errorf("output not indented:\n%s", buf.String())
	}
}

func TestNew_Factory(t *testing.T) {
	r, err := New("json")
	if err != nil {
		t.Fatalf("New(json): %v", err)
	}
	if r.Format() != "json" {
		t.Errorf("Format() = %q, want json", r.Format())
	}

	if _, err := New("unknown"); err == nil {
		t.Error("expected error for unknown format")
	}
}
