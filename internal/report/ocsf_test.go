package report

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
)

// Compile-time assertion.
var _ core.Reporter = (*OCSFReporter)(nil)

func TestOCSF_Format(t *testing.T) {
	if got := NewOCSF().Format(); got != "json-ocsf" {
		t.Errorf("Format() = %q, want json-ocsf", got)
	}
}

func TestOCSF_RenderEmptyIsEmptyArray(t *testing.T) {
	var buf bytes.Buffer
	if err := NewOCSF().Render(context.Background(), nil, nil, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	// Output must be a valid JSON array.
	var arr []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &arr); err != nil {
		t.Fatalf("output not valid JSON array: %v\n%s", err, buf.String())
	}
	if len(arr) != 0 {
		t.Errorf("empty input should produce [], got %d events", len(arr))
	}
}

func TestOCSF_RenderEmitsAllStatuses(t *testing.T) {
	// SIEM use cases need pass+fail+skip so dashboards can compute
	// pass rates. Unlike SARIF, OCSF emits everything.
	findings := []core.Finding{
		{
			CheckID:   "fail-check",
			Status:    core.StatusFail,
			Severity:  core.SeverityHigh,
			Resource:  core.ResourceRef{ID: "r1", Name: "web-01", Type: "linux.host"},
			Message:   "broken",
			Timestamp: time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC),
		},
		{
			CheckID:  "pass-check",
			Status:   core.StatusPass,
			Severity: core.SeverityLow,
			Resource: core.ResourceRef{ID: "r2", Name: "web-02", Type: "linux.host"},
		},
		{
			CheckID:  "skip-check",
			Status:   core.StatusSkip,
			Severity: core.SeverityMedium,
			Resource: core.ResourceRef{ID: "r3", Name: "web-03", Type: "linux.host"},
		},
	}

	var buf bytes.Buffer
	if err := NewOCSF().Render(context.Background(), findings, nil, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}

	var events []struct {
		Metadata struct {
			Version string `json:"version"`
		} `json:"metadata"`
		CategoryUID int    `json:"category_uid"`
		ClassUID    int    `json:"class_uid"`
		SeverityID  int    `json:"severity_id"`
		Severity    string `json:"severity"`
		StatusID    int    `json:"status_id"`
		Status      string `json:"status"`
		Time        int64  `json:"time"`
		Compliance  struct {
			Control string `json:"control"`
		} `json:"compliance"`
		Resources []struct {
			Name string `json:"name"`
			Type string `json:"type"`
			UID  string `json:"uid"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(buf.Bytes(), &events); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}

	if len(events) != 3 {
		t.Fatalf("expected 3 events (one per finding), got %d", len(events))
	}

	for _, e := range events {
		if e.Metadata.Version != "1.5.0" {
			t.Errorf("event has wrong OCSF version: %q", e.Metadata.Version)
		}
		if e.CategoryUID != 2 {
			t.Errorf("category_uid = %d, want 2", e.CategoryUID)
		}
		if e.ClassUID != 2003 {
			t.Errorf("class_uid = %d, want 2003", e.ClassUID)
		}
	}

	// Spot-check the failing event in detail.
	fail := events[0]
	if fail.Compliance.Control != "fail-check" {
		t.Errorf("compliance.control = %q, want fail-check", fail.Compliance.Control)
	}
	if fail.SeverityID != 4 || fail.Severity != "High" {
		t.Errorf("severity = (%d, %q), want (4, High)", fail.SeverityID, fail.Severity)
	}
	if fail.StatusID != 2 || fail.Status != "Failure" {
		t.Errorf("status = (%d, %q), want (2, Failure)", fail.StatusID, fail.Status)
	}
	if len(fail.Resources) != 1 || fail.Resources[0].UID != "r1" {
		t.Errorf("resources = %v, want one with UID r1", fail.Resources)
	}

	// Pass event uses status_id=1 (Pass).
	if events[1].StatusID != 1 || events[1].Status != "Pass" {
		t.Errorf("pass: status = (%d, %q), want (1, Pass)", events[1].StatusID, events[1].Status)
	}

	// Skip event uses status_id=99 (Other) -- OCSF Compliance Finding
	// enum has no native skip; collapsing to Other is the correct
	// downstream-friendly mapping.
	if events[2].StatusID != 99 || events[2].Status != "Other" {
		t.Errorf("skip: status = (%d, %q), want (99, Other)", events[2].StatusID, events[2].Status)
	}
}

func TestOCSF_SeverityMapping(t *testing.T) {
	cases := []struct {
		sev    core.Severity
		wantID int
		wantS  string
	}{
		{core.SeverityInfo, 1, "Informational"},
		{core.SeverityLow, 2, "Low"},
		{core.SeverityMedium, 3, "Medium"},
		{core.SeverityHigh, 4, "High"},
		{core.SeverityCritical, 5, "Critical"},
	}
	for _, c := range cases {
		gotID, gotS := ocsfSeverityFor(c.sev)
		if gotID != c.wantID || gotS != c.wantS {
			t.Errorf("ocsfSeverityFor(%s) = (%d, %q), want (%d, %q)", c.sev, gotID, gotS, c.wantID, c.wantS)
		}
	}
}

func TestOCSF_TimePopulatedWhenZero(t *testing.T) {
	// Findings produced by checks before the engine stamps them
	// (defensive) should still have a non-zero OCSF time.
	findings := []core.Finding{
		{CheckID: "x", Status: core.StatusPass, Severity: core.SeverityInfo, Resource: core.ResourceRef{ID: "r"}},
	}
	var buf bytes.Buffer
	_ = NewOCSF().Render(context.Background(), findings, nil, &buf)

	var events []struct {
		Time int64 `json:"time"`
	}
	_ = json.Unmarshal(buf.Bytes(), &events)
	if events[0].Time <= 0 {
		t.Errorf("time = %d, want > 0 (now-fallback when Timestamp is zero)", events[0].Time)
	}
}

func TestOCSF_FactoryNew(t *testing.T) {
	r, err := New("json-ocsf")
	if err != nil {
		t.Fatalf("New(json-ocsf): %v", err)
	}
	if r.Format() != "json-ocsf" {
		t.Errorf("got %q, want json-ocsf", r.Format())
	}
}
