package ocsf

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/ingest"
	"github.com/darpanzope/compliancekit/internal/report"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// TestRoundTrip_NativeOCSFEmitThenIngest exercises the path that
// matters most: a native compliancekit finding is rendered to OCSF,
// then immediately ingested back through the v0.13 OCSF adapter, and
// the recovered finding matches the original on every load-bearing
// field (CheckID, Status, Severity, Resource ID + region + account,
// Source.Type/Tool/Format, Message, Tags). Lossless across the trip
// is the v0.13 invariant for OCSF as a wire format.
func TestRoundTrip_NativeOCSFEmitThenIngest(t *testing.T) {
	original := compliancekit.Finding{
		CheckID:  "aws.s3.bucket-public-read",
		Status:   compliancekit.StatusFail,
		Severity: compliancekit.SeverityCritical,
		Resource: compliancekit.ResourceRef{
			ID:        "arn:aws:s3:::acme-customer-backups",
			Type:      "aws.s3.bucket",
			Name:      "acme-customer-backups",
			Provider:  "aws",
			Region:    "us-east-1",
			AccountID: "123456789012",
		},
		Message:   "Bucket grants Read to AllUsers",
		Tags:      []string{"s3", "public-access"},
		Timestamp: time.Date(2026, 5, 15, 10, 0, 0, 0, time.UTC),
		Source: &compliancekit.Source{
			Type: "native",
		},
	}

	// Emit via the existing report.OCSFReporter.
	var buf bytes.Buffer
	if err := report.NewOCSF().Render(context.Background(), []compliancekit.Finding{original}, nil, &buf); err != nil {
		t.Fatalf("OCSF emit: %v", err)
	}

	// Ingest back via the v0.13 OCSF adapter.
	r, err := adapter{}.Ingest(context.Background(), &buf, ingest.Options{})
	if err != nil {
		t.Fatalf("OCSF ingest: %v", err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("want 1 finding after round-trip, got %d", len(r.Findings))
	}

	recovered := r.Findings[0]

	// CheckID must survive verbatim — no `ingest.compliancekit.` prefix.
	if recovered.CheckID != original.CheckID {
		t.Errorf("CheckID drifted: %q → %q", original.CheckID, recovered.CheckID)
	}
	if recovered.Severity != original.Severity {
		t.Errorf("Severity drifted: %v → %v", original.Severity, recovered.Severity)
	}
	if recovered.Status != original.Status {
		t.Errorf("Status drifted: %v → %v", original.Status, recovered.Status)
	}
	if recovered.Resource.ID != original.Resource.ID {
		t.Errorf("Resource.ID drifted: %q → %q", original.Resource.ID, recovered.Resource.ID)
	}
	if recovered.Resource.Region != original.Resource.Region {
		t.Errorf("Resource.Region drifted: %q → %q", original.Resource.Region, recovered.Resource.Region)
	}
	if recovered.Resource.AccountID != original.Resource.AccountID {
		t.Errorf("Resource.AccountID drifted: %q → %q", original.Resource.AccountID, recovered.Resource.AccountID)
	}
	if recovered.Message != original.Message {
		t.Errorf("Message drifted: %q → %q", original.Message, recovered.Message)
	}

	// Source.Type should be "native" (round-trip preserved via
	// unmapped.compliancekit_source). Tool/Format are blank on a
	// native finding, so they should still be blank after recovery.
	if recovered.Source == nil {
		t.Fatalf("Source nil after round-trip")
	}
	if recovered.Source.Type != "native" {
		t.Errorf("Source.Type drifted: %q → %q", "native", recovered.Source.Type)
	}

	// Fingerprint is the canonical correlation key for the diff engine.
	// Both sides must produce the same one or drift detection will mis-
	// classify the recovered finding as a "new" finding next run.
	if original.Fingerprint() != recovered.Fingerprint() {
		t.Errorf("Fingerprint drifted: %s → %s", original.Fingerprint(), recovered.Fingerprint())
	}

	// Tags: must contain the originals (mapping table may append more,
	// which is OK; ours-must-still-be-there is the assertion).
	wantTags := map[string]bool{}
	for _, tg := range original.Tags {
		wantTags[tg] = true
	}
	for _, tg := range recovered.Tags {
		delete(wantTags, tg)
	}
	if len(wantTags) > 0 {
		t.Errorf("missing tags after round-trip: %v", wantTags)
	}
}

// TestEmitContainsRoundTripFields verifies the OCSF emit populates
// every field the v0.13 ingest adapter needs to reverse the trip —
// metadata.product.name = "compliancekit", finding_info.uid +
// finding_info.types[0] = CheckID, compliance.control = CheckID,
// resources[0] = ResourceRef equivalent, unmapped.compliancekit_source
// preserves the Source struct.
func TestEmitContainsRoundTripFields(t *testing.T) {
	f := compliancekit.Finding{
		CheckID:  "do.spaces.public-read",
		Status:   compliancekit.StatusFail,
		Severity: compliancekit.SeverityHigh,
		Resource: compliancekit.ResourceRef{
			ID:       "do://spaces/sfo3/customer-data",
			Type:     "digitalocean.spaces.bucket",
			Name:     "customer-data",
			Provider: "digitalocean",
			Region:   "sfo3",
		},
		Message: "Spaces bucket exposes public read",
		Source:  &compliancekit.Source{Type: "native"},
	}
	var buf bytes.Buffer
	if err := report.NewOCSF().Render(context.Background(), []compliancekit.Finding{f}, nil, &buf); err != nil {
		t.Fatalf("emit: %v", err)
	}

	s := buf.String()
	wantSubstrings := []string{
		`"name": "compliancekit"`,            // product name → triggers round-trip path
		`"control": "do.spaces.public-read"`, // compliance.control
		`"uid": "do.spaces.public-read"`,     // finding_info.uid
		`"do.spaces.public-read"`,            // finding_info.types[0]
		`"compliancekit_source"`,             // round-trip provenance slot
		`"sfo3"`,                             // region
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(s, want) {
			t.Errorf("OCSF emit missing %q\ngot:\n%s", want, s)
		}
	}
}
