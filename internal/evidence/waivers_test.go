package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func TestWriteWaiversJSON_EmptyWhenNoWaivers(t *testing.T) {
	dir := t.TempDir()
	path, err := writeWaiversJSON(dir, []compliancekit.Finding{
		{CheckID: "x", Status: compliancekit.StatusFail, Resource: compliancekit.ResourceRef{ID: "r"}},
	})
	if err != nil {
		t.Fatalf("writeWaiversJSON: %v", err)
	}
	if path != "" {
		t.Errorf("no waivers → empty path; got %q", path)
	}
	if _, err := os.Stat(filepath.Join(dir, "waivers.json")); !os.IsNotExist(err) {
		t.Errorf("waivers.json should NOT be written when no waivers present")
	}
}

func TestWriteWaiversJSON_PopulatedShape(t *testing.T) {
	dir := t.TempDir()
	expires := time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC)
	findings := []compliancekit.Finding{
		{
			CheckID:  "aws-s3-no-public-acls",
			Status:   compliancekit.StatusSkip,
			Severity: compliancekit.SeverityHigh,
			Resource: compliancekit.ResourceRef{ID: "aws.s3.bucket.public-cdn", Name: "public-cdn"},
			Message:  "bucket has public ACL",
			Waiver: &compliancekit.WaiverRef{
				CheckID:    "aws-s3-no-public-acls",
				ResourceID: "aws.s3.bucket.public-cdn",
				Reason:     "public CDN bucket; CloudFront enforces signed URLs at edge",
				Approver:   "security@acme.com",
				Expires:    expires,
				Source:     "file",
				SourcePath: "waivers.yaml",
			},
		},
		{
			CheckID:  "x",
			Status:   compliancekit.StatusFail,
			Resource: compliancekit.ResourceRef{ID: "r"},
			// No Waiver — should not appear in the artifact.
		},
	}
	path, err := writeWaiversJSON(dir, findings)
	if err != nil {
		t.Fatalf("writeWaiversJSON: %v", err)
	}
	if filepath.Base(path) != "waivers.json" {
		t.Errorf("unexpected filename: %s", path)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, body)
	}
	if doc["schema"] != "compliancekit.waivers.v1" {
		t.Errorf("schema = %v", doc["schema"])
	}
	if doc["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1 (only one waivered finding)", doc["count"])
	}
	entries := doc["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries = %d", len(entries))
	}
	first := entries[0].(map[string]any)
	if first["check_id"] != "aws-s3-no-public-acls" {
		t.Errorf("check_id = %v", first["check_id"])
	}
	if !strings.Contains(first["reason"].(string), "CloudFront") {
		t.Errorf("reason lifted from WaiverRef: %v", first["reason"])
	}
	if first["finding"] == nil {
		t.Errorf("finding cross-reference missing")
	}
}

func TestWriteWaiversJSON_StableOrder(t *testing.T) {
	dir := t.TempDir()
	expires := time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC)
	mkFinding := func(check, res string) compliancekit.Finding {
		return compliancekit.Finding{
			CheckID:  check,
			Status:   compliancekit.StatusSkip,
			Resource: compliancekit.ResourceRef{ID: res},
			Waiver: &compliancekit.WaiverRef{
				CheckID: check, ResourceID: res, Reason: "ok", Approver: "a",
				Expires: expires,
			},
		}
	}
	findings := []compliancekit.Finding{
		mkFinding("z-check", "r-2"),
		mkFinding("a-check", "r-1"),
		mkFinding("a-check", "r-0"),
	}
	path, _ := writeWaiversJSON(dir, findings)
	body, _ := os.ReadFile(path)
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
	entries := doc["entries"].([]any)
	first := entries[0].(map[string]any)
	second := entries[1].(map[string]any)
	third := entries[2].(map[string]any)
	if first["check_id"] != "a-check" || first["resource_id"] != "r-0" {
		t.Errorf("first entry should be (a-check, r-0): %+v", first)
	}
	if second["check_id"] != "a-check" || second["resource_id"] != "r-1" {
		t.Errorf("second entry should be (a-check, r-1): %+v", second)
	}
	if third["check_id"] != "z-check" {
		t.Errorf("third entry should be z-check: %+v", third)
	}
}
