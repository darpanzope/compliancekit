package waivers

import (
	"strings"
	"testing"
)

func TestScanAnnotations_Fixture(t *testing.T) {
	now := fixedNow()
	waivers, errs := ScanAnnotations("testdata/annotated", now)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(waivers) != 2 {
		t.Fatalf("expected 2 annotations, got %d:\n%+v", len(waivers), waivers)
	}

	// First annotation has full kwargs.
	first := waivers[0]
	if first.CheckID != "aws-s3-no-public-acls" {
		t.Errorf("first CheckID = %q", first.CheckID)
	}
	if first.ResourceID != "aws.s3.bucket.public-cdn" {
		t.Errorf("first ResourceID = %q", first.ResourceID)
	}
	if !strings.Contains(first.Reason, "CloudFront") {
		t.Errorf("reason should be lifted from annotation: %q", first.Reason)
	}
	if first.Approver != "security@acme.com" {
		t.Errorf("approver = %q", first.Approver)
	}
	if first.Source != "annotation" {
		t.Errorf("source = %q", first.Source)
	}
	if !strings.Contains(first.SourcePath, "main.tf:") {
		t.Errorf("source_path should include file:line — got %q", first.SourcePath)
	}

	// Second annotation has NO kwargs — defaults apply.
	second := waivers[1]
	if second.CheckID != "aws-iam-no-user-managed-policies" {
		t.Errorf("second CheckID = %q", second.CheckID)
	}
	if !strings.Contains(second.Reason, "annotation in") {
		t.Errorf("default reason should reference annotation location: %q", second.Reason)
	}
	if second.Approver != "@annotation" {
		t.Errorf("default approver = %q, want @annotation", second.Approver)
	}
	// Default expiry = 90 days from `now`. Approximate check.
	if days := int(second.Expires.Sub(now).Hours() / 24); days < 89 || days > 91 {
		t.Errorf("default expiry should be ~90 days; got %d days", days)
	}
}

func TestParseAnnotationKVs_QuotedAndBare(t *testing.T) {
	got := parseAnnotationKVs(` reason="hello world" approver=bob@x.com expires=2026-12-31 unknown=ignored`)
	if got["reason"] != "hello world" {
		t.Errorf("quoted reason wrong: %q", got["reason"])
	}
	if got["approver"] != "bob@x.com" {
		t.Errorf("bare approver wrong: %q", got["approver"])
	}
	if got["expires"] != "2026-12-31" {
		t.Errorf("expires = %q", got["expires"])
	}
	if got["unknown"] != "ignored" {
		t.Errorf("unknown keys should pass through silently (forward-compat)")
	}
}

func TestShouldScanFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"main.tf", true},
		{"vars.tfvars", true},
		{"config.yaml", true},
		{"deploy.sh", true},
		{"app.py", true},
		{"main.go", true},
		{"Dockerfile", true},
		{"backend.dockerfile", true},
		{"README.md", false},
		{"image.png", false},
	}
	for _, c := range cases {
		if got := shouldScanFile(c.path); got != c.want {
			t.Errorf("shouldScanFile(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestShouldSkipDir(t *testing.T) {
	for _, name := range []string{".git", "node_modules", "vendor", ".terraform", "dist"} {
		if !shouldSkipDir(name) {
			t.Errorf("shouldSkipDir(%q) should be true", name)
		}
	}
	if shouldSkipDir("src") {
		t.Errorf("src should not be skipped")
	}
}

func TestScanAnnotations_MissingRoot(t *testing.T) {
	waivers, errs := ScanAnnotations("testdata/does-not-exist", fixedNow())
	if len(errs) != 0 {
		t.Errorf("missing root should not error: %v", errs)
	}
	if waivers != nil {
		t.Errorf("missing root should return nil waivers; got %v", waivers)
	}
}

func TestScanAnnotations_SingleFile(t *testing.T) {
	// Calling ScanAnnotations with a single .tf path (not a dir)
	// should still work — useful for module-scoped scans.
	waivers, errs := ScanAnnotations("testdata/annotated/main.tf", fixedNow())
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(waivers) != 2 {
		t.Errorf("expected 2 waivers from single file scan, got %d", len(waivers))
	}
}
