package waivers

import (
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func TestMatch_ExactPair(t *testing.T) {
	now := fixedNow()
	list, _ := NewWaiverList([]Waiver{validWaiver()}, now)

	if w := list.Match("aws-s3-public-access-block", "aws.s3.bucket.public-cdn"); w == nil {
		t.Errorf("exact (check, resource) should match")
	}
	if w := list.Match("aws-s3-versioning", "aws.s3.bucket.public-cdn"); w != nil {
		t.Errorf("different check should NOT match")
	}
	if w := list.Match("aws-s3-public-access-block", "aws.s3.bucket.other"); w != nil {
		t.Errorf("different resource should NOT match")
	}
}

func TestMatch_GlobWildcard(t *testing.T) {
	now := fixedNow()
	entries := []Waiver{
		{
			CheckID: "aws-s3-*", ResourceID: "aws.s3.bucket.public-cdn",
			Reason: "a long enough reason for the audit", Approver: "alice@x.com",
			Expires: now.AddDate(0, 1, 0),
		},
		{
			CheckID: "do-droplet-no-vpc", ResourceID: "digitalocean.droplet.*",
			Reason: "a long enough reason for the audit", Approver: "alice@x.com",
			Expires: now.AddDate(0, 1, 0),
		},
	}
	list, _ := NewWaiverList(entries, now)

	// aws-s3-* matches multiple specific S3 check IDs on the matching resource.
	if w := list.Match("aws-s3-versioning", "aws.s3.bucket.public-cdn"); w == nil {
		t.Errorf("CheckID glob aws-s3-* should match aws-s3-versioning")
	}
	if w := list.Match("aws-iam-root-mfa", "aws.s3.bucket.public-cdn"); w != nil {
		t.Errorf("aws-s3-* should NOT match aws-iam-root-mfa")
	}

	// ResourceID glob digitalocean.droplet.* matches any droplet ID.
	if w := list.Match("do-droplet-no-vpc", "digitalocean.droplet.web-1"); w == nil {
		t.Errorf("ResourceID glob should match")
	}
	if w := list.Match("do-droplet-no-vpc", "digitalocean.firewall.x"); w != nil {
		t.Errorf("ResourceID glob digitalocean.droplet.* should NOT match a firewall ID")
	}
}

func TestApply_MutesFindingsAndTagsThem(t *testing.T) {
	now := fixedNow()
	list, _ := NewWaiverList([]Waiver{validWaiver()}, now)

	findings := []compliancekit.Finding{
		{
			CheckID: "aws-s3-public-access-block", Status: compliancekit.StatusFail, Severity: compliancekit.SeverityCritical,
			Resource: compliancekit.ResourceRef{ID: "aws.s3.bucket.public-cdn", Name: "public-cdn"},
		},
		{
			// Different resource — should NOT be muted.
			CheckID: "aws-s3-public-access-block", Status: compliancekit.StatusFail, Severity: compliancekit.SeverityCritical,
			Resource: compliancekit.ResourceRef{ID: "aws.s3.bucket.other", Name: "other"},
		},
	}
	muted, synth := list.Apply(findings, now)
	if muted != 1 {
		t.Errorf("muted = %d, want 1", muted)
	}
	if len(synth) != 0 {
		t.Errorf("no expired waivers → no synthesized findings: got %d", len(synth))
	}
	if findings[0].Status != compliancekit.StatusSkip {
		t.Errorf("matched finding should be StatusSkip; got %v", findings[0].Status)
	}
	if findings[0].Waiver == nil {
		t.Errorf("WaiverRef should be populated on muted finding")
	}
	if !hasTag(findings[0].Tags, "waived") {
		t.Errorf("`waived` tag should be appended")
	}
	if findings[1].Status != compliancekit.StatusFail {
		t.Errorf("non-matching finding should retain StatusFail")
	}
}

func TestApply_DoesNotMutePassingFindings(t *testing.T) {
	now := fixedNow()
	list, _ := NewWaiverList([]Waiver{validWaiver()}, now)
	findings := []compliancekit.Finding{
		{
			CheckID: "aws-s3-public-access-block", Status: compliancekit.StatusPass,
			Resource: compliancekit.ResourceRef{ID: "aws.s3.bucket.public-cdn"},
		},
	}
	muted, _ := list.Apply(findings, now)
	if muted != 0 {
		t.Errorf("passing findings shouldn't be touched; muted=%d", muted)
	}
	if findings[0].Status != compliancekit.StatusPass {
		t.Errorf("passing finding status changed: %v", findings[0].Status)
	}
}

func TestApply_SynthesizesExpiredFindings(t *testing.T) {
	now := fixedNow()
	expired := validWaiver()
	expired.Expires = now.AddDate(0, 0, -15) // 15 days expired
	list, _ := NewWaiverList([]Waiver{expired}, now)

	_, synth := list.Apply(nil, now)
	if len(synth) != 1 {
		t.Fatalf("expected 1 synthesized finding, got %d", len(synth))
	}
	got := synth[0]
	if got.CheckID != "compliancekit-waiver-expired" {
		t.Errorf("CheckID = %q", got.CheckID)
	}
	if got.Severity != compliancekit.SeverityInfo {
		t.Errorf("Severity = %v, want info", got.Severity)
	}
	if got.Waiver == nil || got.Waiver.Reason == "" {
		t.Errorf("synthesized finding must carry WaiverRef with original metadata")
	}
	if got.Resource.ID != expired.ResourceID {
		t.Errorf("Resource.ID = %q, want %q", got.Resource.ID, expired.ResourceID)
	}
	if !hasTag(got.Tags, "expired") {
		t.Errorf("`expired` tag missing")
	}
}

func TestMatchIDPattern(t *testing.T) {
	cases := []struct {
		pattern, target string
		want            bool
	}{
		{"literal", "literal", true},
		{"literal", "other", false},
		{"aws-s3-*", "aws-s3-versioning", true},
		{"aws-s3-*", "aws-iam-x", false},
		{"a?c", "abc", true},
		{"a?c", "abbc", false},
		{"[", "[", true}, // malformed pattern silently fails → fall back to literal-equality
	}
	for _, c := range cases {
		got := matchID(c.pattern, c.target)
		if got != c.want {
			t.Errorf("matchID(%q, %q) = %v, want %v", c.pattern, c.target, got, c.want)
		}
	}
}

// Ensure synthesizeExpiredFindings is deterministic order across runs.
func TestSynthesizeExpiredFindings_DeterministicOrder(t *testing.T) {
	now := fixedNow()
	entries := []Waiver{
		{CheckID: "z", ResourceID: "y", Reason: "a long enough reason for the audit",
			Approver: "alice@x.com", Expires: now.AddDate(0, 0, -10)},
		{CheckID: "a", ResourceID: "y", Reason: "a long enough reason for the audit",
			Approver: "alice@x.com", Expires: now.AddDate(0, 0, -20)},
	}
	list, _ := NewWaiverList(entries, now)
	synth := synthesizeExpiredFindings(list.Expired, now)
	if len(synth) != 2 || synth[0].Waiver.CheckID != "a" || synth[1].Waiver.CheckID != "z" {
		t.Errorf("expected synth sorted by CheckID; got %+v", synth)
	}
}

// regression: matchID returns false for empty patterns; ensures
// "" pattern doesn't accidentally match any non-empty target.
func TestMatchID_EmptyPattern(t *testing.T) {
	if matchID("", "anything") {
		t.Errorf("empty pattern should not match a non-empty target")
	}
	if !matchID("", "") {
		t.Errorf("empty pattern + empty target should match (literal equality)")
	}
}

// Ensure DaysUntilExpiry returns negative for past dates.
func TestDaysUntilExpiry_Negative(t *testing.T) {
	w := &compliancekit.WaiverRef{Expires: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)}
	days := w.DaysUntilExpiry(time.Date(2026, 5, 17, 0, 0, 0, 0, time.UTC))
	if days >= 0 {
		t.Errorf("expected negative days for past expiry; got %d", days)
	}
}
