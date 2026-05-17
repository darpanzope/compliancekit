package waivers

import (
	"strings"
	"testing"
	"time"
)

func fixedNow() time.Time {
	return time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
}

func validWaiver() Waiver {
	return Waiver{
		CheckID:    "aws-s3-public-access-block",
		ResourceID: "aws.s3.bucket.public-cdn",
		Reason:     "public CDN bucket; CloudFront enforces access at the edge",
		Approver:   "security@acme.com",
		Expires:    fixedNow().AddDate(0, 3, 0),
	}
}

func TestValidate_HappyPath(t *testing.T) {
	w := validWaiver()
	if err := w.Validate(); err != nil {
		t.Errorf("valid waiver should pass: %v", err)
	}
}

func TestValidate_MissingRequiredFields(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*Waiver)
		wants string
	}{
		{"empty check_id", func(w *Waiver) { w.CheckID = "" }, "check_id"},
		{"empty resource_id", func(w *Waiver) { w.ResourceID = "" }, "resource_id"},
		{"empty reason", func(w *Waiver) { w.Reason = "" }, "reason"},
		{"empty approver", func(w *Waiver) { w.Approver = "" }, "approver"},
		{"zero expires", func(w *Waiver) { w.Expires = time.Time{} }, "expires"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := validWaiver()
			c.mut(&w)
			err := w.Validate()
			if err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
			if !strings.Contains(err.Error(), c.wants) {
				t.Errorf("error should mention %q: %v", c.wants, err)
			}
		})
	}
}

func TestValidate_RejectsTrivialReason(t *testing.T) {
	w := validWaiver()
	w.Reason = "OK"
	err := w.Validate()
	if err == nil || !strings.Contains(err.Error(), "16") {
		t.Errorf("short reason should be rejected with %d-char floor: %v", minReasonLen, err)
	}
}

func TestNewWaiverList_BucketsByExpiry(t *testing.T) {
	now := fixedNow()
	entries := []Waiver{
		// active
		{
			CheckID: "a", ResourceID: "x",
			Reason: "a long enough reason for the audit", Approver: "alice@x.com",
			Expires: now.AddDate(0, 1, 0),
		},
		// expired
		{
			CheckID: "b", ResourceID: "x",
			Reason: "a long enough reason for the audit", Approver: "alice@x.com",
			Expires: now.AddDate(0, -1, 0),
		},
	}
	list, errs := NewWaiverList(entries, now)
	if len(errs) != 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	if len(list.Active) != 1 || list.Active[0].CheckID != "a" {
		t.Errorf("Active = %+v", list.Active)
	}
	if len(list.Expired) != 1 || list.Expired[0].CheckID != "b" {
		t.Errorf("Expired = %+v", list.Expired)
	}
}

func TestNewWaiverList_DuplicateRejected(t *testing.T) {
	now := fixedNow()
	w := validWaiver()
	_, errs := NewWaiverList([]Waiver{w, w}, now)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "duplicates") {
		t.Errorf("expected duplicate error; got %v", errs)
	}
}

func TestNewWaiverList_InvalidEntryBundled(t *testing.T) {
	now := fixedNow()
	good := validWaiver()
	bad := validWaiver()
	bad.CheckID = "y"
	bad.ResourceID = "y"
	bad.Approver = ""
	list, errs := NewWaiverList([]Waiver{good, bad}, now)
	if len(errs) != 1 {
		t.Fatalf("expected exactly 1 error, got %d: %v", len(errs), errs)
	}
	if len(list.Active) != 1 {
		t.Errorf("the valid waiver should still load even when a sibling errors")
	}
}

func TestCounts_ExpiringSoon(t *testing.T) {
	now := fixedNow()
	entries := []Waiver{
		// active, expires in 10 days → counts as expiring-soon
		{CheckID: "a", ResourceID: "x", Reason: "a long enough reason for the audit",
			Approver: "alice@x.com", Expires: now.AddDate(0, 0, 10)},
		// active, expires in 90 days → NOT expiring soon
		{CheckID: "b", ResourceID: "x", Reason: "a long enough reason for the audit",
			Approver: "alice@x.com", Expires: now.AddDate(0, 0, 90)},
		// expired → counts as expired, not expiring-soon
		{CheckID: "c", ResourceID: "x", Reason: "a long enough reason for the audit",
			Approver: "alice@x.com", Expires: now.AddDate(0, 0, -5)},
	}
	list, _ := NewWaiverList(entries, now)
	active, expired, expiring := list.Counts(now)
	if active != 2 || expired != 1 || expiring != 1 {
		t.Errorf("Counts = (active=%d, expired=%d, expiring=%d), want (2, 1, 1)",
			active, expired, expiring)
	}
}

func TestToRef_LiftsAllFields(t *testing.T) {
	w := validWaiver()
	w.Source = "file"
	w.SourcePath = "waivers.yaml"
	ref := w.ToRef()
	if ref == nil ||
		ref.CheckID != w.CheckID ||
		ref.ResourceID != w.ResourceID ||
		ref.Reason != w.Reason ||
		ref.Approver != w.Approver ||
		!ref.Expires.Equal(w.Expires) ||
		ref.Source != w.Source ||
		ref.SourcePath != w.SourcePath {
		t.Errorf("ToRef mismatch: %+v vs %+v", ref, w)
	}
}
