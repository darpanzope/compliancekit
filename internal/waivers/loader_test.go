package waivers

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadFile_Fixture(t *testing.T) {
	list, errs := LoadFile("testdata/waivers.yaml", fixedNow())
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	// All three fixture waivers expire after fixedNow (2026-05-17):
	// the two 2099-12-31 entries are active; the 2026-06-30 entry
	// is active too (just barely — it expires in ~6 weeks). So
	// Active=3, Expired=0.
	if len(list.Active) != 3 {
		t.Errorf("Active = %d, want 3 (all fixture entries still in effect)", len(list.Active))
	}
	if len(list.Expired) != 0 {
		t.Errorf("Expired = %d, want 0 (none of the fixture entries have lapsed)", len(list.Expired))
	}

	// Confirm SourcePath gets stamped.
	for _, w := range list.Active {
		if w.Source != "file" {
			t.Errorf("Source = %q, want file", w.Source)
		}
		if filepath.Base(w.SourcePath) != "waivers.yaml" {
			t.Errorf("SourcePath = %q, expected to end in waivers.yaml", w.SourcePath)
		}
	}
}

func TestLoadFile_MissingPathReturnsEmpty(t *testing.T) {
	list, errs := LoadFile("testdata/does-not-exist.yaml", fixedNow())
	if len(errs) != 0 {
		t.Errorf("missing file should not error: %v", errs)
	}
	if list == nil || len(list.Active) != 0 || len(list.Expired) != 0 {
		t.Errorf("missing file should return empty list, got %+v", list)
	}
}

func TestLoad_BadYAML(t *testing.T) {
	_, errs := Load([]byte("this is not yaml\n  - a:\n  bad: indent"), "inline", fixedNow())
	if len(errs) == 0 {
		t.Fatalf("expected parse error")
	}
	if !strings.Contains(errs[0].Error(), "parse") {
		t.Errorf("error should call out parse failure: %v", errs[0])
	}
}

func TestLoad_BadExpiryDate(t *testing.T) {
	body := []byte(`
waivers:
  - check_id: x
    resource_id: y
    reason: "a long enough reason for the audit"
    approver: alice@x.com
    expires: "not a date"
`)
	_, errs := Load(body, "inline", fixedNow())
	if len(errs) == 0 {
		t.Fatalf("expected parse error for bad date")
	}
	if !strings.Contains(errs[0].Error(), "expires") {
		t.Errorf("error should call out expires field: %v", errs[0])
	}
}

func TestLoad_BundlesValidationErrors(t *testing.T) {
	body := []byte(`
waivers:
  - check_id: good
    resource_id: x
    reason: "a long enough reason for the audit"
    approver: alice@x.com
    expires: 2099-12-31
  - check_id: bad-missing-approver
    resource_id: x
    reason: "a long enough reason for the audit"
    expires: 2099-12-31
`)
	list, errs := Load(body, "inline", fixedNow())
	if len(errs) != 1 {
		t.Fatalf("expected 1 validation error, got %d: %v", len(errs), errs)
	}
	if len(list.Active) != 1 {
		t.Errorf("good entry should still load; got %d active", len(list.Active))
	}
}

func TestParseExpiryDate_AcceptsBothFormats(t *testing.T) {
	cases := []struct {
		in   string
		want time.Time
	}{
		{"2026-12-31", time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)},
		{"2026-06-30T15:04:05Z", time.Date(2026, 6, 30, 15, 4, 5, 0, time.UTC)},
	}
	for _, c := range cases {
		got, err := parseExpiryDate(c.in)
		if err != nil {
			t.Errorf("parseExpiryDate(%q): %v", c.in, err)
			continue
		}
		if !got.Equal(c.want) {
			t.Errorf("parseExpiryDate(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseExpiryDate_Rejects(t *testing.T) {
	cases := []string{"", "12/31/2026", "today", "2026"}
	for _, c := range cases {
		if _, err := parseExpiryDate(c); err == nil {
			t.Errorf("parseExpiryDate(%q) should fail", c)
		}
	}
}
