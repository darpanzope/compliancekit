package core

import "testing"

// The fingerprint is the contract between scans and the diff engine.
// These tests pin down exactly which fields participate.

func TestFinding_FingerprintStableAcrossSeverityAndMessage(t *testing.T) {
	a := Finding{
		CheckID:  "do-spaces-public-acl",
		Resource: ResourceRef{ID: "do.bucket.1"},
		Status:   StatusFail,
		Severity: SeverityHigh,
		Message:  "bucket public",
	}
	b := Finding{
		CheckID:  "do-spaces-public-acl",
		Resource: ResourceRef{ID: "do.bucket.1"},
		Status:   StatusFail,
		Severity: SeverityCritical,    // changed
		Message:  "very public bucket", // changed
	}
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("fingerprint must be stable across severity and message changes")
	}
}

func TestFinding_FingerprintChangesWithStatus(t *testing.T) {
	base := Finding{
		CheckID:  "do-spaces-public-acl",
		Resource: ResourceRef{ID: "do.bucket.1"},
		Status:   StatusFail,
	}
	resolved := base
	resolved.Status = StatusPass

	if base.Fingerprint() == resolved.Fingerprint() {
		t.Error("fingerprint must differ when status changes")
	}
}

func TestFinding_FingerprintChangesWithResource(t *testing.T) {
	base := Finding{
		CheckID:  "do-spaces-public-acl",
		Resource: ResourceRef{ID: "do.bucket.1"},
		Status:   StatusFail,
	}
	other := base
	other.Resource.ID = "do.bucket.2"

	if base.Fingerprint() == other.Fingerprint() {
		t.Error("fingerprint must differ when resource ID changes")
	}
}

func TestFinding_FingerprintChangesWithCheckID(t *testing.T) {
	base := Finding{
		CheckID:  "do-spaces-public-acl",
		Resource: ResourceRef{ID: "do.bucket.1"},
		Status:   StatusFail,
	}
	other := base
	other.CheckID = "do-spaces-no-cdn"

	if base.Fingerprint() == other.Fingerprint() {
		t.Error("fingerprint must differ when check ID changes")
	}
}

func TestFinding_FingerprintIsHex(t *testing.T) {
	f := Finding{
		CheckID:  "do-spaces-public-acl",
		Resource: ResourceRef{ID: "do.bucket.1"},
		Status:   StatusFail,
	}
	fp := f.Fingerprint()
	if len(fp) != 64 {
		t.Errorf("fingerprint length = %d, want 64 (sha256 hex)", len(fp))
	}
	for _, r := range fp {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Errorf("fingerprint contains non-hex char %q", r)
			break
		}
	}
}
