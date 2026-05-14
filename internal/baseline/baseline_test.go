package baseline

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
)

func mkFinding(checkID, resID string, status core.Status, sev core.Severity) core.Finding {
	return core.Finding{
		CheckID:  checkID,
		Status:   status,
		Severity: sev,
		Resource: core.ResourceRef{
			ID:       resID,
			Type:     "digitalocean.droplet",
			Name:     resID,
			Provider: "digitalocean",
		},
	}
}

func TestCapture_DeduplicatesByFingerprint(t *testing.T) {
	f := mkFinding("do-droplet-no-firewall", "droplet-1", core.StatusFail, core.SeverityHigh)
	b := Capture([]core.Finding{f, f, f}, time.Date(2026, 5, 14, 0, 0, 0, 0, time.UTC))
	if len(b.Entries) != 1 {
		t.Errorf("dedup failed: got %d entries, want 1", len(b.Entries))
	}
}

func TestCapture_DeterministicOrdering(t *testing.T) {
	in := []core.Finding{
		mkFinding("zzz-check", "droplet-9", core.StatusPass, core.SeverityLow),
		mkFinding("aaa-check", "droplet-1", core.StatusFail, core.SeverityHigh),
		mkFinding("mmm-check", "droplet-5", core.StatusSkip, core.SeverityMedium),
	}
	b1 := Capture(in, time.Now())
	b2 := Capture(in, time.Now())
	if len(b1.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(b1.Entries))
	}
	for i := range b1.Entries {
		if b1.Entries[i].Fingerprint != b2.Entries[i].Fingerprint {
			t.Errorf("nondeterministic ordering at %d", i)
		}
	}
	// Sorted by fingerprint
	for i := 1; i < len(b1.Entries); i++ {
		if b1.Entries[i-1].Fingerprint > b1.Entries[i].Fingerprint {
			t.Errorf("entries not sorted: %s > %s", b1.Entries[i-1].Fingerprint, b1.Entries[i].Fingerprint)
		}
	}
}

func TestCapture_ScoreCarried(t *testing.T) {
	in := []core.Finding{
		mkFinding("a", "r1", core.StatusPass, core.SeverityHigh),
		mkFinding("b", "r2", core.StatusFail, core.SeverityHigh),
	}
	b := Capture(in, time.Now())
	if b.Score != 50 {
		t.Errorf("score 50 expected, got %d", b.Score)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".compliancekit", "baseline.json")

	want := Capture([]core.Finding{
		mkFinding("do-droplet-no-firewall", "droplet-1", core.StatusFail, core.SeverityHigh),
		mkFinding("linux-sshd-no-root-login", "host-1", core.StatusPass, core.SeverityHigh),
	}, time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC))

	if err := Save(want, path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got.Schema != SchemaVersion {
		t.Errorf("schema mismatch: %s", got.Schema)
	}
	if got.Score != want.Score {
		t.Errorf("score: %d vs %d", got.Score, want.Score)
	}
	if len(got.Entries) != len(want.Entries) {
		t.Errorf("entries: %d vs %d", len(got.Entries), len(want.Entries))
	}
	for i := range want.Entries {
		if got.Entries[i] != want.Entries[i] {
			t.Errorf("entry %d: %+v vs %+v", i, got.Entries[i], want.Entries[i])
		}
	}
}

func TestParse_RejectsUnknownSchema(t *testing.T) {
	bad := []byte(`{"schema":"compliancekit.baseline.v9999","entries":[]}`)
	_, err := Parse(bad)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("expected schema rejection, got: %v", err)
	}
}

func TestSave_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deeply", "nested", "baseline.json")
	b := Capture(nil, time.Now())
	if err := Save(b, path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("baseline not written: %v", err)
	}
}

func TestFingerprintSet(t *testing.T) {
	b := Capture([]core.Finding{
		mkFinding("a", "r1", core.StatusFail, core.SeverityHigh),
		mkFinding("b", "r2", core.StatusPass, core.SeverityLow),
	}, time.Now())
	set := b.FingerprintSet()
	if len(set) != 2 {
		t.Errorf("set size: %d, want 2", len(set))
	}
	for _, e := range b.Entries {
		if got, ok := set[e.Fingerprint]; !ok || got.Fingerprint != e.Fingerprint {
			t.Errorf("entry %s missing from set", e.Fingerprint)
		}
	}
}

func TestWriteJSON_Pretty(t *testing.T) {
	b := Capture([]core.Finding{
		mkFinding("a", "r1", core.StatusFail, core.SeverityHigh),
	}, time.Date(2026, 5, 14, 0, 0, 0, 0, time.UTC))
	var buf bytes.Buffer
	if err := WriteJSON(b, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"schema": "compliancekit.baseline.v1"`) {
		t.Errorf("schema field missing or not pretty: %s", out)
	}
	if !strings.Contains(out, "\n  ") {
		t.Errorf("output not indented: %s", out)
	}
}
