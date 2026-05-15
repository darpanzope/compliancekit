package evidence

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
)

func TestWriteVulnerabilitiesCSV(t *testing.T) {
	dir := t.TempDir()
	findings := []core.Finding{
		{
			CheckID:  "ingest.trivy.CVE-2024-12345",
			Status:   core.StatusFail,
			Severity: core.SeverityHigh,
			Resource: core.ResourceRef{
				ID:   "container-image://abc123",
				Type: "container.image",
				Name: "alpine:3.18.0",
			},
			Vulnerability: &core.Vulnerability{
				ID:           "CVE-2024-12345",
				CVSSScore:    8.1,
				CVSSVector:   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
				FixedVersion: "3.0.8",
				Image:        "alpine:3.18.0",
				PrimaryURL:   "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
				Package: core.Package{
					Name:      "openssl",
					Version:   "3.0.7",
					Ecosystem: "apk",
					PURL:      "pkg:apk/alpine/openssl@3.0.7",
				},
			},
			Source: &core.Source{
				Type:        "ingest",
				Tool:        "trivy",
				ToolVersion: "v0.50.4",
				Format:      "trivy-json",
			},
		},
		// A non-vuln finding shouldn't appear.
		{
			CheckID:  "do.spaces.public-read",
			Status:   core.StatusFail,
			Severity: core.SeverityHigh,
		},
	}

	path, err := writeVulnerabilitiesCSV(dir, findings)
	if err != nil {
		t.Fatalf("writeVulnerabilitiesCSV: %v", err)
	}
	if !strings.HasSuffix(path, "vulnerabilities.csv") {
		t.Fatalf("path = %q", path)
	}

	body, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	reader := csv.NewReader(strings.NewReader(string(body)))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v", err)
	}
	// Header + 1 row (the CVE; non-vuln finding excluded).
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2 (header + 1 data row)", len(records))
	}
	row := records[1]
	wantCols := map[int]string{
		0:  "CVE-2024-12345",
		1:  "high",
		2:  "8.1",
		4:  "openssl",
		5:  "3.0.7",
		6:  "apk",
		7:  "pkg:apk/alpine/openssl@3.0.7",
		8:  "3.0.8",
		9:  "alpine:3.18.0",
		10: "container-image://abc123",
		11: "container.image",
		14: "trivy",
		15: "v0.50.4",
		16: "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
	}
	for idx, want := range wantCols {
		if row[idx] != want {
			t.Errorf("row[%d] = %q, want %q", idx, row[idx], want)
		}
	}
}

func TestWriteVulnerabilitiesCSV_NoVulnFindings(t *testing.T) {
	dir := t.TempDir()
	findings := []core.Finding{
		{CheckID: "do.spaces.public-read", Status: core.StatusFail, Severity: core.SeverityHigh},
	}
	path, err := writeVulnerabilitiesCSV(dir, findings)
	if err != nil {
		t.Fatalf("writeVulnerabilitiesCSV: %v", err)
	}
	if path != "" {
		t.Errorf("path = %q, want empty (no CVE findings means no file)", path)
	}
	// Confirm no file was created.
	if _, err := os.Stat(filepath.Join(dir, "vulnerabilities.csv")); !os.IsNotExist(err) {
		t.Errorf("vulnerabilities.csv exists despite zero CVE findings: %v", err)
	}
}

func TestFormatCVSS(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, ""},
		{8.1, "8.1"},
		{7.5, "7.5"},
		{10, "10.0"},
	}
	for _, c := range cases {
		if got := formatCVSS(c.in); got != c.want {
			t.Errorf("formatCVSS(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
