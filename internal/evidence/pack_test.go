package evidence

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	// Side-effect imports populate the check registry so groupByControl
	// can resolve CheckID -> Frameworks. Mirrors cmd/compliancekit/main.go.
	_ "github.com/darpanzope/compliancekit/internal/checks/digitalocean"
	_ "github.com/darpanzope/compliancekit/internal/checks/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

// helper finding with real check IDs so the registry can resolve
// framework mappings.
func mkFinding(checkID, resourceID string, status core.Status, sev core.Severity) core.Finding {
	return core.Finding{
		CheckID:  checkID,
		Status:   status,
		Severity: sev,
		Resource: core.ResourceRef{
			ID:       resourceID,
			Type:     "digitalocean.droplet",
			Name:     resourceID,
			Provider: "digitalocean",
		},
		Message:   fmt.Sprintf("synthetic finding for %s", checkID),
		Timestamp: time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC),
	}
}

func TestGenerate_ProducesExpectedLayout(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "pack")

	findings := []core.Finding{
		// Maps to soc2/CC6.6 + iso27001/A.8.21 + cis-v8/4.4 + 12.2
		mkFinding("do-droplet-no-firewall", "droplet-1", core.StatusFail, core.SeverityHigh),
		// Same control bucket (CC6.6) plus another control set
		mkFinding("do-droplet-backups-disabled", "droplet-2", core.StatusFail, core.SeverityMedium),
	}

	res, err := Generate(context.Background(), findings, Options{
		OutDir:    out,
		Period:    "2026-Q2",
		Generated: time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if res.OutDir == "" || res.ManifestPath == "" {
		t.Fatalf("result has empty OutDir or ManifestPath: %+v", res)
	}

	// Expect at least one directory per framework that the checks
	// reference.
	for _, fw := range []string{"soc2", "iso27001", "cis-v8"} {
		if _, err := os.Stat(filepath.Join(out, fw)); err != nil {
			t.Errorf("missing framework dir %s: %v", fw, err)
		}
	}

	// Manifest at the root.
	if _, err := os.Stat(res.ManifestPath); err != nil {
		t.Errorf("manifest missing: %v", err)
	}

	// Framework rollup should include soc2 + iso27001 + cis-v8.
	gotFW := map[string]bool{}
	for _, fr := range res.FrameworkResults {
		gotFW[fr.FrameworkID] = true
		if fr.ControlsCovered == 0 {
			t.Errorf("framework %s: ControlsCovered=0", fr.FrameworkID)
		}
	}
	for _, want := range []string{"soc2", "iso27001", "cis-v8"} {
		if !gotFW[want] {
			t.Errorf("framework %s missing from FrameworkResults", want)
		}
	}
}

func TestGenerate_RefusesNonEmptyDir(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "pack")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "stale.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Generate(context.Background(), nil, Options{OutDir: out})
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("expected 'not empty' error, got: %v", err)
	}
}

func TestGenerate_EmptyOutDirErrors(t *testing.T) {
	_, err := Generate(context.Background(), nil, Options{})
	if err == nil {
		t.Error("expected error for empty OutDir")
	}
}

func TestGenerate_ManifestCoversAllFiles(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "pack")

	findings := []core.Finding{
		mkFinding("do-droplet-no-firewall", "droplet-1", core.StatusFail, core.SeverityHigh),
	}

	res, err := Generate(context.Background(), findings, Options{
		OutDir:    out,
		Generated: time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Re-walk and confirm every non-manifest file appears in the
	// manifest with a matching hash.
	want := map[string]string{}
	err = filepath.WalkDir(res.OutDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Base(path) == "MANIFEST.sha256" {
			return nil
		}
		// G304: path comes from a TempDir we control.
		//nolint:gosec
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		rel, err := filepath.Rel(res.OutDir, path)
		if err != nil {
			return err
		}
		want[filepath.ToSlash(rel)] = fmt.Sprintf("%x", h.Sum(nil))
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(want) == 0 {
		t.Fatal("no files to check; pack is empty")
	}

	// Parse the manifest.
	// G304: ManifestPath is from our TempDir.
	//nolint:gosec
	mf, err := os.Open(res.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	defer mf.Close()
	got := map[string]string{}
	scanner := bufio.NewScanner(mf)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "  ", 2)
		if len(parts) != 2 {
			t.Fatalf("bad manifest line: %q", scanner.Text())
		}
		got[parts[1]] = parts[0]
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	if len(got) != len(want) {
		t.Fatalf("manifest line count %d != file count %d", len(got), len(want))
	}
	for path, hash := range want {
		if got[path] != hash {
			t.Errorf("manifest mismatch for %s: got %s want %s", path, got[path], hash)
		}
	}
}

func TestGenerate_FindingsJSONIsParseable(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "pack")

	findings := []core.Finding{
		mkFinding("do-droplet-no-firewall", "droplet-1", core.StatusFail, core.SeverityHigh),
	}
	if _, err := Generate(context.Background(), findings, Options{
		OutDir:    out,
		Generated: time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Find at least one findings.json and parse it.
	var found bool
	err := filepath.WalkDir(out, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || filepath.Base(path) != "findings.json" {
			return nil
		}
		// G304: path comes from a TempDir we control.
		//nolint:gosec
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var payload controlPayload
		if err := json.Unmarshal(data, &payload); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if payload.Schema != schemaVersion {
			t.Errorf("schema mismatch in %s: %s", path, payload.Schema)
		}
		if payload.FrameworkID == "" || payload.ControlID == "" {
			t.Errorf("missing framework/control IDs in %s", path)
		}
		if len(payload.Findings) == 0 {
			t.Errorf("no findings in %s", path)
		}
		found = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Error("no findings.json files written")
	}
}

func TestRedactString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"aws key", "key=AKIAIOSFODNN7EXAMPLE foo", "key=[REDACTED:aws-access-key] foo"},
		{"github pat", "token gh_pas_failure ghp_abcdefghijklmnopqrstuv done", "token gh_pas_failure [REDACTED:github-token] done"},
		{"bearer", "Authorization: Bearer eyJhbcdef.zzz", "Authorization: Bearer [REDACTED:bearer-token]"},
		{"email", "owner alice@example.com here", "owner [REDACTED:email]@example.com here"},
		{"plain text", "host 'db1' is fine", "host 'db1' is fine"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactString(tc.in)
			if got != tc.want {
				t.Errorf("redactString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSlugify(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Logical and Physical Access Controls", "logical-and-physical-access-controls"},
		{"  hello   world  ", "hello-world"},
		{"User Endpoint Devices", "user-endpoint-devices"},
		{"", "control"},
		{"!!!", "control"},
		// Long input gets truncated.
		{strings.Repeat("a", 100), strings.Repeat("a", 40)},
	}
	for _, c := range cases {
		got := slugify(c.in)
		if got != c.want {
			t.Errorf("slugify(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGenerate_WritesControlMarkdown(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "pack")

	findings := []core.Finding{
		mkFinding("do-droplet-no-firewall", "droplet-1", core.StatusFail, core.SeverityHigh),
		mkFinding("do-droplet-no-firewall", "droplet-2", core.StatusPass, core.SeverityHigh),
	}
	if _, err := Generate(context.Background(), findings, Options{
		OutDir:    out,
		Period:    "2026-Q2",
		Generated: time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Locate one control.md and validate its key sections.
	var md string
	err := filepath.WalkDir(out, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || filepath.Base(path) != "control.md" {
			return nil
		}
		// G304: TempDir.
		//nolint:gosec
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		md = string(data)
		return io.EOF // stop walking after first match
	})
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if md == "" {
		t.Fatal("no control.md found")
	}
	for _, want := range []string{
		"## Control statement",
		"## Coverage summary",
		"## Findings",
		"do-droplet-no-firewall",
		"Period:** 2026-Q2",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("control.md missing %q\n---\n%s", want, md)
		}
	}
}

func TestGenerate_WritesMappingCSV(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "pack")

	findings := []core.Finding{
		mkFinding("do-droplet-no-firewall", "droplet-1", core.StatusFail, core.SeverityHigh),
		mkFinding("do-droplet-no-firewall", "droplet-2", core.StatusFail, core.SeverityHigh),
	}
	res, err := Generate(context.Background(), findings, Options{
		OutDir:    out,
		Generated: time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if res.MappingCSVPath == "" {
		t.Fatal("MappingCSVPath empty")
	}

	// G304: TempDir.
	//nolint:gosec
	data, err := os.ReadFile(res.MappingCSVPath)
	if err != nil {
		t.Fatal(err)
	}
	r := csv.NewReader(strings.NewReader(string(data)))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if len(rows) < 2 {
		t.Fatalf("expected header + at least one row, got %d", len(rows))
	}
	wantHeader := []string{
		"framework_id", "control_id", "control_name",
		"check_id", "check_title",
		"resource_id", "resource_name", "resource_type",
		"account_id", "region",
		"status", "severity", "evidence_path",
	}
	for i, want := range wantHeader {
		if rows[0][i] != want {
			t.Errorf("header[%d] = %q, want %q", i, rows[0][i], want)
		}
	}

	// At least one row should reference our check and a real evidence path.
	// evidence_path is the last column (index 12 with account_id+region added).
	foundCheck := false
	for _, row := range rows[1:] {
		if row[3] == "do-droplet-no-firewall" {
			foundCheck = true
			if !strings.HasSuffix(row[12], "/findings.json") {
				t.Errorf("evidence_path malformed: %q", row[12])
			}
		}
	}
	if !foundCheck {
		t.Error("CSV missing rows for do-droplet-no-firewall")
	}
}

func TestGenerate_WritesSummaryHTML(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "pack")

	findings := []core.Finding{
		mkFinding("do-droplet-no-firewall", "droplet-1", core.StatusFail, core.SeverityHigh),
		mkFinding("do-droplet-no-firewall", "droplet-2", core.StatusPass, core.SeverityHigh),
	}
	res, err := Generate(context.Background(), findings, Options{
		OutDir:    out,
		Period:    "2026-Q2",
		Generated: time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if res.SummaryHTMLPath == "" {
		t.Fatal("SummaryHTMLPath empty")
	}
	// G304: TempDir.
	//nolint:gosec
	data, err := os.ReadFile(res.SummaryHTMLPath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	for _, want := range []string{
		"<!doctype html>",
		"compliancekit evidence pack",
		"Period: <strong>2026-Q2</strong>",
		"SOC 2 Trust Services Criteria",
		"ISO/IEC 27001:2022 Annex A",
		"control-mapping.csv",
		`href="soc2/`, // relative link to a control dir
	} {
		if !strings.Contains(body, want) {
			t.Errorf("summary.html missing %q", want)
		}
	}
}

func TestDefaultPeriod(t *testing.T) {
	cases := []struct {
		month time.Month
		want  string
	}{
		{time.January, "2026-Q1"},
		{time.March, "2026-Q1"},
		{time.April, "2026-Q2"},
		{time.July, "2026-Q3"},
		{time.December, "2026-Q4"},
	}
	for _, c := range cases {
		got := defaultPeriod(time.Date(2026, c.month, 1, 0, 0, 0, 0, time.UTC))
		if got != c.want {
			t.Errorf("defaultPeriod(month=%s) = %q, want %q", c.month, got, c.want)
		}
	}
}
