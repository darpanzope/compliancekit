package evidence

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/frameworks"
)

// vulnCSVName is the filename written into the evidence pack root.
const vulnCSVName = "vulnerabilities.csv"

// writeOSCALAndVulnArtifacts groups the v0.13+ OSCAL writers and
// the v0.14+ vulnerabilities.csv writer behind one entrypoint so
// Generate stays under gocyclo:15. Each writer's path lands on
// the Result struct; FilesWritten is bumped per produced file.
func writeOSCALAndVulnArtifacts(abs string, findings []core.Finding, result *Result, opts Options) error {
	oscalARPath, err := writeAssessmentResultsOSCAL(abs, findings, opts)
	if err != nil {
		return err
	}
	result.OSCALARPath = oscalARPath
	result.FilesWritten++

	oscalProfilePath, err := writeProfileOSCAL(abs, result, opts)
	if err != nil {
		return err
	}
	result.OSCALProfilePath = oscalProfilePath
	result.FilesWritten++

	vulnPath, err := writeVulnerabilitiesCSV(abs, findings)
	if err != nil {
		return err
	}
	if vulnPath != "" {
		result.VulnerabilitiesPath = vulnPath
		result.FilesWritten++
	}

	waiverPath, err := writeWaiversJSON(abs, findings)
	if err != nil {
		return err
	}
	if waiverPath != "" {
		result.WaiversPath = waiverPath
		result.FilesWritten++
	}
	return nil
}

// vulnColumns is the header row of vulnerabilities.csv. Stable
// across pack-schema v1 (v0.14 introduces the file).
var vulnColumns = []string{
	"cve_id",
	"severity",
	"cvss_score",
	"cvss_vector",
	"package_name",
	"package_version",
	"package_ecosystem",
	"package_purl",
	"fixed_version",
	"image",
	"resource_id",
	"resource_type",
	"resource_name",
	"frameworks", // semicolon-separated "framework:control" pairs
	"source_tool",
	"source_tool_version",
	"primary_url",
	"published_date",
}

// writeVulnerabilitiesCSV emits <out>/vulnerabilities.csv with one
// row per (CVE, resource) pair drawn from findings whose
// core.Finding.Vulnerability block is populated. v0.14+.
//
// The file complements control-mapping.csv (which is one row per
// (control, finding) and covers posture findings + ingested
// non-vuln findings too). vulnerabilities.csv is the auditor's
// "what CVEs exist on what resources" pivot — directly importable
// into vuln-mgmt tools (Snyk, Tenable, Defender) and into the
// GRC layer's risk register.
//
// Returns the absolute path of the written file, or "" + nil error
// when zero findings carry a Vulnerability block (no file written).
func writeVulnerabilitiesCSV(outDir string, findings []core.Finding) (string, error) {
	rows := collectVulnRows(findings)
	if len(rows) == 0 {
		return "", nil
	}

	path := filepath.Join(outDir, vulnCSVName)
	//nolint:gosec // outDir is operator-controlled pack root
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", path, err)
	}

	w := csv.NewWriter(f)
	if err := w.Write(vulnColumns); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write header: %w", err)
	}
	for _, row := range rows {
		if err := w.Write(row); err != nil {
			_ = f.Close()
			return "", fmt.Errorf("write row: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("flush: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close: %w", err)
	}
	abs, _ := filepath.Abs(path)
	return abs, nil
}

// collectVulnRows builds the CSV row matrix from the findings that
// carry a Vulnerability block. One row per (Finding, resolved
// framework) — the same CVE appears multiple times when it maps to
// multiple frameworks, mirroring control-mapping.csv's shape.
func collectVulnRows(findings []core.Finding) [][]string {
	rows := make([][]string, 0, len(findings))
	for _, f := range findings {
		if f.Vulnerability == nil {
			continue
		}
		frameworksStr := framewroksForCheck(f.CheckID)
		v := f.Vulnerability
		rows = append(rows, []string{
			v.ID,
			f.Severity.String(),
			formatCVSS(v.CVSSScore),
			v.CVSSVector,
			v.Package.Name,
			v.Package.Version,
			v.Package.Ecosystem,
			v.Package.PURL,
			v.FixedVersion,
			v.Image,
			f.Resource.ID,
			f.Resource.Type,
			f.Resource.Name,
			frameworksStr,
			sourceTool(f),
			sourceToolVersion(f),
			v.PrimaryURL,
			v.PublishedDate,
		})
	}
	return rows
}

// framewroksForCheck assembles a semicolon-separated list of
// "framework:control" pairs the originating check maps to. Empty for
// ingested checks not in the native registry.
func framewroksForCheck(checkID string) string {
	check, ok := core.LookupCheck(checkID)
	if !ok {
		return ""
	}
	resolved := frameworks.ResolveCheckControls(check.Frameworks)
	parts := make([]string, 0, len(resolved))
	for _, rc := range resolved {
		parts = append(parts, rc.Framework.ID+":"+rc.Control.ID)
	}
	return strings.Join(parts, ";")
}

func formatCVSS(s float64) string {
	if s == 0 {
		return ""
	}
	return strconv.FormatFloat(s, 'f', 1, 64)
}

func sourceTool(f core.Finding) string {
	if f.Source == nil {
		return ""
	}
	return f.Source.Tool
}

func sourceToolVersion(f core.Finding) string {
	if f.Source == nil {
		return ""
	}
	return f.Source.ToolVersion
}
