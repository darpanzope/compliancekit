package evidence

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"

	"github.com/darpanzope/compliancekit/internal/core"
)

// mappingCSVName is the filename used for the control-mapping export
// at the pack root. The format and column order below are designed to
// be ingested directly by Drata, Vanta, and AuditBoard import
// templates (every published schema for these tools accepts the
// (framework, control, evidence) triple expressed as CSV columns).
const mappingCSVName = "control-mapping.csv"

// mappingColumns is the header row. Stable across pack-schema v1; a
// breaking change bumps schemaVersion (in pack.go) and the documented
// shape here. Listed explicitly so the writer cannot drift from the
// header even after refactoring.
var mappingColumns = []string{
	"framework_id",
	"control_id",
	"control_name",
	"check_id",
	"check_title",
	"resource_id",
	"resource_name",
	"resource_type",
	"account_id", // v0.7: AWS account / GCP project / Hetzner project
	"region",     // v0.7: AWS region / GCP location; empty for global resources
	"status",
	"severity",
	"evidence_path",
}

// writeMappingCSV emits <out>/control-mapping.csv with one row per
// (control, finding) pair drawn from the already-grouped ControlRef
// list. The same finding therefore appears in multiple rows when the
// originating check maps to multiple controls -- which is exactly what
// Drata/Vanta want: each control gets its own row so it can be
// independently checked off.
//
// evidence_path is the forward-slash relative path from the pack root
// to the control's findings.json. Auditors can follow that path
// directly inside the pack to see the underlying detail.
func writeMappingCSV(outDir string, controls []ControlRef) (string, error) {
	path := filepath.Join(outDir, mappingCSVName)
	// G304: outDir is the operator-controlled pack root.
	//nolint:gosec // operator-controlled output path
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write(mappingColumns); err != nil {
		return "", fmt.Errorf("write header: %w", err)
	}

	for _, c := range controls {
		evidenceRel := fmt.Sprintf("%s/%s/findings.json", c.FrameworkID, c.DirName)
		for _, fnd := range c.Findings {
			title := ""
			if chk, ok := core.LookupCheck(fnd.CheckID); ok {
				title = chk.Title
			}
			row := []string{
				c.FrameworkID,
				c.ControlID,
				c.ControlName,
				fnd.CheckID,
				title,
				fnd.Resource.ID,
				fnd.Resource.Name,
				fnd.Resource.Type,
				fnd.Resource.AccountID,
				fnd.Resource.Region,
				string(fnd.Status),
				fnd.Severity.String(),
				evidenceRel,
			}
			if err := w.Write(row); err != nil {
				return "", fmt.Errorf("write row: %w", err)
			}
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return "", fmt.Errorf("flush csv: %w", err)
	}
	return path, nil
}
