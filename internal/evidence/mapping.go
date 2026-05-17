package evidence

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/frameworks"
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
//
// v0.12 added the framework_name, control_family, control_tags,
// tailored, and tailoring_justification columns. Insertion is
// additive at the end of the row so v0.4-era CSV consumers reading
// by column name continue to work.
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
	// v0.12 additions:
	"framework_name",          // human-readable framework name
	"control_family",          // NIST family (AC/AU/...), CIS Control short slug, etc.
	"control_tags",            // CIS IG level / HIPAA required-or-addressable / ATT&CK tactic IDs (semicolon-separated)
	"tailored",                // "true" if operator scoped this control out
	"tailoring_justification", // operator's reason; empty when not tailored
	// v0.13 additions:
	"finding_source", // "native" | "ingest" — where the finding came from
	"finding_tool",   // populated for ingest findings (e.g. "trivy", "aws-security-hub"); empty for native
	// v0.18 additions — waiver attribution (additive per ADR-013):
	"waiver_active",   // "true" when a waiver muted this finding (Finding.Waiver != nil); "false" otherwise
	"waiver_reason",   // operator's justification from the matching waiver; empty when not waived
	"waiver_approver", // who signed off; empty when not waived
	"waiver_expires",  // YYYY-MM-DD; empty when not waived
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
func writeMappingCSV(outDir string, controls []ControlRef, tailoring *frameworks.Tailoring) (string, error) {
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

	// Resolve framework + control metadata once per (fwID, ctrlID)
	// pair instead of re-resolving on every row.
	all, err := frameworks.All()
	if err != nil {
		return "", fmt.Errorf("load frameworks: %w", err)
	}

	for _, c := range controls {
		evidenceRel := fmt.Sprintf("%s/%s/findings.json", c.FrameworkID, c.DirName)
		fwName, family, tagsCSV := resolveControlMeta(all, c.FrameworkID, c.ControlID)
		tailored := "false"
		justification := ""
		if just, ok := tailoring.Lookup(c.FrameworkID, c.ControlID); ok {
			tailored = "true"
			justification = just
		}
		for _, fnd := range c.Findings {
			title := ""
			if chk, ok := core.LookupCheck(fnd.CheckID); ok {
				title = chk.Title
			}
			sourceType, sourceTool := sourceColumns(fnd)
			waiverActive, waiverReason, waiverApprover, waiverExpires := waiverColumns(fnd)
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
				fwName,
				family,
				tagsCSV,
				tailored,
				justification,
				sourceType,
				sourceTool,
				waiverActive,
				waiverReason,
				waiverApprover,
				waiverExpires,
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

// sourceColumns returns the (finding_source, finding_tool) values
// for the control-mapping.csv row. A nil Source or Type=="native"
// (or empty) maps to ("native", ""); ingest findings carry through
// their Source.Type + Source.Tool. v0.13+.
func sourceColumns(f core.Finding) (sourceType, sourceTool string) {
	if f.Source == nil || f.Source.Type == "" || f.Source.Type == "native" {
		return "native", ""
	}
	return f.Source.Type, f.Source.Tool
}

// waiverColumns returns the (active, reason, approver, expires)
// values for the v0.18 waiver attribution columns. Nil Waiver →
// all empty + active="false". Populated Waiver → all four fields
// rendered for the audit trail.
//
// Per ADR-013 the waiver block is visible in the evidence pack —
// the auditor sees the acknowledgement plus the reason + approver
// rather than the finding silently disappearing.
func waiverColumns(f core.Finding) (active, reason, approver, expires string) {
	if f.Waiver == nil {
		return "false", "", "", ""
	}
	expiresStr := ""
	if !f.Waiver.Expires.IsZero() {
		expiresStr = f.Waiver.Expires.Format("2006-01-02")
	}
	return "true", f.Waiver.Reason, f.Waiver.Approver, expiresStr
}

// resolveControlMeta looks up the framework and control to surface
// human-readable + machine-friendly metadata in the mapping CSV.
// Empty strings when the framework/control is unknown, matching the
// existing silent-skip semantics elsewhere in the package.
func resolveControlMeta(all map[string]*frameworks.Framework, fwID, ctrlID string) (fwName, family, tagsCSV string) {
	fw, ok := all[fwID]
	if !ok {
		return
	}
	fwName = fw.Name
	ctrl, ok := fw.Controls[ctrlID]
	if !ok {
		return
	}
	family = ctrl.Family
	if len(ctrl.Tags) > 0 {
		tagsCSV = strings.Join(ctrl.Tags, ";")
	}
	return
}
