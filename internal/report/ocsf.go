package report

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
)

// FormatOCSF is the lowercase identifier matching ROADMAP.md /
// CONFIGURATION.md naming. The hyphen distinguishes it from the plain
// "json" reporter, which uses our own envelope.
const FormatOCSF = "json-ocsf"

// OCSF taxonomy values we emit. OCSF is versioned independently of our
// schema; pin once so a SIEM team knows exactly which spec to validate
// against when ingesting our output.
//
// Reference: https://schema.ocsf.io/1.5.0/classes/compliance_finding
const (
	ocsfVersion                     = "1.5.0"
	ocsfCategoryFinding             = 2      // Findings
	ocsfClassComplianceFinding      = 2003   // Compliance Finding
	ocsfTypeComplianceFindingCreate = 200301 // Compliance Finding: Create
	ocsfActivityCreate              = 1      // Create

	ocsfProductName       = "compliancekit"
	ocsfProductVendorName = "darpanzope"
)

// OCSFReporter renders findings as a JSON array of OCSF 1.5
// Compliance Finding events, one per finding.
//
// OCSF is the AWS/Splunk-backed cybersecurity event interchange
// format; major SIEMs (Splunk Enterprise Security, Sentinel via
// connector, Elastic) ingest it natively. This is the "machine
// downstream" output: humans read JSON or HTML; SOC tooling reads
// OCSF.
//
// Per ADR-003, OCSF lands at v0.3 -- adding it post-hoc would force
// existing consumers to migrate.
type OCSFReporter struct{}

// NewOCSF returns an OCSF reporter.
func NewOCSF() *OCSFReporter { return &OCSFReporter{} }

// Format implements core.Reporter.
func (r *OCSFReporter) Format() string { return FormatOCSF }

// Render implements core.Reporter. Emits a JSON array of events --
// not NDJSON, which would be preferred for streaming but is awkward
// for a file-on-disk reporter. SIEMs typically configure either
// "JSON array" or "JSON Lines" ingestion; the array form is more
// commonly compatible.
//
// All findings (any status) are emitted. SIEM use cases include
// dashboarding pass rates and trend analysis, which need the full
// set -- unlike SARIF, where only actionable findings make sense.
func (r *OCSFReporter) Render(_ context.Context, findings []core.Finding, _ *core.ResourceGraph, w io.Writer) error {
	events := make([]ocsfEvent, 0, len(findings))
	for _, f := range findings {
		events = append(events, findingToOCSFEvent(f))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(events)
}

func findingToOCSFEvent(f core.Finding) ocsfEvent {
	when := f.Timestamp
	if when.IsZero() {
		when = time.Now().UTC()
	}
	sevID, sevName := ocsfSeverityFor(f.Severity)
	statusID, statusName := ocsfStatusFor(f.Status)

	return ocsfEvent{
		Metadata: ocsfMetadata{
			Version: ocsfVersion,
			Product: ocsfProduct{
				Name:       ocsfProductName,
				VendorName: ocsfProductVendorName,
			},
		},
		CategoryUID: ocsfCategoryFinding,
		ClassUID:    ocsfClassComplianceFinding,
		TypeUID:     ocsfTypeComplianceFindingCreate,
		ActivityID:  ocsfActivityCreate,
		SeverityID:  sevID,
		Severity:    sevName,
		StatusID:    statusID,
		Status:      statusName,
		// OCSF time is Unix milliseconds.
		Time:    when.UnixMilli(),
		Message: f.Message,
		Compliance: ocsfCompliance{
			Control:  f.CheckID,
			StatusID: statusID,
			Status:   statusName,
		},
		Resources: []ocsfResource{
			{
				Name: f.Resource.Name,
				Type: f.Resource.Type,
				UID:  f.Resource.ID,
			},
		},
	}
}

// ocsfSeverityFor maps our severity enum to OCSF's severity_id /
// severity string pair.
//
// OCSF severity_id values (1.5.0):
//
//	0  Unknown        1  Informational   2  Low
//	3  Medium         4  High            5  Critical
//	6  Fatal          99 Other
//
// We do not emit Fatal -- it would require human-life implications
// per the spec.
func ocsfSeverityFor(sev core.Severity) (id int, label string) {
	switch sev {
	case core.SeverityInfo:
		return 1, "Informational"
	case core.SeverityLow:
		return 2, "Low"
	case core.SeverityMedium:
		return 3, "Medium"
	case core.SeverityHigh:
		return 4, "High"
	case core.SeverityCritical:
		return 5, "Critical"
	default:
		return 0, "Unknown"
	}
}

// ocsfStatusFor maps our Status to OCSF Compliance Finding status_id /
// status string. OCSF 1.5 Compliance Finding status enum:
//
//	0  Unknown   1  Pass   2  Failure   99 Other
//
// We collapse Skip and Error into Other so the SIEM can still
// classify them without inventing a new enum value.
func ocsfStatusFor(s core.Status) (id int, label string) {
	switch s {
	case core.StatusPass:
		return 1, "Pass"
	case core.StatusFail:
		return 2, "Failure"
	default:
		return 99, "Other"
	}
}

// OCSF schema types (subset of 1.5 Compliance Finding).

type ocsfEvent struct {
	Metadata    ocsfMetadata   `json:"metadata"`
	CategoryUID int            `json:"category_uid"`
	ClassUID    int            `json:"class_uid"`
	TypeUID     int            `json:"type_uid"`
	ActivityID  int            `json:"activity_id"`
	SeverityID  int            `json:"severity_id"`
	Severity    string         `json:"severity"`
	StatusID    int            `json:"status_id"`
	Status      string         `json:"status"`
	Time        int64          `json:"time"`
	Message     string         `json:"message,omitempty"`
	Compliance  ocsfCompliance `json:"compliance"`
	Resources   []ocsfResource `json:"resources,omitempty"`
}

type ocsfMetadata struct {
	Version string      `json:"version"`
	Product ocsfProduct `json:"product"`
}

type ocsfProduct struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
}

type ocsfCompliance struct {
	Control  string `json:"control"`
	StatusID int    `json:"status_id"`
	Status   string `json:"status"`
}

type ocsfResource struct {
	Name string `json:"name"`
	Type string `json:"type"`
	UID  string `json:"uid"`
}
