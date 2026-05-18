package report

import (
	"context"
	"encoding/json"
	"io"
	"strings"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// FormatSARIF is the lowercase identifier used in config / CLI.
const FormatSARIF = "sarif"

// sarifVersion matches the schema URI; CodeQL / GitHub Code Scanning
// validate against 2.1.0 today.
const (
	sarifVersion    = "2.1.0"
	sarifSchemaURI  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifToolDriver = "compliancekit"
	sarifToolURI    = "https://github.com/darpanzope/compliancekit"
)

// SARIFReporter renders findings as a SARIF 2.1.0 document for GitHub
// Code Scanning ingestion. The JSON-OCSF reporter at Phase 3 covers
// SIEMs; SARIF specifically targets the Security tab on GitHub plus
// any other code-scanning ingester that speaks the schema.
//
// Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
type SARIFReporter struct{}

// NewSARIF returns a SARIF reporter.
func NewSARIF() *SARIFReporter { return &SARIFReporter{} }

// Format implements compliancekit.Reporter.
func (r *SARIFReporter) Format() string { return FormatSARIF }

// Render implements compliancekit.Reporter. Emits a single-run SARIF document.
// Only actionable findings (Fail / Error) are emitted as results; the
// Code Scanning UI treats every emitted result as something needing
// action, so listing Pass would be noise.
//
// Every distinct check ID becomes a rule under tool.driver.rules,
// even when no result for that run cites it -- consistent rule sets
// make GitHub's "compare two runs" view more useful.
func (r *SARIFReporter) Render(_ context.Context, findings []compliancekit.Finding, _ *compliancekit.ResourceGraph, w io.Writer) error {
	rules := buildSARIFRules(findings)
	results := buildSARIFResults(findings, rules)

	doc := sarifLog{
		Schema:  sarifSchemaURI,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           sarifToolDriver,
						InformationURI: sarifToolURI,
						Rules:          rulesAsSlice(rules),
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// buildSARIFRules produces one rule per distinct check ID, regardless of
// status, so the rule set is stable as findings flap pass/fail across runs.
func buildSARIFRules(findings []compliancekit.Finding) map[string]sarifRule {
	out := map[string]sarifRule{}
	for _, f := range findings {
		if _, exists := out[f.CheckID]; exists {
			continue
		}
		out[f.CheckID] = sarifRule{
			ID: f.CheckID,
			ShortDescription: sarifText{
				Text: f.CheckID,
			},
			DefaultConfiguration: sarifConfig{
				Level: sarifLevelFor(f.Severity),
			},
			Properties: map[string]any{
				"severity": f.Severity.String(),
				"tags":     f.Tags,
			},
		}
	}
	return out
}

// buildSARIFResults converts actionable findings into SARIF result
// entries. Each result references the rule by index in tool.driver.rules
// (per the spec's preferred form) AND by ruleId (legacy form, which
// GitHub still accepts and some other ingesters require).
func buildSARIFResults(findings []compliancekit.Finding, rules map[string]sarifRule) []sarifResult {
	// Build a stable index for ruleIndex assignment: alphabetical by
	// ID matches the order we emit rules in rulesAsSlice.
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sortStrings(ids)
	idx := map[string]int{}
	for i, id := range ids {
		idx[id] = i
	}

	out := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		if !f.Status.IsActionable() {
			continue
		}
		out = append(out, sarifResult{
			RuleID:    f.CheckID,
			RuleIndex: idx[f.CheckID],
			Level:     sarifLevelFor(f.Severity),
			Message: sarifText{
				Text: messageOrDefault(f),
			},
			Locations: []sarifLocation{
				{
					LogicalLocations: []sarifLogicalLocation{
						{
							FullyQualifiedName: f.Resource.ID,
							Kind:               f.Resource.Type,
						},
					},
				},
			},
			Properties: enrichSARIFProps(f),
		})
	}
	return out
}

// enrichSARIFProps adds v0.14 Vulnerability + Secret fields onto the
// SARIF result.properties bag when those typed blocks are populated.
// Code Scanning surfaces "security-severity" specifically as a
// GitHub-recognized property; the rest are passthrough strings other
// SARIF consumers can filter on.
func enrichSARIFProps(f compliancekit.Finding) map[string]any {
	props := map[string]any{
		"status":        string(f.Status),
		"severity":      f.Severity.String(),
		"resource_name": f.Resource.Name,
		"resource_type": f.Resource.Type,
		"resource_id":   f.Resource.ID,
	}
	if v := f.Vulnerability; v != nil {
		props["cve_id"] = v.ID
		if v.CVSSScore > 0 {
			props["security-severity"] = v.CVSSScore // GitHub recognizes this
			props["cvss_score"] = v.CVSSScore
		}
		if v.CVSSVector != "" {
			props["cvss_vector"] = v.CVSSVector
		}
		if v.FixedVersion != "" {
			props["fixed_version"] = v.FixedVersion
		}
		if v.Package.PURL != "" {
			props["package_purl"] = v.Package.PURL
		}
		if v.Image != "" {
			props["image"] = v.Image
		}
	}
	if s := f.Secret; s != nil {
		props["secret_rule_id"] = s.RuleID
		props["secret_fingerprint"] = s.Fingerprint // already redacted
		if s.Author != "" {
			props["secret_author"] = s.Author
		}
	}
	return props
}

// rulesAsSlice converts the rule map to the alphabetical slice form
// SARIF expects (and that buildSARIFResults indexes against).
func rulesAsSlice(rules map[string]sarifRule) []sarifRule {
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sortStrings(ids)
	out := make([]sarifRule, 0, len(rules))
	for _, id := range ids {
		out = append(out, rules[id])
	}
	return out
}

// sarifLevelFor maps our severity enum to SARIF's level vocabulary.
// SARIF has four levels: none, note, warning, error. We collapse:
//
//	info, low      -> note
//	medium         -> warning
//	high, critical -> error
//
// "none" is for findings explicitly reported as informational with no
// associated action; we don't emit those from compliancekit.
func sarifLevelFor(sev compliancekit.Severity) string {
	switch sev {
	case compliancekit.SeverityCritical, compliancekit.SeverityHigh:
		return "error"
	case compliancekit.SeverityMedium:
		return "warning"
	case compliancekit.SeverityLow, compliancekit.SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}

// messageOrDefault falls back to a humane message when the check
// emitted no text (shouldn't happen, but defensive).
func messageOrDefault(f compliancekit.Finding) string {
	if msg := strings.TrimSpace(f.Message); msg != "" {
		return msg
	}
	return f.CheckID + " on " + f.Resource.Name + " (status: " + string(f.Status) + ", severity: " + f.Severity.String() + ")"
}

// Local sort to avoid pulling in another import path here; the
// standard library's sort.Strings would do the same thing.
func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j-1] > ss[j]; j-- {
			ss[j-1], ss[j] = ss[j], ss[j-1]
		}
	}
}

// SARIF schema types (subset).
// Reference: docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	ShortDescription     sarifText      `json:"shortDescription"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind,omitempty"`
}
