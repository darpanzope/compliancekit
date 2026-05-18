package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// OSCAL Assessment Results v1.1.2 schema constants. Pinned so a
// FedRAMP / consuming GRC tool knows exactly which validator profile
// to apply. The Compliance Finding shape from v1.0 onward is what we
// emit; newer minor versions add fields we leave omitted (back-matter,
// origins, related-tasks, …).
const (
	oscalVersion  = "1.1.2"
	oscalARSchema = "https://csrc.nist.gov/ns/oscal/1.0"

	// arFileName is the filename written into the evidence pack root.
	// `.oscal.json` is the convention OSCAL tooling expects so
	// validators auto-detect the schema family.
	arFileName = "assessment-results.oscal.json"
)

// writeAssessmentResultsOSCAL writes an OSCAL Assessment Results
// document derived from the scan's findings + tailoring. Lands as
// <pack>/assessment-results.oscal.json. Returns the absolute path
// of the written file.
//
// The document carries one Result block per scan run (compliancekit
// produces one scan per evidence pack). Every actionable finding —
// StatusFail / StatusError — becomes an OSCAL Finding entry inside
// that Result. Tailoring entries become OSCAL findings targeting
// the same control with a Type="objective-id" + an extension prop
// recording the justification, so an auditor consuming the AR sees
// the scope-out decisions alongside the in-scope findings.
//
// UUIDs are derived deterministically from content so two runs of
// the same findings produce byte-identical AR documents. Helps the
// diff engine and tamper-evident manifest stay coherent.
func writeAssessmentResultsOSCAL(root string, findings []compliancekit.Finding, opts Options) (string, error) {
	doc := buildAssessmentResults(findings, opts)

	path := filepath.Join(root, arFileName)
	f, err := os.Create(path) //nolint:gosec // root is operator-supplied evidence dir
	if err != nil {
		return "", fmt.Errorf("create %s: %w", path, err)
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("encode oscal-ar: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close %s: %w", path, err)
	}
	abs, _ := filepath.Abs(path)
	return abs, nil
}

func buildAssessmentResults(findings []compliancekit.Finding, opts Options) arDocument {
	generated := opts.Generated
	if generated.IsZero() {
		generated = time.Now().UTC()
	}

	docUUID := uuidFromContent("ar", generated.Format(time.RFC3339Nano), opts.Period)
	resultUUID := uuidFromContent("result", generated.Format(time.RFC3339Nano), opts.Period)

	arFindings := make([]arFinding, 0, len(findings))
	covered := map[string]bool{}

	for _, fnd := range findings {
		if !fnd.Status.IsActionable() {
			continue
		}
		for ctrlID := range controlIDsForFinding(fnd) {
			arFindings = append(arFindings, oscalFindingFor(fnd, ctrlID))
			covered[ctrlID] = true
		}
	}

	// Tailoring entries are appended as findings whose target is the
	// scoped-out control plus a "tailored" prop so auditors see every
	// scope-out decision with its justification.
	if opts.Tailoring != nil {
		for _, rule := range opts.Tailoring.Rules {
			ctrlID := rule.Framework + ":" + rule.Control
			arFindings = append(arFindings, arFinding{
				UUID:        uuidFromContent("tailored", rule.Framework, rule.Control),
				Title:       "Control scoped out of audit",
				Description: rule.Justification,
				Target: arTarget{
					Type:     "objective-id",
					TargetID: ctrlID,
				},
				Props: []arProp{
					{Name: "compliancekit-tailored", Value: "true"},
					{Name: "compliancekit-framework", Value: rule.Framework},
					{Name: "compliancekit-control", Value: rule.Control},
					{Name: "compliancekit-tailoring-justification", Value: rule.Justification},
				},
			})
			covered[ctrlID] = true
		}
	}

	included := includedControls(covered)

	return arDocument{
		AssessmentResults: arAssessmentResults{
			UUID: docUUID,
			Metadata: arMetadata{
				Title:        fmt.Sprintf("compliancekit assessment results — %s", periodOrDefault(opts.Period, generated)),
				LastModified: generated.UTC().Format(time.RFC3339),
				Version:      schemaVersion,
				OSCALVersion: oscalVersion,
			},
			Results: []arResult{
				{
					UUID:        resultUUID,
					Title:       fmt.Sprintf("compliancekit scan — %s", periodOrDefault(opts.Period, generated)),
					Description: "Automated assessment results produced by compliancekit. Each finding is an actionable result projected onto the cited objective-id (framework:control).",
					Start:       generated.UTC().Format(time.RFC3339),
					End:         generated.UTC().Format(time.RFC3339),
					ReviewedControls: arReviewedControls{
						ControlSelections: []arControlSelection{
							{IncludeControls: included},
						},
					},
					Findings: arFindings,
				},
			},
		},
	}
}

// controlIDsForFinding returns the set of "framework:control" pairs
// this finding covers, derived from the finding's CheckID via the
// frameworks registry. Returns an empty set when the check isn't in
// the registry (typical for ingested findings whose mapping table
// did not match).
func controlIDsForFinding(f compliancekit.Finding) map[string]struct{} {
	out := map[string]struct{}{}
	check, ok := compliancekit.LookupCheck(f.CheckID)
	if !ok {
		return out
	}
	for fwID, ctrls := range check.Frameworks {
		for _, c := range ctrls {
			out[fwID+":"+c] = struct{}{}
		}
	}
	return out
}

// oscalFindingFor builds one OSCAL Finding from a compliancekit
// Finding + the target control ID. Props carry compliancekit-
// specific metadata (severity, status, resource id) under the
// `compliancekit-*` name convention so consumers can filter without
// schema collision.
func oscalFindingFor(f compliancekit.Finding, ctrlID string) arFinding {
	return arFinding{
		UUID:        uuidFromContent("finding", f.CheckID, f.Resource.ID, ctrlID),
		Title:       f.CheckID,
		Description: f.Message,
		Target: arTarget{
			Type:     "objective-id",
			TargetID: ctrlID,
		},
		Props: []arProp{
			{Name: "compliancekit-check-id", Value: f.CheckID},
			{Name: "compliancekit-resource-id", Value: f.Resource.ID},
			{Name: "compliancekit-resource-type", Value: f.Resource.Type},
			{Name: "compliancekit-severity", Value: f.Severity.String()},
			{Name: "compliancekit-status", Value: string(f.Status)},
			{Name: "compliancekit-fingerprint", Value: f.Fingerprint()},
		},
	}
}

// includedControls returns the OSCAL include-controls array sorted
// by ID for byte-stable output across runs.
func includedControls(covered map[string]bool) []arIncludeControl {
	ids := make([]string, 0, len(covered))
	for id := range covered {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]arIncludeControl, 0, len(ids))
	for _, id := range ids {
		out = append(out, arIncludeControl{ControlID: id})
	}
	return out
}

func periodOrDefault(period string, generated time.Time) string {
	if period != "" {
		return period
	}
	return defaultPeriod(generated)
}

// uuidFromContent derives a deterministic, well-formed UUID string
// from a set of input parts. SHA256 → first 16 bytes → format as
// UUID with the v5 (name-based) version + RFC4122 variant bits set.
// Two AR documents over the same findings produce the same UUIDs,
// which lets the manifest stay stable across re-runs and lets
// downstream tooling correlate scan iterations safely.
func uuidFromContent(parts ...string) string {
	h := sha256.New()
	h.Write([]byte(strings.Join(parts, "|")))
	digest := h.Sum(nil)[:16]
	// Set version (5) and variant (RFC4122) bits per the standard.
	digest[6] = (digest[6] & 0x0f) | 0x50
	digest[8] = (digest[8] & 0x3f) | 0x80

	hex := hex.EncodeToString(digest)
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex[0:8], hex[8:12], hex[12:16], hex[16:20], hex[20:32])
}

// OSCAL Assessment Results document model (subset).

type arDocument struct {
	AssessmentResults arAssessmentResults `json:"assessment-results"`
}

type arAssessmentResults struct {
	UUID     string     `json:"uuid"`
	Metadata arMetadata `json:"metadata"`
	Results  []arResult `json:"results"`
}

type arMetadata struct {
	Title        string `json:"title"`
	LastModified string `json:"last-modified"`
	Version      string `json:"version"`
	OSCALVersion string `json:"oscal-version"`
}

type arResult struct {
	UUID             string             `json:"uuid"`
	Title            string             `json:"title"`
	Description      string             `json:"description"`
	Start            string             `json:"start"`
	End              string             `json:"end"`
	ReviewedControls arReviewedControls `json:"reviewed-controls"`
	Findings         []arFinding        `json:"findings,omitempty"`
}

type arReviewedControls struct {
	ControlSelections []arControlSelection `json:"control-selections"`
}

type arControlSelection struct {
	IncludeControls []arIncludeControl `json:"include-controls,omitempty"`
}

type arIncludeControl struct {
	ControlID string `json:"control-id"`
}

type arFinding struct {
	UUID        string   `json:"uuid"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Target      arTarget `json:"target"`
	Props       []arProp `json:"props,omitempty"`
}

type arTarget struct {
	Type     string `json:"type"`
	TargetID string `json:"target-id"`
}

type arProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	NS    string `json:"ns,omitempty"`
	Class string `json:"class,omitempty"`
}
