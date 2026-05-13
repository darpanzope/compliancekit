package report

import (
	"context"
	"embed"
	"html/template"
	"io"
	"sort"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/frameworks"
)

// FormatHTML is the lowercase identifier used in config / CLI.
const FormatHTML = "html"

//go:embed assets/template.html
var htmlAssets embed.FS

// htmlTemplate is parsed once at init; subsequent Render calls execute it.
var htmlTemplate = template.Must(template.ParseFS(htmlAssets, "assets/template.html"))

// HTMLReporter renders findings as a single self-contained HTML
// document with dark-mode styling, severity filter pills, and a
// free-text search box. All CSS and JS live inline so the output is
// emailable as one file.
//
// Per ARCHITECTURE.md §10 the v0.4 evidence pack reporter also writes
// HTML for the auditor-readable index; that reporter will share
// chrome with this one once both exist.
type HTMLReporter struct{}

// NewHTML returns an HTML reporter.
func NewHTML() *HTMLReporter { return &HTMLReporter{} }

// Format implements core.Reporter.
func (r *HTMLReporter) Format() string { return FormatHTML }

// Render implements core.Reporter. Emits a complete HTML page (with
// doctype, head, body, embedded CSS+JS, footer) so the operator can
// open the file directly in a browser, email it, or commit it to a
// repo as a static artifact.
//
// Pass and Skip findings are included so the operator can see the
// full coverage matrix in the HTML rendering -- distinct from the
// Markdown reporter which strips them to keep PR comments tight.
//
// The graph is currently unused; the v0.4 evidence pack reporter
// will read raw resource detail through it.
func (r *HTMLReporter) Render(_ context.Context, findings []core.Finding, _ *core.ResourceGraph, w io.Writer) error {
	view := buildHTMLView(findings)
	return htmlTemplate.Execute(w, view)
}

// htmlView is what the template consumes.
type htmlView struct {
	Generated       string
	TotalCount      int
	ActionableCount int
	HasFindings     bool
	Counts          map[string]int // by lowercase severity name
	Sections        []htmlSection
}

// htmlSection groups findings by severity for rendering.
type htmlSection struct {
	SeverityName  string // "Critical", "High", ...
	SeverityClass string // "critical", "high", ... (CSS class)
	Findings      []htmlFinding
}

// htmlFinding is one finding plus the check / framework metadata
// resolved at render time.
type htmlFinding struct {
	CheckID       string
	Status        string
	Severity      string
	SeverityClass string
	ResourceName  string
	ResourceType  string
	Message       string
	Title         string
	Description   string
	Remediation   string
	Frameworks    []frameworkRef
}

// frameworkRef is one (framework, control) pair attributed to a finding.
type frameworkRef struct {
	FrameworkID   string
	FrameworkName string
	ControlID     string
	ControlName   string
}

// buildHTMLView assembles the template view from a flat findings slice.
// Pass findings are included; the consumer (a browser, not a PR
// reviewer) wants the full picture.
func buildHTMLView(findings []core.Finding) htmlView {
	counts := map[string]int{
		"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
	}
	actionable := 0
	for _, f := range findings {
		if f.Status.IsActionable() {
			actionable++
			counts[f.Severity.String()]++
		}
	}

	sections := buildHTMLSections(findings)

	return htmlView{
		Generated:       time.Now().UTC().Format(time.RFC3339),
		TotalCount:      len(findings),
		ActionableCount: actionable,
		HasFindings:     len(findings) > 0,
		Counts:          counts,
		Sections:        sections,
	}
}

// buildHTMLSections buckets findings by severity in display order
// (Critical -> Info). Within each bucket, findings sort by check ID
// then resource ID so re-renders are byte-stable.
func buildHTMLSections(findings []core.Finding) []htmlSection {
	bySev := map[core.Severity][]htmlFinding{}
	for _, f := range findings {
		bySev[f.Severity] = append(bySev[f.Severity], findingToHTML(f))
	}

	severities := []core.Severity{
		core.SeverityCritical,
		core.SeverityHigh,
		core.SeverityMedium,
		core.SeverityLow,
		core.SeverityInfo,
	}
	out := make([]htmlSection, 0, len(severities))
	for _, sev := range severities {
		findings := bySev[sev]
		sort.SliceStable(findings, func(i, j int) bool {
			if findings[i].CheckID != findings[j].CheckID {
				return findings[i].CheckID < findings[j].CheckID
			}
			return findings[i].ResourceName < findings[j].ResourceName
		})
		out = append(out, htmlSection{
			SeverityName:  capitalize(sev.String()),
			SeverityClass: sev.String(),
			Findings:      findings,
		})
	}
	return out
}

// findingToHTML expands a Finding with metadata from the check registry
// and the framework catalog so the template doesn't have to chase
// references at render time.
func findingToHTML(f core.Finding) htmlFinding {
	view := htmlFinding{
		CheckID:       f.CheckID,
		Status:        string(f.Status),
		Severity:      f.Severity.String(),
		SeverityClass: f.Severity.String(),
		ResourceName:  f.Resource.Name,
		ResourceType:  f.Resource.Type,
		Message:       f.Message,
	}

	// Pull Title / Description / Remediation / Frameworks from the
	// registered Check metadata. A finding for an unregistered check
	// (shouldn't happen, but defensive) renders with the minimum
	// fields above.
	if check, ok := core.LookupCheck(f.CheckID); ok {
		view.Title = check.Title
		view.Description = check.Description
		view.Remediation = check.Remediation
		for _, rc := range frameworks.ResolveCheckControls(check.Frameworks) {
			view.Frameworks = append(view.Frameworks, frameworkRef{
				FrameworkID:   rc.Framework.ID,
				FrameworkName: rc.Framework.Name,
				ControlID:     rc.Control.ID,
				ControlName:   rc.Control.Name,
			})
		}
	}
	return view
}

// capitalize maps a lowercase severity name to its display form. The
// inputs are a fixed ASCII set, so an explicit switch is clearer than
// generic Unicode case mapping for one byte.
func capitalize(s string) string {
	switch s {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "info":
		return "Info"
	}
	return s
}
