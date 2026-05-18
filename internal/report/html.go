package report

import (
	"context"
	"embed"
	"html/template"
	"io"
	"sort"
	"time"

	"github.com/darpanzope/compliancekit/internal/frameworks"
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/score"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// FormatHTML is the lowercase identifier used in config / CLI.
const FormatHTML = "html"

//go:embed assets/template.html assets/icons/sprite.svg
var htmlAssets embed.FS

// htmlTemplate is parsed once at init; subsequent Render calls execute it.
var htmlTemplate = template.Must(template.ParseFS(htmlAssets, "assets/template.html"))

// htmlIconSprite is the raw <svg><defs><symbol>...</symbol></defs></svg>
// sheet inlined into the top of <body> at every render. Read once
// at init so Render is allocation-light. v1.2 phase 2.
var htmlIconSprite = func() template.HTML {
	b, err := htmlAssets.ReadFile("assets/icons/sprite.svg")
	if err != nil {
		// embed.FS errors at runtime would mean the binary was built
		// without the sprite. Compile-time go:embed guarantees the
		// file is present, so this branch is unreachable in practice;
		// returning empty keeps the report usable rather than panicking.
		return ""
	}
	return template.HTML(b) //nolint:gosec // sprite is build-time embedded
}()

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

// Format implements compliancekit.Reporter.
func (r *HTMLReporter) Format() string { return FormatHTML }

// Render implements compliancekit.Reporter. Emits a complete HTML page (with
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
func (r *HTMLReporter) Render(_ context.Context, findings []compliancekit.Finding, _ *compliancekit.ResourceGraph, w io.Writer) error {
	view := buildHTMLView(findings)
	return htmlTemplate.Execute(w, view)
}

// htmlView is what the template consumes.
type htmlView struct {
	Generated       string
	TotalCount      int
	ActionableCount int
	HasFindings     bool
	Score           int            // v0.6 hardening score per DECISIONS.md ADR-008
	Coverage        int            // v0.6 parallel metric: % of finding weight evaluable
	Counts          map[string]int // by lowercase severity name
	Sections        []htmlSection
	IconSprite      template.HTML // v1.2 phase 2 — inlined <symbol> sheet
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
	Snippets      []htmlSnippet // v0.22.1 — bespoke per-format remediation snippets
}

// frameworkRef is one (framework, control) pair attributed to a finding.
type frameworkRef struct {
	FrameworkID   string
	FrameworkName string
	ControlID     string
	ControlName   string
}

// htmlSnippet is one bespoke remediation snippet for a finding,
// pulled from the remediate registry at render time. v0.22.1 surfaces
// these inline in findings.html so operators no longer need to run
// `compliancekit remediate` separately and cross-reference by CheckID.
type htmlSnippet struct {
	Format    string // bash / terraform / kubectl / doctl / helm / etc.
	Risk      string // safe / review / manual
	RiskClass string // CSS class derived from Risk
	Content   string
	VerifyCmd string
	Notes     string
	Refs      []string
}

// buildHTMLView assembles the template view from a flat findings slice.
// Pass findings are included; the consumer (a browser, not a PR
// reviewer) wants the full picture.
func buildHTMLView(findings []compliancekit.Finding) htmlView {
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
	s := score.Compute(findings)

	return htmlView{
		Generated:       time.Now().UTC().Format(time.RFC3339),
		TotalCount:      len(findings),
		ActionableCount: actionable,
		HasFindings:     len(findings) > 0,
		Score:           s.Score,
		Coverage:        s.Coverage,
		Counts:          counts,
		Sections:        sections,
		IconSprite:      htmlIconSprite,
	}
}

// buildHTMLSections buckets findings by severity in display order
// (Critical -> Info). Within each bucket, findings sort by check ID
// then resource ID so re-renders are byte-stable.
func buildHTMLSections(findings []compliancekit.Finding) []htmlSection {
	bySev := map[compliancekit.Severity][]htmlFinding{}
	for _, f := range findings {
		bySev[f.Severity] = append(bySev[f.Severity], findingToHTML(f))
	}

	severities := []compliancekit.Severity{
		compliancekit.SeverityCritical,
		compliancekit.SeverityHigh,
		compliancekit.SeverityMedium,
		compliancekit.SeverityLow,
		compliancekit.SeverityInfo,
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
func findingToHTML(f compliancekit.Finding) htmlFinding {
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
	if check, ok := compliancekit.LookupCheck(f.CheckID); ok {
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

	// v0.22.1 — pull bespoke per-format remediation snippets from the
	// strategy registry. Only emits entries whose Strategy explicitly
	// claims this CheckID (wildcard "*" fallback strategies excluded
	// so the HTML doesn't fill with "no strategy registered" stubs).
	view.Snippets = htmlSnippetsForCheck(f)
	return view
}

// htmlSnippetsForCheck queries the default remediate registry for
// every bespoke Strategy covering the finding's CheckID, renders each
// Strategy in every Format it supports, and returns the rendered
// snippets in a stable order (sorted by Format).
//
// Wildcard "*" fallback strategies are excluded — they produce a
// generic "see message" stub that's noise inline. The runbook
// produced by `compliancekit remediate` is where the fallback shows
// up; the HTML stays clean.
func htmlSnippetsForCheck(f compliancekit.Finding) []htmlSnippet {
	var out []htmlSnippet
	seen := map[remediate.Format]bool{}
	for _, s := range remediate.Default.StrategiesFor(f.CheckID) {
		bespoke := false
		for _, id := range s.CheckIDs() {
			if id == f.CheckID {
				bespoke = true
				break
			}
		}
		if !bespoke {
			continue
		}
		for _, fmtID := range s.Formats() {
			if seen[fmtID] {
				continue // dedup: same format across multiple strategies
			}
			snip, err := s.Render(f, fmtID)
			if err != nil {
				continue
			}
			seen[fmtID] = true
			out = append(out, htmlSnippet{
				Format:    string(fmtID),
				Risk:      string(snip.Risk),
				RiskClass: string(snip.Risk),
				Content:   snip.Content,
				VerifyCmd: snip.VerifyCmd,
				Notes:     snip.Notes,
				Refs:      append([]string(nil), snip.Refs...),
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Format < out[j].Format })
	return out
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
