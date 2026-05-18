package report

import (
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/frameworks"
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/score"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// FormatHTML is the lowercase identifier used in config / CLI.
const FormatHTML = "html"

//go:embed assets/template.html assets/icons/sprite.svg assets/chart.js
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

// htmlChartJS is the vanilla-JS SVG chart-primitives source, inlined
// into the bottom of <body> as a second <script>. v1.2 phase 3.
var htmlChartJS = func() template.JS {
	b, err := htmlAssets.ReadFile("assets/chart.js")
	if err != nil {
		return ""
	}
	return template.JS(b) //nolint:gosec // chart.js is build-time embedded
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
	ChartJS         template.JS   // v1.2 phase 3 — vanilla-JS SVG primitives

	// v1.2 phase 3 — summary cards. DonutJSON is the per-severity
	// segment list, HBarJSON is per-framework pass/fail tallies.
	// Pre-rendered as JSON strings; the template emits them in
	// data-* attribute context so html/template's auto-escape handles
	// any quote characters. JSON.parse on the JS side reverses the
	// escaping.
	DonutJSON string
	HBarJSON  string

	// v1.2 phase 4 — filter chip groups. Each group is one row of
	// togglable chips (severity, status, provider, framework). The
	// filter JS reads data-filter-key + data-filter-val off each chip
	// to drive show/hide of findings + section headers.
	ChipGroups []htmlChipGroup
}

// htmlChipGroup is one row of categorical filter chips.
type htmlChipGroup struct {
	Key   string     // "severity", "status", "provider", "framework"
	Label string     // human-facing group label
	Chips []htmlChip // displayed left-to-right in this order
}

// htmlChip is one togglable filter.
type htmlChip struct {
	Value    string // matched against the article's data-<key> attribute
	Label    string // display text
	Count    int    // findings matching this chip in isolation
	ColorVar string // optional CSS variable for chip border + text accent
}

// htmlDonutSegment is one wedge in the severity donut card.
type htmlDonutSegment struct {
	Key   string `json:"key"`   // severity slug (matches --sev-<key>)
	Label string `json:"label"` // display name
	Value int    `json:"value"` // actionable count
}

// htmlFrameworkRow is one row in the framework-coverage horizontal-
// bar card. Pass + Fail count distinct (CheckID, ResourceID) pairs
// attributed to the framework via the check registry.
type htmlFrameworkRow struct {
	Label string `json:"label"`
	Pass  int    `json:"pass"`
	Fail  int    `json:"fail"`
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
	CheckID         string
	Status          string
	Severity        string
	SeverityClass   string
	ResourceName    string
	ResourceType    string
	Provider        string   // v1.2 phase 4 — prefix of ResourceType ("digitalocean" from "digitalocean.droplet")
	FrameworkIDs    []string // v1.2 phase 4 — distinct framework IDs the check is attributed to
	FrameworkIDsCSV string   // v1.2 phase 4 — same list, comma-joined for the data-fws attribute
	Message         string
	Title           string
	Description     string
	Remediation     string
	Frameworks      []frameworkRef
	Snippets        []htmlSnippet // v0.22.1 — bespoke per-format remediation snippets
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
		ChartJS:         htmlChartJS,
		DonutJSON:       buildDonutJSON(counts),
		HBarJSON:        buildFrameworkJSON(findings),
		ChipGroups:      buildChipGroups(findings),
	}
}

// providerOf extracts the leading provider segment from a resource
// type. "digitalocean.droplet" → "digitalocean"; "linux.host" →
// "linux"; "k8s.pod" → "k8s". Resources without a dot return the
// full type so they still cluster meaningfully.
func providerOf(resourceType string) string {
	if i := strings.Index(resourceType, "."); i >= 0 {
		return resourceType[:i]
	}
	return resourceType
}

// buildChipGroups returns the four chip rows that drive the filter UI:
// severity (fixed order Critical → Info), status (Fail → Skip),
// provider (sorted, derived from resource types present in this scan),
// framework (sorted, derived from check-registry framework
// attribution). A group with zero distinct values is still emitted —
// the template skips empty groups so the UI stays clean.
func buildChipGroups(findings []compliancekit.Finding) []htmlChipGroup {
	sevCounts := map[string]int{}
	statusCounts := map[string]int{}
	provCounts := map[string]int{}
	fwCounts := map[string]int{}
	fwNames := map[string]string{}

	for _, f := range findings {
		sev := f.Severity.String()
		sevCounts[sev]++
		statusCounts[string(f.Status)]++
		provCounts[providerOf(f.Resource.Type)]++
		check, ok := compliancekit.LookupCheck(f.CheckID)
		if !ok {
			continue
		}
		seen := map[string]bool{}
		for _, rc := range frameworks.ResolveCheckControls(check.Frameworks) {
			if seen[rc.Framework.ID] {
				continue
			}
			seen[rc.Framework.ID] = true
			fwCounts[rc.Framework.ID]++
			fwNames[rc.Framework.ID] = rc.Framework.Name
		}
	}

	sevOrder := []struct{ key, label string }{
		{"critical", "Critical"},
		{"high", "High"},
		{"medium", "Medium"},
		{"low", "Low"},
		{"info", "Info"},
	}
	sevChips := make([]htmlChip, 0, 5)
	for _, s := range sevOrder {
		if sevCounts[s.key] == 0 {
			continue
		}
		sevChips = append(sevChips, htmlChip{Value: s.key, Label: s.label, Count: sevCounts[s.key], ColorVar: "--sev-" + s.key})
	}

	statusOrder := []struct{ key, label string }{
		{"fail", "Fail"},
		{"error", "Error"},
		{"pass", "Pass"},
		{"skip", "Skip"},
	}
	statusChips := make([]htmlChip, 0, 4)
	for _, s := range statusOrder {
		if statusCounts[s.key] == 0 {
			continue
		}
		statusChips = append(statusChips, htmlChip{Value: s.key, Label: s.label, Count: statusCounts[s.key], ColorVar: "--status-" + s.key})
	}

	provIDs := make([]string, 0, len(provCounts))
	for id := range provCounts {
		provIDs = append(provIDs, id)
	}
	sort.Strings(provIDs)
	provChips := make([]htmlChip, 0, len(provIDs))
	for _, id := range provIDs {
		provChips = append(provChips, htmlChip{Value: id, Label: id, Count: provCounts[id]})
	}

	fwIDs := make([]string, 0, len(fwCounts))
	for id := range fwCounts {
		fwIDs = append(fwIDs, id)
	}
	sort.Strings(fwIDs)
	fwChips := make([]htmlChip, 0, len(fwIDs))
	for _, id := range fwIDs {
		fwChips = append(fwChips, htmlChip{Value: id, Label: fwNames[id], Count: fwCounts[id]})
	}

	return []htmlChipGroup{
		{Key: "severity", Label: "Severity", Chips: sevChips},
		{Key: "status", Label: "Status", Chips: statusChips},
		{Key: "provider", Label: "Provider", Chips: provChips},
		{Key: "framework", Label: "Framework", Chips: fwChips},
	}
}

// buildDonutJSON renders the per-severity actionable counts as a JSON
// array suitable for the donut chart's data-segments attribute. Order
// matches display order so the wedges paint Critical → Info clockwise.
func buildDonutJSON(counts map[string]int) string {
	segs := []htmlDonutSegment{
		{Key: "critical", Label: "Critical", Value: counts["critical"]},
		{Key: "high", Label: "High", Value: counts["high"]},
		{Key: "medium", Label: "Medium", Value: counts["medium"]},
		{Key: "low", Label: "Low", Value: counts["low"]},
		{Key: "info", Label: "Info", Value: counts["info"]},
	}
	b, err := json.Marshal(segs)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// buildFrameworkJSON aggregates findings by attributed framework and
// renders a JSON array for the framework-coverage horizontal-bar
// card. A finding contributes one tally per framework it maps to
// (multi-framework checks count in each). Pass/Skip rolls into Pass
// (the operator just wants to see "this control didn't fail");
// Fail/Error rolls into Fail.
func buildFrameworkJSON(findings []compliancekit.Finding) string {
	type tally struct {
		name       string
		pass, fail int
	}
	byFW := map[string]*tally{}
	for _, f := range findings {
		check, ok := compliancekit.LookupCheck(f.CheckID)
		if !ok {
			continue
		}
		for _, rc := range frameworks.ResolveCheckControls(check.Frameworks) {
			t, exists := byFW[rc.Framework.ID]
			if !exists {
				t = &tally{name: rc.Framework.Name}
				byFW[rc.Framework.ID] = t
			}
			if f.Status.IsActionable() {
				t.fail++
			} else {
				t.pass++
			}
		}
	}
	if len(byFW) == 0 {
		return "[]"
	}
	ids := make([]string, 0, len(byFW))
	for id := range byFW {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows := make([]htmlFrameworkRow, 0, len(ids))
	for _, id := range ids {
		t := byFW[id]
		rows = append(rows, htmlFrameworkRow{Label: t.name, Pass: t.pass, Fail: t.fail})
	}
	b, err := json.Marshal(rows)
	if err != nil {
		return "[]"
	}
	return string(b)
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
		Provider:      providerOf(f.Resource.Type),
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
		fwSeen := map[string]bool{}
		for _, rc := range frameworks.ResolveCheckControls(check.Frameworks) {
			view.Frameworks = append(view.Frameworks, frameworkRef{
				FrameworkID:   rc.Framework.ID,
				FrameworkName: rc.Framework.Name,
				ControlID:     rc.Control.ID,
				ControlName:   rc.Control.Name,
			})
			if !fwSeen[rc.Framework.ID] {
				fwSeen[rc.Framework.ID] = true
				view.FrameworkIDs = append(view.FrameworkIDs, rc.Framework.ID)
			}
		}
		view.FrameworkIDsCSV = strings.Join(view.FrameworkIDs, ",")
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
