package report

import (
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/baseline"
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
type HTMLReporter struct {
	// baselines is the optional history of baseline snapshots used to
	// render trend sparklines on the summary cards. Oldest first,
	// newest last. Empty = no trend section / no drift card. v1.2
	// phase 6.
	baselines []baseline.Baseline
}

// NewHTML returns an HTML reporter.
func NewHTML() *HTMLReporter { return &HTMLReporter{} }

// WithBaselines returns the reporter with a baseline history attached.
// Callers pass the history in chronological order (oldest first). When
// non-empty, the rendered report includes a "Drift vs baseline" card,
// per-card delta indicators, sparklines on the score / severity /
// framework cards, and a "new" badge on findings that were not
// fingerprinted in the most recent baseline.
//
// Mutates + returns r so the call site stays a one-liner:
//
//	r := report.NewHTML().WithBaselines(history)
func (r *HTMLReporter) WithBaselines(b []baseline.Baseline) *HTMLReporter {
	r.baselines = b
	return r
}

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
	if len(r.baselines) > 0 {
		applyBaselineHistory(&view, findings, r.baselines)
	}
	return htmlTemplate.Execute(w, view)
}

// htmlView is what the template consumes.
type htmlView struct {
	Generated       string
	TotalCount      int
	ActionableCount int
	PassCount       int // v1.2 phase 8 — for the "X / Y pass" celebration
	HasFindings     bool
	IsAllClear      bool           // v1.2 phase 8 — HasFindings && ActionableCount == 0
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

	// v1.2 phase 5 — sticky resource sidebar. Resources are bucketed
	// provider → type → resource, sorted alphabetically for stable
	// rendering. Sidebar links scroll to the first article for that
	// resource (anchor IDs are wired by client-side JS on load).
	SidebarGroups []htmlSidebarGroup

	// v1.2 phase 6 — baseline trend. HasBaseline gates every drift-
	// related piece of UI: if no baseline was passed to the reporter,
	// these fields are zero values and the template skips their
	// blocks. NewIDs is the set of fingerprints absent from the most
	// recent baseline; the per-article template stamps "new since
	// baseline" when its fingerprint appears here.
	HasBaseline     bool
	BaselineLabel   string // human-readable "captured 5 days ago" or capture date
	DriftNew        int
	DriftResolved   int
	DriftExisting   int
	ScoreTrend      string          // JSON array of 7 (or fewer) ints
	ActionableTrend string          // JSON array of 7 (or fewer) ints
	ScoreDelta      int             // signed (current - earliest)
	ActionableDelta int             // signed (current - earliest); negative is good
	NewIDs          map[string]bool // fingerprint set; per-article template uses {{ index .NewIDs .Fingerprint }}
}

// htmlSidebarGroup is the top-level provider bucket in the resource
// sidebar.
type htmlSidebarGroup struct {
	Provider   string
	Total      int
	Actionable int
	Types      []htmlSidebarSubgroup
}

// htmlSidebarSubgroup is a resource-type bucket inside a provider
// group (e.g. provider=digitalocean → type=digitalocean.droplet).
type htmlSidebarSubgroup struct {
	Type       string
	TypeShort  string // suffix after the provider prefix, for display
	Total      int
	Actionable int
	Resources  []htmlSidebarItem
}

// htmlSidebarItem is one resource row inside the sidebar.
type htmlSidebarItem struct {
	ID         string // matches Finding.Resource.ID; used for the scroll anchor
	AnchorID   string // CSS-safe slug of the resource ID
	Name       string
	Total      int
	Actionable int
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
	CheckID          string
	Fingerprint      string // v1.2 phase 6 — for the "new since baseline" lookup
	Status           string
	Severity         string
	SeverityClass    string
	ResourceID       string // raw resource ID — drives the sidebar anchor target
	ResourceAnchorID string // CSS-safe slug used as the article's element id
	ResourceName     string
	ResourceType     string
	Provider         string   // v1.2 phase 4 — prefix of ResourceType ("digitalocean" from "digitalocean.droplet")
	FrameworkIDs     []string // v1.2 phase 4 — distinct framework IDs the check is attributed to
	FrameworkIDsCSV  string   // v1.2 phase 4 — same list, comma-joined for the data-fws attribute
	Message          string
	Title            string
	Description      string
	Remediation      string
	Frameworks       []frameworkRef
	Snippets         []htmlSnippet // v0.22.1 — bespoke per-format remediation snippets
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
	pass := 0
	for _, f := range findings {
		if f.Status.IsActionable() {
			actionable++
			counts[f.Severity.String()]++
		} else if f.Status == compliancekit.StatusPass {
			pass++
		}
	}

	sections := buildHTMLSections(findings)
	s := score.Compute(findings)

	return htmlView{
		Generated:       time.Now().UTC().Format(time.RFC3339),
		TotalCount:      len(findings),
		ActionableCount: actionable,
		PassCount:       pass,
		HasFindings:     len(findings) > 0,
		IsAllClear:      len(findings) > 0 && actionable == 0,
		Score:           s.Score,
		Coverage:        s.Coverage,
		Counts:          counts,
		Sections:        sections,
		IconSprite:      htmlIconSprite,
		ChartJS:         htmlChartJS,
		DonutJSON:       buildDonutJSON(counts),
		HBarJSON:        buildFrameworkJSON(findings),
		ChipGroups:      buildChipGroups(findings),
		SidebarGroups:   buildSidebarGroups(findings),
	}
}

// resourceAnchorID renders a CSS-id-safe slug for a resource ID.
// Replaces every non-[A-Za-z0-9_-] byte with "-" and prefixes "r-"
// so the result is a valid id selector and a stable URL fragment.
func resourceAnchorID(resourceID string) string {
	var b strings.Builder
	b.Grow(len(resourceID) + 2)
	b.WriteString("r-")
	for _, r := range resourceID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

// buildSidebarGroups walks findings, buckets resources by provider →
// type → resource, and counts total + actionable findings per bucket.
// Sort order is alpha throughout so the sidebar is byte-stable across
// renders + reloads.
func buildSidebarGroups(findings []compliancekit.Finding) []htmlSidebarGroup {
	type rkey struct{ id, name, typ string }
	type rstate struct {
		name              string
		total, actionable int
	}
	// provider → type → resourceID → counts
	tree := map[string]map[string]map[rkey]*rstate{}

	for _, f := range findings {
		prov := providerOf(f.Resource.Type)
		typ := f.Resource.Type
		id := f.Resource.ID
		if id == "" {
			id = f.Resource.Name // fall back so the tree still buckets
		}
		k := rkey{id: id, name: f.Resource.Name, typ: typ}
		byType, ok := tree[prov]
		if !ok {
			byType = map[string]map[rkey]*rstate{}
			tree[prov] = byType
		}
		byRes, ok := byType[typ]
		if !ok {
			byRes = map[rkey]*rstate{}
			byType[typ] = byRes
		}
		st, ok := byRes[k]
		if !ok {
			st = &rstate{name: f.Resource.Name}
			byRes[k] = st
		}
		st.total++
		if f.Status.IsActionable() {
			st.actionable++
		}
	}

	provs := make([]string, 0, len(tree))
	for p := range tree {
		provs = append(provs, p)
	}
	sort.Strings(provs)

	out := make([]htmlSidebarGroup, 0, len(provs))
	for _, prov := range provs {
		group := htmlSidebarGroup{Provider: prov}
		byType := tree[prov]
		typs := make([]string, 0, len(byType))
		for t := range byType {
			typs = append(typs, t)
		}
		sort.Strings(typs)
		for _, t := range typs {
			sub := htmlSidebarSubgroup{Type: t, TypeShort: strings.TrimPrefix(t, prov+".")}
			items := make([]htmlSidebarItem, 0, len(byType[t]))
			for k, st := range byType[t] {
				items = append(items, htmlSidebarItem{
					ID:         k.id,
					AnchorID:   resourceAnchorID(k.id),
					Name:       st.name,
					Total:      st.total,
					Actionable: st.actionable,
				})
				sub.Total += st.total
				sub.Actionable += st.actionable
			}
			// Highest-actionable resources first so the operator sees
			// the noisy ones at the top; ties broken by name for byte-
			// stability.
			sort.SliceStable(items, func(i, j int) bool {
				if items[i].Actionable != items[j].Actionable {
					return items[i].Actionable > items[j].Actionable
				}
				return items[i].Name < items[j].Name
			})
			sub.Resources = items
			group.Total += sub.Total
			group.Actionable += sub.Actionable
			group.Types = append(group.Types, sub)
		}
		out = append(out, group)
	}
	return out
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
	rid := f.Resource.ID
	if rid == "" {
		rid = f.Resource.Name
	}
	view := htmlFinding{
		CheckID:          f.CheckID,
		Fingerprint:      f.Fingerprint(),
		Status:           string(f.Status),
		Severity:         f.Severity.String(),
		SeverityClass:    f.Severity.String(),
		ResourceID:       rid,
		ResourceAnchorID: resourceAnchorID(rid),
		ResourceName:     f.Resource.Name,
		ResourceType:     f.Resource.Type,
		Provider:         providerOf(f.Resource.Type),
		Message:          f.Message,
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

// applyBaselineHistory enriches the view with the baseline-driven
// fields: drift counts, the "new" fingerprint set, summary-card
// deltas, and the sparkline series for score + actionable counts.
// The newest entry in baselines is treated as the immediate
// comparison point; the full slice drives the 7-point sparklines.
// v1.2 phase 6.
func applyBaselineHistory(view *htmlView, current []compliancekit.Finding, baselines []baseline.Baseline) {
	if len(baselines) == 0 {
		return
	}
	// Newest baseline is the immediate comparison point. Diff is in
	// fingerprint space, matching internal/diff and the baseline
	// drift workflow.
	latest := baselines[len(baselines)-1]
	latestFP := latest.FingerprintSet()
	currentFP := map[string]bool{}
	view.NewIDs = map[string]bool{}
	for _, f := range current {
		fp := f.Fingerprint()
		currentFP[fp] = true
		if _, hit := latestFP[fp]; !hit {
			view.NewIDs[fp] = true
		}
	}
	var resolved int
	for fp := range latestFP {
		if !currentFP[fp] {
			resolved++
		}
	}
	view.HasBaseline = true
	view.DriftNew = len(view.NewIDs)
	view.DriftResolved = resolved
	view.DriftExisting = len(latestFP) - resolved
	view.BaselineLabel = baselineLabel(latest.CapturedAt)

	// Sparkline series — score + actionable count across the history,
	// with the current scan tacked on as the final point.
	scoreSeries := make([]int, 0, len(baselines)+1)
	actSeries := make([]int, 0, len(baselines)+1)
	for _, b := range baselines {
		scoreSeries = append(scoreSeries, b.Score)
		var actionable int
		for _, e := range b.Entries {
			if e.Status.IsActionable() {
				actionable++
			}
		}
		actSeries = append(actSeries, actionable)
	}
	scoreSeries = append(scoreSeries, view.Score)
	actSeries = append(actSeries, view.ActionableCount)

	if data, err := json.Marshal(scoreSeries); err == nil {
		view.ScoreTrend = string(data)
	} else {
		view.ScoreTrend = "[]"
	}
	if data, err := json.Marshal(actSeries); err == nil {
		view.ActionableTrend = string(data)
	} else {
		view.ActionableTrend = "[]"
	}
	if len(scoreSeries) >= 2 {
		view.ScoreDelta = scoreSeries[len(scoreSeries)-1] - scoreSeries[0]
		view.ActionableDelta = actSeries[len(actSeries)-1] - actSeries[0]
	}
}

// baselineLabel returns a short human-readable description of how old
// the baseline is. "captured today" / "captured 3 days ago" / the raw
// date for anything older than 14 days.
func baselineLabel(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	days := int(time.Since(at).Hours() / 24)
	switch {
	case days <= 0:
		return "captured today"
	case days == 1:
		return "captured yesterday"
	case days <= 14:
		return "captured " + intToStr(days) + " days ago"
	default:
		return "captured " + at.Format("2 Jan 2006")
	}
}

// intToStr is a tiny strconv.Itoa alias to keep the import list lean.
func intToStr(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	n := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		buf[n] = '-'
	}
	return string(buf[n:])
}

// LoadBaselineHistory loads either a single baseline file or every
// *.json baseline in a directory, returning them in chronological
// order (oldest first). Used by the render subcommand's --baseline
// flag. Single-file inputs return a 1-element slice; directories with
// no baselines return (nil, nil) so the reporter renders without a
// trend section rather than erroring.
func LoadBaselineHistory(path string) ([]baseline.Baseline, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		b, err := baseline.Load(path)
		if err != nil {
			return nil, err
		}
		return []baseline.Baseline{b}, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	loaded := make([]baseline.Baseline, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := baseline.Load(filepath.Join(path, e.Name()))
		if err != nil {
			// Skip files that don't parse as baselines; the directory
			// may carry other JSON artifacts (findings exports, etc.).
			continue
		}
		loaded = append(loaded, b)
	}
	sort.Slice(loaded, func(i, j int) bool {
		return loaded[i].CapturedAt.Before(loaded[j].CapturedAt)
	})
	// Keep the most recent 7 — sparklines are 7-point per the spec.
	if len(loaded) > 7 {
		loaded = loaded[len(loaded)-7:]
	}
	return loaded, nil
}
