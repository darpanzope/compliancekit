package report

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// FormatMarkdown is the lowercase identifier used in config / CLI.
const FormatMarkdown = "markdown"

// MarkdownReporter renders findings as GitHub-flavored Markdown intended
// for posting in PR comments and CI summaries. The output is compact
// (severity table + per-severity sections) and renders cleanly without
// any external CSS or JS.
type MarkdownReporter struct{}

// NewMarkdown returns a Markdown reporter.
func NewMarkdown() *MarkdownReporter { return &MarkdownReporter{} }

// Format implements compliancekit.Reporter.
func (r *MarkdownReporter) Format() string { return FormatMarkdown }

// Render implements compliancekit.Reporter. Output structure:
//
//	# Scan report
//	**Generated:** <UTC timestamp>
//	**Findings:** N (counts...)
//
//	## Summary
//	| Severity | Count |
//	|----------|-------|
//	| critical | 0     |
//	...
//
//	## Findings
//	### Critical
//	- **check-id** on `resource` (type)
//	  > message
//	...
//
// Passing and skipped findings are intentionally omitted from the body
// (they show in the count tally) to keep the PR comment scannable.
// Reviewers want to see what's broken, not what passed.
func (r *MarkdownReporter) Render(_ context.Context, findings []compliancekit.Finding, _ *compliancekit.ResourceGraph, w io.Writer) error {
	bySev := groupBySeverity(findings)

	bw := &errWriter{w: w}
	fmt.Fprintf(bw, "# Scan report\n\n")
	fmt.Fprintf(bw, "**Generated:** %s\n\n", time.Now().UTC().Format(time.RFC3339))

	total := len(findings)
	actionable := 0
	for _, f := range findings {
		if f.Status.IsActionable() {
			actionable++
		}
	}
	fmt.Fprintf(bw, "**Findings:** %d total, %d actionable\n\n", total, actionable)

	// Summary table -- all severities, even if zero, so the table reads
	// the same shape across runs.
	fmt.Fprintf(bw, "## Summary\n\n")
	fmt.Fprintf(bw, "| Severity | Findings |\n|----------|----------|\n")
	for _, sev := range severitiesHighToLow() {
		fmt.Fprintf(bw, "| %s | %d |\n", titleCase(sev.String()), len(actionableOnly(bySev[sev])))
	}
	fmt.Fprintf(bw, "\n")

	// Body sections, high severity first. Skip a section entirely when
	// it has no actionable findings.
	wroteAny := false
	for _, sev := range severitiesHighToLow() {
		section := actionableOnly(bySev[sev])
		if len(section) == 0 {
			continue
		}
		wroteAny = true
		fmt.Fprintf(bw, "## %s findings\n\n", titleCase(sev.String()))
		for _, f := range section {
			renderFindingMarkdown(bw, f)
		}
	}
	if !wroteAny {
		fmt.Fprintf(bw, "_No actionable findings._\n")
	}

	return bw.err
}

func renderFindingMarkdown(w io.Writer, f compliancekit.Finding) {
	// `**check-id** on `resource-name` (resource-type)`
	fmt.Fprintf(w, "- **%s** on `%s`", f.CheckID, f.Resource.Name)
	if f.Resource.Type != "" {
		fmt.Fprintf(w, " (%s)", f.Resource.Type)
	}
	fmt.Fprintf(w, "\n")

	if msg := strings.TrimSpace(f.Message); msg != "" {
		// Indented blockquote so it nests under the bullet.
		fmt.Fprintf(w, "  > %s\n", msg)
	}

	renderVulnSubbullet(w, f.Vulnerability)
	renderSecretSubbullet(w, f.Secret)
}

// renderVulnSubbullet emits the v0.14 Vulnerability block as one or
// two indented subbullets under the parent finding. No-op when v
// is nil.
func renderVulnSubbullet(w io.Writer, v *compliancekit.Vulnerability) {
	if v == nil {
		return
	}
	details := []string{}
	if v.CVSSScore > 0 {
		details = append(details, fmt.Sprintf("CVSS %.1f", v.CVSSScore))
	}
	if v.Package.Name != "" {
		pkg := v.Package.Name
		if v.Package.Version != "" {
			pkg += "@" + v.Package.Version
		}
		details = append(details, "package="+pkg)
	}
	if v.FixedVersion != "" {
		details = append(details, "fixed-in="+v.FixedVersion)
	} else if v.Package.Name != "" {
		details = append(details, "unpatched")
	}
	if v.Image != "" {
		details = append(details, "image="+v.Image)
	}
	if len(details) > 0 {
		fmt.Fprintf(w, "  > vulnerability: %s\n", strings.Join(details, " · "))
	}
	if v.PrimaryURL != "" {
		fmt.Fprintf(w, "  > advisory: %s\n", v.PrimaryURL)
	}
}

// renderSecretSubbullet emits the v0.14 Secret block. Fingerprint is
// pre-redacted by the ingest adapter; the renderer must never enrich
// or attempt to recover the raw value (ADR-010).
func renderSecretSubbullet(w io.Writer, s *compliancekit.Secret) {
	if s == nil {
		return
	}
	fmt.Fprintf(w, "  > secret: rule=%s · fingerprint=%s", s.RuleID, s.Fingerprint)
	if s.File != "" {
		fmt.Fprintf(w, " · file=%s", s.File)
		if s.Line > 0 {
			fmt.Fprintf(w, ":L%d", s.Line)
		}
	}
	if s.Author != "" {
		fmt.Fprintf(w, " · author=%s", s.Author)
	}
	fmt.Fprintf(w, "\n")
}

// groupBySeverity buckets findings by severity. Findings whose severity
// is SeverityUnknown end up in their own bucket (defensive -- shouldn't
// happen in practice since every check sets a real severity).
func groupBySeverity(findings []compliancekit.Finding) map[compliancekit.Severity][]compliancekit.Finding {
	out := map[compliancekit.Severity][]compliancekit.Finding{}
	for _, f := range findings {
		out[f.Severity] = append(out[f.Severity], f)
	}
	// Stable order within each bucket: by check ID then resource ID.
	for sev := range out {
		sort.SliceStable(out[sev], func(i, j int) bool {
			a, b := out[sev][i], out[sev][j]
			if a.CheckID != b.CheckID {
				return a.CheckID < b.CheckID
			}
			return a.Resource.ID < b.Resource.ID
		})
	}
	return out
}

// actionableOnly filters to fail/error findings. The Markdown report
// is intended for PR review; pass/skip findings would just add noise.
func actionableOnly(findings []compliancekit.Finding) []compliancekit.Finding {
	out := make([]compliancekit.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Status.IsActionable() {
			out = append(out, f)
		}
	}
	return out
}

// severitiesHighToLow returns the severity enum in display order:
// Critical first, then High, Medium, Low, Info.
func severitiesHighToLow() []compliancekit.Severity {
	return []compliancekit.Severity{
		compliancekit.SeverityCritical,
		compliancekit.SeverityHigh,
		compliancekit.SeverityMedium,
		compliancekit.SeverityLow,
		compliancekit.SeverityInfo,
	}
}

// titleCase capitalizes the first rune of s. We avoid strings.Title
// (deprecated) and golang.org/x/text/cases overhead for this trivial use.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// errWriter is a tiny io.Writer wrapper that captures the first write
// error and short-circuits subsequent writes. Lets the report code
// stay readable (no `if err != nil` after every Fprintf) while still
// propagating IO failures via Render's return value.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) Write(p []byte) (int, error) {
	if ew.err != nil {
		return 0, ew.err
	}
	n, err := ew.w.Write(p)
	if err != nil {
		ew.err = err
	}
	return n, err
}
