// Package runbook writes the operator-facing artifacts of v0.15's
// remediation flow:
//
//   - remediation.md — a structured runbook grouping every snippet
//     by severity → check → resource, with TOC, verify/rollback,
//     references, and the strategy's risk class.
//   - remediate.sh — a single bash script bundling the RiskSafe
//     snippets (where every command can be re-run without coordination)
//     for operators who want a one-shot apply. RiskReview and
//     RiskManual snippets are intentionally excluded — applying them
//     requires per-resource decisions.
//   - remediate-<format>/ — one subdirectory per Format, with the
//     raw snippet bodies grouped per-resource so operators can `git
//     diff` the directory between scans.
//
// All three artifacts live inside the evidence pack so the audit
// trail stays self-contained. Determinism: identical findings + the
// same registry produce byte-identical files (no timestamps in
// snippet bodies; deterministic sort order).
package runbook

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Options controls runbook generation.
type Options struct {
	// GeneratedAt is stamped into the runbook header. Zero defaults
	// to time.Now() — tests pass a fixed value.
	GeneratedAt time.Time
	// Project optionally identifies the assessment subject; appears
	// in the runbook title.
	Project string
	// IncludeFormats restricts which formats appear in the runbook
	// + per-format directories. Empty means all formats present in
	// the snippets.
	IncludeFormats []remediate.Format
}

// Result reports the files written. Paths are absolute.
type Result struct {
	RunbookPath    string // remediation.md
	BulkScriptPath string // remediate.sh
	FormatDirs     map[remediate.Format]string
}

// Write produces the runbook + bulk script + per-format directories
// under root. Caller ensures root exists.
//
// snippets is the full output of remediate.Default.RenderAll for
// the findings under remediation. unmatched (optional) is the slice
// of findings without any strategy — they appear in the runbook's
// "Unmatched" section as breadcrumbs even though they're handled by
// POA&M emit elsewhere.
func Write(root string, snippets []remediate.Snippet, unmatched []compliancekit.Finding, opts Options) (Result, error) {
	if root == "" {
		return Result{}, fmt.Errorf("runbook: empty root")
	}
	formats := opts.IncludeFormats
	if len(formats) == 0 {
		formats = formatsInUse(snippets)
	}

	// Per-format directories.
	formatDirs := make(map[remediate.Format]string, len(formats))
	for _, f := range formats {
		dir := filepath.Join(root, "remediate-"+string(f))
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return Result{}, fmt.Errorf("runbook: mkdir %s: %w", dir, err)
		}
		formatDirs[f] = dir
	}
	for _, sn := range snippets {
		if !formatActive(sn.Format, formats) {
			continue
		}
		dir := formatDirs[sn.Format]
		fname := snippetFilename(sn)
		// #nosec G306
		if err := os.WriteFile(filepath.Join(dir, fname), []byte(sn.Content), 0o644); err != nil {
			return Result{}, fmt.Errorf("runbook: write snippet %s: %w", fname, err)
		}
	}

	// remediation.md
	runbookBody := renderMarkdown(snippets, unmatched, formats, opts)
	runbookPath := filepath.Join(root, "remediation.md")
	// #nosec G306
	if err := os.WriteFile(runbookPath, []byte(runbookBody), 0o644); err != nil {
		return Result{}, fmt.Errorf("runbook: write runbook: %w", err)
	}

	// remediate.sh — RiskSafe-only bulk apply.
	scriptBody := renderBulkScript(snippets)
	scriptPath := filepath.Join(root, "remediate.sh")
	// #nosec G306 — operator script intentionally readable/executable.
	if err := os.WriteFile(scriptPath, []byte(scriptBody), 0o755); err != nil {
		return Result{}, fmt.Errorf("runbook: write bulk script: %w", err)
	}

	return Result{
		RunbookPath:    runbookPath,
		BulkScriptPath: scriptPath,
		FormatDirs:     formatDirs,
	}, nil
}

// renderMarkdown is exposed for tests; produces the full runbook.
func renderMarkdown(snippets []remediate.Snippet, unmatched []compliancekit.Finding, formats []remediate.Format, opts Options) string {
	generated := opts.GeneratedAt
	if generated.IsZero() {
		generated = time.Now().UTC()
	}
	project := opts.Project
	if project == "" {
		project = "compliancekit"
	}
	var sb strings.Builder

	fmt.Fprintf(&sb, "# %s — Remediation runbook\n\n", project)
	fmt.Fprintf(&sb, "*Generated %s — %d total snippets across %d findings.*\n\n",
		generated.Format(time.RFC3339), len(snippets), countFindings(snippets, unmatched))
	sb.WriteString("> Format quick-pick: ")
	for i, f := range formats {
		if i > 0 {
			sb.WriteString(" · ")
		}
		fmt.Fprintf(&sb, "`%s`", f)
	}
	sb.WriteString("\n\n")

	writeRiskLegend(&sb)

	// Group snippets by (Risk, CheckID, Resource.ID, Format).
	grouped := groupByRiskCheckResource(snippets)
	writeTOC(&sb, grouped)

	for _, risk := range []remediate.RiskClass{remediate.RiskSafe, remediate.RiskReview, remediate.RiskManual} {
		entries := grouped[risk]
		if len(entries) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "## %s — %d snippets\n\n", riskHeader(risk), countSnippetsInRisk(entries))
		for _, e := range entries {
			writeEntry(&sb, e)
		}
	}

	if len(unmatched) > 0 {
		sb.WriteString("## Unmatched — POA&M-only\n\n")
		sb.WriteString("These findings have no registered remediation strategy. Each appears as a manual-action entry in `poam.oscal.json`.\n\n")
		sort.SliceStable(unmatched, func(i, j int) bool {
			if unmatched[i].CheckID != unmatched[j].CheckID {
				return unmatched[i].CheckID < unmatched[j].CheckID
			}
			return unmatched[i].Resource.ID < unmatched[j].Resource.ID
		})
		for _, f := range unmatched {
			fmt.Fprintf(&sb, "- `%s` on `%s` — %s\n", f.CheckID, f.Resource.ID, f.Message)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func writeRiskLegend(sb *strings.Builder) {
	sb.WriteString("## Risk classes\n\n")
	sb.WriteString("| Class | Meaning |\n|---|---|\n")
	sb.WriteString("| Safe | No data loss, no service disruption, no behavior change beyond posture. Applies via `remediate.sh`. |\n")
	sb.WriteString("| Review | Visible behavior change. Read the snippet before applying. |\n")
	sb.WriteString("| Manual | Cannot be expressed as a snippet — requires out-of-band coordination. Tracked in `poam.oscal.json`. |\n\n")
}

type entry struct {
	risk     remediate.RiskClass
	checkID  string
	resource compliancekit.ResourceRef
	byFormat map[remediate.Format]remediate.Snippet
}

func groupByRiskCheckResource(snippets []remediate.Snippet) map[remediate.RiskClass][]entry {
	keyed := map[string]*entry{}
	for _, sn := range snippets {
		key := fmt.Sprintf("%s|%s|%s", sn.Risk, sn.CheckID, sn.Resource.ID)
		e, ok := keyed[key]
		if !ok {
			e = &entry{
				risk:     sn.Risk,
				checkID:  sn.CheckID,
				resource: sn.Resource,
				byFormat: map[remediate.Format]remediate.Snippet{},
			}
			keyed[key] = e
		}
		e.byFormat[sn.Format] = sn
	}
	out := map[remediate.RiskClass][]entry{}
	for _, e := range keyed {
		out[e.risk] = append(out[e.risk], *e)
	}
	for k := range out {
		sort.SliceStable(out[k], func(i, j int) bool {
			if out[k][i].checkID != out[k][j].checkID {
				return out[k][i].checkID < out[k][j].checkID
			}
			return out[k][i].resource.ID < out[k][j].resource.ID
		})
	}
	return out
}

func writeTOC(sb *strings.Builder, grouped map[remediate.RiskClass][]entry) {
	total := 0
	for _, es := range grouped {
		total += len(es)
	}
	if total == 0 {
		return
	}
	sb.WriteString("## Table of contents\n\n")
	for _, risk := range []remediate.RiskClass{remediate.RiskSafe, remediate.RiskReview, remediate.RiskManual} {
		entries := grouped[risk]
		if len(entries) == 0 {
			continue
		}
		fmt.Fprintf(sb, "- [%s](#%s) (%d)\n", riskHeader(risk), riskAnchor(risk), len(entries))
	}
	sb.WriteString("\n")
}

func writeEntry(sb *strings.Builder, e entry) {
	resName := e.resource.Name
	if resName == "" {
		resName = e.resource.ID
	}
	fmt.Fprintf(sb, "### `%s` on `%s`\n\n", e.checkID, resName)

	// Lookup metadata from the catalog for nicer prose.
	if c, ok := compliancekit.LookupCheck(e.checkID); ok {
		if c.Title != "" {
			fmt.Fprintf(sb, "**%s**\n\n", c.Title)
		}
		if c.Description != "" {
			fmt.Fprintf(sb, "%s\n\n", c.Description)
		}
	}

	// Sorted format list for stable output.
	formats := make([]remediate.Format, 0, len(e.byFormat))
	for f := range e.byFormat {
		formats = append(formats, f)
	}
	sort.Slice(formats, func(i, j int) bool { return string(formats[i]) < string(formats[j]) })

	for _, f := range formats {
		sn := e.byFormat[f]
		fmt.Fprintf(sb, "#### %s\n\n", f)
		if sn.Notes != "" {
			fmt.Fprintf(sb, "> %s\n\n", sn.Notes)
		}
		fmt.Fprintf(sb, "```%s\n%s\n```\n\n", codeFenceLang(f), strings.TrimRight(sn.Content, "\n"))
		if sn.VerifyCmd != "" {
			fmt.Fprintf(sb, "**Verify:** `%s`\n\n", sn.VerifyCmd)
		}
		if sn.RollbackCmd != "" {
			fmt.Fprintf(sb, "**Rollback:** `%s`\n\n", sn.RollbackCmd)
		}
		if len(sn.Refs) > 0 {
			sb.WriteString("**References:** ")
			for i, r := range sn.Refs {
				if i > 0 {
					sb.WriteString(", ")
				}
				fmt.Fprintf(sb, "<%s>", r)
			}
			sb.WriteString("\n\n")
		}
	}
}

func renderBulkScript(snippets []remediate.Snippet) string {
	var sb strings.Builder
	sb.WriteString("#!/usr/bin/env bash\n")
	sb.WriteString("# Auto-generated by compliancekit remediate — RiskSafe snippets only.\n")
	sb.WriteString("# Review every command before running. Run individual blocks rather\n")
	sb.WriteString("# than the whole script if you are unsure of any step.\n")
	sb.WriteString("set -euo pipefail\n\n")

	// Sort for determinism.
	sorted := append([]remediate.Snippet(nil), snippets...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].CheckID != sorted[j].CheckID {
			return sorted[i].CheckID < sorted[j].CheckID
		}
		if sorted[i].Resource.ID != sorted[j].Resource.ID {
			return sorted[i].Resource.ID < sorted[j].Resource.ID
		}
		return string(sorted[i].Format) < string(sorted[j].Format)
	})

	emitted := 0
	for _, sn := range sorted {
		if sn.Risk != remediate.RiskSafe {
			continue
		}
		// Pick exactly one format per (CheckID, Resource) pair so the
		// script doesn't apply the same fix twice. Preference order
		// matches AllFormats with bash first → cloud-CLI families
		// before IaC (which require a separate apply step).
		if !preferredForBulk(sn.Format) {
			continue
		}
		fmt.Fprintf(&sb, "# === %s on %s ===\n", sn.CheckID, sn.Resource.ID)
		if sn.Notes != "" {
			fmt.Fprintf(&sb, "# %s\n", oneLineNotes(sn.Notes))
		}
		sb.WriteString(strings.TrimRight(sn.Content, "\n"))
		sb.WriteString("\n\n")
		emitted++
	}
	if emitted == 0 {
		sb.WriteString("# No RiskSafe snippets were generated. Nothing to apply.\n")
	}
	return sb.String()
}

// preferredForBulk picks the formats whose snippets are most
// reliably bash-pasteable for inclusion in remediate.sh. IaC
// formats (Terraform, kubectl manifests as YAML, Helm) require a
// separate `terraform apply` / `kubectl apply` / `helm upgrade`
// step and don't belong inside a single sequential bash script.
func preferredForBulk(f remediate.Format) bool {
	switch f {
	case remediate.FormatBash, remediate.FormatAWSCLI, remediate.FormatGCloud,
		remediate.FormatAzureCLI, remediate.FormatDoctl, remediate.FormatHcloud:
		return true
	}
	return false
}

// formatsInUse returns the unique Formats present in snippets, in
// the canonical AllFormats order.
func formatsInUse(snippets []remediate.Snippet) []remediate.Format {
	present := map[remediate.Format]bool{}
	for _, sn := range snippets {
		present[sn.Format] = true
	}
	out := make([]remediate.Format, 0, len(present))
	for _, f := range remediate.AllFormats {
		if present[f] {
			out = append(out, f)
		}
	}
	return out
}

func formatActive(f remediate.Format, allowed []remediate.Format) bool {
	for _, a := range allowed {
		if a == f {
			return true
		}
	}
	return false
}

func snippetFilename(sn remediate.Snippet) string {
	resID := sn.Resource.ID
	if resID == "" {
		resID = sn.Resource.Name
	}
	if resID == "" {
		resID = "global"
	}
	resID = strings.NewReplacer("/", "_", ":", "_", " ", "_").Replace(resID)
	return fmt.Sprintf("%s--%s.%s", sn.CheckID, resID, fileExtFor(sn.Format))
}

func fileExtFor(f remediate.Format) string {
	switch f {
	case remediate.FormatTerraform:
		return "tf"
	case remediate.FormatKubectl, remediate.FormatHelm, remediate.FormatAnsible:
		return "yaml"
	default:
		return "sh"
	}
}

func codeFenceLang(f remediate.Format) string {
	switch f {
	case remediate.FormatTerraform:
		return "hcl"
	case remediate.FormatKubectl, remediate.FormatHelm, remediate.FormatAnsible:
		return "yaml"
	}
	return "bash"
}

func riskHeader(r remediate.RiskClass) string {
	switch r {
	case remediate.RiskSafe:
		return "Safe (auto-apply candidates)"
	case remediate.RiskReview:
		return "Review (read before applying)"
	case remediate.RiskManual:
		return "Manual (POA&M-tracked)"
	}
	return string(r)
}

func riskAnchor(r remediate.RiskClass) string {
	switch r {
	case remediate.RiskSafe:
		return "safe-auto-apply-candidates"
	case remediate.RiskReview:
		return "review-read-before-applying"
	case remediate.RiskManual:
		return "manual-poam-tracked"
	}
	return string(r)
}

func oneLineNotes(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 180 {
		s = s[:177] + "..."
	}
	return s
}

func countSnippetsInRisk(entries []entry) int {
	total := 0
	for _, e := range entries {
		total += len(e.byFormat)
	}
	return total
}

func countFindings(snippets []remediate.Snippet, unmatched []compliancekit.Finding) int {
	seen := map[string]bool{}
	for _, sn := range snippets {
		seen[sn.CheckID+"|"+sn.Resource.ID] = true
	}
	for _, f := range unmatched {
		seen[f.CheckID+"|"+f.Resource.ID] = true
	}
	return len(seen)
}
