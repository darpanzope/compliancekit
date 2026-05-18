package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/baseline"
	"github.com/darpanzope/compliancekit/internal/diff"
	"github.com/darpanzope/compliancekit/internal/ui"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

type diffOptions struct {
	failOn string
}

func newDiffCmd() *cobra.Command {
	var opts diffOptions

	cmd := &cobra.Command{
		Use:   "diff <baseline.json> <findings.json>",
		Short: "Compare a baseline to a fresh scan; classify findings as new / existing / resolved",
		Long: `Diff classifies the findings in <findings.json> against
<baseline.json>:

    new       fingerprint not in baseline
    existing  fingerprint present in both
    resolved  in baseline, no longer in scan

Exit codes are severity-aware. The default is --fail-on=never which
prints the diff and exits 0 regardless. Override for CI gating:

    --fail-on=high          exit 2 if ANY actionable finding is
                            at or above 'high' (matches scan's gate)

    --fail-on=new-high      exit 2 if any NEW actionable finding is
                            at or above 'high' (the drift-gate use
                            case: PR introduced a regression)

    --fail-on=never         never exit non-zero on findings

Severity values: critical, high, medium, low, info.

Example workflow:

    compliancekit scan --output json --out-dir out/
    compliancekit baseline --in out/findings.json
    # commit .compliancekit/baseline.json

    # ... later, in CI ...
    compliancekit scan --output json --out-dir out/
    compliancekit diff .compliancekit/baseline.json out/findings.json \
        --fail-on=new-high`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(cmd.Context(), cmd.OutOrStdout(), stylerFor(cmd), args[0], args[1], opts)
		},
	}

	cmd.Flags().StringVar(&opts.failOn, "fail-on", "never",
		"severity threshold for non-zero exit: never | <sev> | new-<sev> (e.g. high, new-high)")
	return cmd
}

func runDiff(_ context.Context, w io.Writer, st *ui.Styler, baselinePath, findingsPath string, opts diffOptions) error {
	b, err := baseline.Load(baselinePath)
	if err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	current, err := loadFindingsForBaseline(findingsPath)
	if err != nil {
		return err
	}

	result := diff.Compute(b, current)
	renderDiff(w, st, result)

	return checkFailOnGate(opts.failOn, result)
}

// renderDiff prints the human-readable summary documented in
// ROADMAP.md v0.6:
//
//   - 2 new   (1 high, 1 medium)
//   - 1 resolved
//     = 23 existing
//     Hardening score: 76 -> 73 (-3)
func renderDiff(w io.Writer, st *ui.Styler, r diff.DiffResult) {
	addedMark := st.DiffMark(ui.DiffKindAdded)
	removedMark := st.DiffMark(ui.DiffKindRemoved)
	existingMark := st.DiffMark(ui.DiffKindExisting)

	// New findings get the bold-green + glyph treatment; the count
	// is also accented so the eye lands on it first.
	fmt.Fprintf(w, "%s %s new", addedMark, st.InStatus(fmt.Sprintf("%d", len(r.New)), compliancekit.StatusFail))
	if len(r.New) > 0 {
		fmt.Fprintf(w, "   %s", formatSeverityBreakdown(st, diff.CountsBySeverity(r.New)))
	}
	fmt.Fprintln(w)

	// Resolved get the dim-strikethrough treatment from DiffMark plus
	// a muted count — they're informational, not actionable.
	fmt.Fprintf(w, "%s %s resolved", removedMark, st.Muted(fmt.Sprintf("%d", len(r.Resolved))))
	if len(r.Resolved) > 0 {
		fmt.Fprintf(w, "  %s", formatSeverityBreakdown(st, diff.CountsBySeverityEntries(r.Resolved)))
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%s %s existing\n", existingMark, st.Muted(fmt.Sprintf("%d", len(r.Existing))))

	delta := r.CurrentScore - r.PreviousScore
	var deltaStr string
	switch {
	case delta > 0:
		deltaStr = st.InStatus(fmt.Sprintf("+%d", delta), compliancekit.StatusPass)
	case delta == 0:
		deltaStr = st.Muted("+0")
	default:
		// Negative delta = score got worse.
		deltaStr = st.InSeverity(fmt.Sprintf("%d", delta), compliancekit.SeverityHigh)
	}
	fmt.Fprintf(w, "Hardening score: %d %s %d (%s)\n",
		r.PreviousScore, st.Glyph("arrow"), r.CurrentScore, deltaStr)
}

// formatSeverityBreakdown produces "(1 [HIGH], 1 [MEDIUM])" style.
// Severities render in display order (critical -> info) with each
// chip colored by severity band.
func formatSeverityBreakdown(st *ui.Styler, counts map[string]int) string {
	order := []compliancekit.Severity{
		compliancekit.SeverityCritical,
		compliancekit.SeverityHigh,
		compliancekit.SeverityMedium,
		compliancekit.SeverityLow,
		compliancekit.SeverityInfo,
	}
	parts := []string{}
	for _, sev := range order {
		if n := counts[sev.String()]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, st.SeverityChip(sev)))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// checkFailOnGate inspects the --fail-on flag value and returns a
// non-zero ExitCodeError when the relevant condition is true.
//
// Accepted forms:
//
//	never           -> always exit 0
//	<severity>      -> exit 2 if any current finding is actionable
//	                   and at or above <severity>
//	new-<severity>  -> exit 2 if any NEW finding is actionable and
//	                   at or above <severity>
func checkFailOnGate(spec string, r diff.DiffResult) error {
	spec = strings.ToLower(strings.TrimSpace(spec))
	if spec == "" || spec == "never" {
		return nil
	}

	onlyNew := false
	sevStr := spec
	if strings.HasPrefix(spec, "new-") {
		onlyNew = true
		sevStr = strings.TrimPrefix(spec, "new-")
	}

	sev, err := compliancekit.ParseSeverity(sevStr)
	if err != nil {
		return fmt.Errorf("invalid --fail-on %q: %w", spec, err)
	}

	if onlyNew {
		if r.HasNewAtOrAbove(sev) {
			return NewExitCode(2, "new findings at or above %s severity", sev)
		}
		return nil
	}
	if r.HasActionableAtOrAbove(sev) {
		return NewExitCode(2, "findings at or above %s severity", sev)
	}
	return nil
}
