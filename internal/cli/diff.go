package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/baseline"
	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/diff"
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
			return runDiff(cmd.Context(), cmd.OutOrStdout(), args[0], args[1], opts)
		},
	}

	cmd.Flags().StringVar(&opts.failOn, "fail-on", "never",
		"severity threshold for non-zero exit: never | <sev> | new-<sev> (e.g. high, new-high)")
	return cmd
}

func runDiff(_ context.Context, w io.Writer, baselinePath, findingsPath string, opts diffOptions) error {
	b, err := baseline.Load(baselinePath)
	if err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	current, err := loadFindingsForBaseline(findingsPath)
	if err != nil {
		return err
	}

	result := diff.Compute(b, current)
	renderDiff(w, result)

	return checkFailOnGate(opts.failOn, result)
}

// renderDiff prints the human-readable summary documented in
// ROADMAP.md v0.6:
//
//   - 2 new   (1 high, 1 medium)
//   - 1 resolved
//     = 23 existing
//     Hardening score: 76 -> 73 (-3)
func renderDiff(w io.Writer, r diff.DiffResult) {
	fmt.Fprintf(w, "+ %d new", len(r.New))
	if len(r.New) > 0 {
		fmt.Fprintf(w, "   %s", formatSeverityBreakdown(diff.CountsBySeverity(r.New)))
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "- %d resolved", len(r.Resolved))
	if len(r.Resolved) > 0 {
		fmt.Fprintf(w, "  %s", formatSeverityBreakdown(diff.CountsBySeverityEntries(r.Resolved)))
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "= %d existing\n", len(r.Existing))

	delta := r.CurrentScore - r.PreviousScore
	sign := ""
	if delta >= 0 {
		sign = "+"
	}
	fmt.Fprintf(w, "Hardening score: %d -> %d (%s%d)\n", r.PreviousScore, r.CurrentScore, sign, delta)
}

// formatSeverityBreakdown produces "(1 high, 1 medium)" style.
// Severities render in display order (critical -> info).
func formatSeverityBreakdown(counts map[string]int) string {
	order := []string{"critical", "high", "medium", "low", "info"}
	parts := []string{}
	for _, sev := range order {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
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

	sev, err := core.ParseSeverity(sevStr)
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
