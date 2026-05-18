package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/baseline"
	"github.com/darpanzope/compliancekit/internal/diff"
	"github.com/darpanzope/compliancekit/internal/score"
	"github.com/darpanzope/compliancekit/internal/ui"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// newMotdCmd builds `compliancekit motd`, the single-screen
// "your fleet at a glance" command. Reads a findings.json (defaults
// to ./out/findings.json, the standard scan output) and renders a
// styled summary card: severity counts, hardening score, top-3
// most-actionable findings, and baseline drift if a baseline is
// available.
//
// Intent: the thing you `alias mc=compliancekit motd` and run after
// every coffee.
func newMotdCmd() *cobra.Command {
	var (
		in       string
		baseline string
	)
	cmd := &cobra.Command{
		Use:   "motd",
		Short: "Single-screen fleet-at-a-glance summary of the last scan",
		Long: `motd reads a previously-saved findings.json and renders a
single-screen styled summary: total findings, severity breakdown,
hardening score, top 3 most actionable findings, and (when a
baseline is available) drift since the last accepted state.

Intended for human consumption, not pipelines. The output uses
colors + Unicode glyphs in TTY mode and falls back to plain text
under NO_COLOR / piped output / --no-color.

Typical use:

  compliancekit motd                              # default ./out/findings.json
  compliancekit motd --in=evidence/findings.json  # arbitrary path
  alias mc='compliancekit motd'                   # after every coffee`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMotd(cmd.OutOrStdout(), stylerFor(cmd), in, baseline)
		},
	}
	cmd.Flags().StringVar(&in, "in", "./out/findings.json", "path to findings JSON (or '-' for stdin)")
	cmd.Flags().StringVar(&baseline, "baseline", ".compliancekit/baseline.json", "path to baseline.json for drift section (skipped if missing)")
	return cmd
}

func runMotd(w io.Writer, st *ui.Styler, in, baselinePath string) error {
	findings, err := readFindingsFile(in)
	if err != nil {
		return fmt.Errorf("read %s: %w", in, err)
	}

	renderMotdHeader(w, st, findings)
	renderMotdScore(w, st, findings)
	renderMotdTopActionable(w, st, findings, 3)
	renderMotdDrift(w, st, baselinePath, findings)
	return nil
}

// readFindingsFile loads a findings.json (or '-' for stdin) into
// the slice of public Findings.
func readFindingsFile(path string) ([]compliancekit.Finding, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path) //nolint:gosec // operator-supplied path is intentional
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	var findings []compliancekit.Finding
	if err := json.NewDecoder(r).Decode(&findings); err != nil {
		return nil, err
	}
	return findings, nil
}

// renderMotdHeader writes the top card: total findings + severity
// breakdown as a horizontal chip row.
func renderMotdHeader(w io.Writer, st *ui.Styler, findings []compliancekit.Finding) {
	counts := countsBySeverity(findings)
	total := counts[compliancekit.SeverityCritical] +
		counts[compliancekit.SeverityHigh] +
		counts[compliancekit.SeverityMedium] +
		counts[compliancekit.SeverityLow] +
		counts[compliancekit.SeverityInfo]

	if total == 0 {
		fmt.Fprintf(w, "%s %s — 0 actionable findings across this scan.\n",
			st.Glyph("pass"), st.Bold("All clear"))
		return
	}

	fmt.Fprintf(w, "%s %s actionable findings:\n",
		st.Glyph("fail"),
		st.Accent(fmt.Sprintf("%d", total)))
	for _, sev := range []compliancekit.Severity{
		compliancekit.SeverityCritical,
		compliancekit.SeverityHigh,
		compliancekit.SeverityMedium,
		compliancekit.SeverityLow,
		compliancekit.SeverityInfo,
	} {
		if n := counts[sev]; n > 0 {
			fmt.Fprintf(w, "  %s  %d\n", st.SeverityChip(sev), n)
		}
	}
}

// renderMotdScore writes the hardening score line with band color.
func renderMotdScore(w io.Writer, st *ui.Styler, findings []compliancekit.Finding) {
	s := score.Compute(findings)
	fmt.Fprintf(w, "\nHardening score: %s/100 (coverage %d%%)\n",
		scoreChip(st, s.Score), s.Coverage)
}

// renderMotdTopActionable writes the top-N most actionable findings
// ordered by severity (critical first) then check ID.
func renderMotdTopActionable(w io.Writer, st *ui.Styler, findings []compliancekit.Finding, n int) {
	actionable := make([]compliancekit.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Status.IsActionable() {
			actionable = append(actionable, f)
		}
	}
	if len(actionable) == 0 {
		return
	}
	sort.SliceStable(actionable, func(i, j int) bool {
		if actionable[i].Severity != actionable[j].Severity {
			return actionable[i].Severity > actionable[j].Severity
		}
		return actionable[i].CheckID < actionable[j].CheckID
	})
	limit := n
	if limit > len(actionable) {
		limit = len(actionable)
	}
	fmt.Fprintf(w, "\n%s\n", st.Bold(fmt.Sprintf("Top %d:", limit)))
	for i := 0; i < limit; i++ {
		f := actionable[i]
		fmt.Fprintf(w, "  %s %s %s %s %s\n",
			st.Muted(st.Glyph("bullet")),
			st.SeverityChip(f.Severity),
			st.Accent(f.CheckID),
			st.Muted("on"),
			f.Resource.Name)
	}
}

// renderMotdDrift writes the drift-vs-baseline section if a
// baseline file exists. Silent when missing — operators without a
// baseline still get a useful motd view.
func renderMotdDrift(w io.Writer, st *ui.Styler, baselinePath string, current []compliancekit.Finding) {
	if baselinePath == "" {
		return
	}
	b, err := baseline.Load(baselinePath)
	if err != nil {
		// Missing baseline isn't an error in motd context — operators
		// run motd before they ever capture a baseline.
		return
	}
	r := diff.Compute(b, current)
	fmt.Fprintf(w, "\n%s vs baseline: %s new, %s resolved, %d existing\n",
		st.Bold("Drift"),
		st.InStatus(fmt.Sprintf("%d", len(r.New)), compliancekit.StatusFail),
		st.InStatus(fmt.Sprintf("%d", len(r.Resolved)), compliancekit.StatusPass),
		len(r.Existing))
}

// countsBySeverity returns the per-severity count of actionable
// findings. Pass / skip are excluded — they don't drive motd
// urgency.
func countsBySeverity(findings []compliancekit.Finding) map[compliancekit.Severity]int {
	counts := map[compliancekit.Severity]int{}
	for _, f := range findings {
		if !f.Status.IsActionable() {
			continue
		}
		counts[f.Severity]++
	}
	return counts
}
