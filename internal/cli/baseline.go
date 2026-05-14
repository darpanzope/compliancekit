package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/baseline"
	"github.com/darpanzope/compliancekit/internal/core"
)

type baselineOptions struct {
	in  string
	out string
}

func newBaselineCmd() *cobra.Command {
	var opts baselineOptions

	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Capture current findings as the accepted baseline",
		Long: `Baseline reads a scan's findings.json and writes a compact, sorted
record of every finding's fingerprint to .compliancekit/baseline.json
(the default; override with --out).

The next scan's ` + "`compliancekit diff`" + ` compares against this baseline
and classifies findings as new (not in baseline), existing (same
fingerprint), or resolved (in baseline but not in current scan).

Baselines are gitignored by default. Commit one deliberately if you
want PR-level drift gating that fails the build whenever new findings
appear since the last accepted state.

Schema is versioned (` + "`compliancekit.baseline.v1`" + `); a future change
will bump the schema, not silently invalidate older files.

Example:

  compliancekit scan --output json --out-dir out/
  compliancekit baseline --in out/findings.json
  # commit .compliancekit/baseline.json if you want PR drift gating

  # later, drift check:
  compliancekit scan --output json --out-dir out/
  compliancekit diff .compliancekit/baseline.json out/findings.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBaseline(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.in, "in", "findings.json", "path to a scan's findings.json")
	cmd.Flags().StringVar(&opts.out, "out", baseline.DefaultPath, "path to write the baseline")
	return cmd
}

func runBaseline(_ context.Context, w io.Writer, opts baselineOptions) error {
	if opts.in == "" {
		return fmt.Errorf("--in is required")
	}
	if opts.out == "" {
		return fmt.Errorf("--out is required")
	}

	findings, err := loadFindingsForBaseline(opts.in)
	if err != nil {
		return err
	}

	b := baseline.Capture(findings, time.Now())
	if err := baseline.Save(b, opts.out); err != nil {
		return fmt.Errorf("baseline: %w", err)
	}

	fmt.Fprintf(w, "Captured %d findings as baseline in %s\n", len(b.Entries), opts.out)
	fmt.Fprintf(w, "Hardening score: %d/100 (coverage %d%%)\n", b.Score, b.Coverage)
	return nil
}

// loadFindingsForBaseline reads either the wrapped scan envelope or
// a raw findings array. Same dual-shape support as the evidence
// subcommand -- a jq-trimmed subset is a valid input.
func loadFindingsForBaseline(path string) ([]core.Finding, error) {
	// G304: path is operator-supplied; this is the documented input.
	//nolint:gosec // operator-supplied input path
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	// Detect shape from first non-whitespace byte: '{' = envelope, '[' = raw array.
	for _, b := range data {
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
			continue
		}
		switch b {
		case '{':
			var env struct {
				Findings []core.Finding `json:"findings"`
			}
			if err := json.Unmarshal(data, &env); err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			return env.Findings, nil
		case '[':
			var raw []core.Finding
			if err := json.Unmarshal(data, &raw); err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			return raw, nil
		default:
			return nil, fmt.Errorf("parse %s: expected JSON object or array", path)
		}
	}
	return nil, fmt.Errorf("parse %s: file is empty", path)
}
