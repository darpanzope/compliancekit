package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/report"
)

// newRenderCmd builds `compliancekit render`, a re-rendering pass over
// an existing findings.json. Lets operators refresh a report against a
// newer compliancekit binary (new template, new chart, new chip
// layout) without paying for another scan.
//
// Intent: tight iteration loop for reporter work, and the natural way
// to test phase 6's `--baseline=path.json` flag on the HTML reporter
// without re-running a full scan.
func newRenderCmd() *cobra.Command {
	var (
		in           string
		format       string
		out          string
		baselinePath string
	)
	cmd := &cobra.Command{
		Use:   "render",
		Short: "Re-render a saved findings.json against any reporter format",
		Long: `render reads a previously-saved findings.json and writes a fresh
report in the requested format. The same reporter the scan command
uses runs here, so output is byte-identical to running ` + "`scan`" + ` against
the same findings — minus the actual scan cost.

Useful for:

  - re-rendering an HTML report after upgrading compliancekit
  - iterating on a templated reporter (HTML, Markdown) without
    re-scanning a 3000-finding fleet every time
  - regenerating a SARIF / OCSF artifact from an evidence pack

Examples:

  compliancekit render --in=findings.json --format=html --out=findings.html
  compliancekit render --in=findings.json --format=markdown   # stdout
  compliancekit render --in=./out/findings.json --format=sarif --out=out.sarif
  compliancekit render --in=findings.json --baseline=.compliancekit/baseline.json --out=findings.html
  compliancekit render --in=findings.json --baseline=.compliancekit/history/ --out=findings.html`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRender(cmd.OutOrStdout(), in, format, out, baselinePath)
		},
	}
	cmd.Flags().StringVar(&in, "in", "findings.json", "path to a scan's findings.json (or '-' for stdin)")
	cmd.Flags().StringVar(&format, "format", "html", "reporter format: html, json, markdown, sarif, ocsf")
	cmd.Flags().StringVar(&out, "out", "", "output path (default: stdout)")
	cmd.Flags().StringVar(&baselinePath, "baseline", "", "baseline.json file (or directory of baselines) to render trend sparklines + drift card against (html format only)")
	return cmd
}

func runRender(stdout io.Writer, in, format, out, baselinePath string) error {
	findings, err := readFindingsFile(in)
	if err != nil {
		return fmt.Errorf("read %s: %w", in, err)
	}
	r, err := report.New(format)
	if err != nil {
		return err
	}
	// --baseline only adds value to the HTML reporter (sparklines +
	// drift card). For other formats the flag is silently ignored, so
	// the operator can leave it in shell aliases without surprises.
	if baselinePath != "" {
		if htmlR, ok := r.(*report.HTMLReporter); ok {
			hist, err := report.LoadBaselineHistory(baselinePath)
			if err != nil {
				return fmt.Errorf("load baseline %s: %w", baselinePath, err)
			}
			r = htmlR.WithBaselines(hist)
		}
	}

	w := stdout
	if out != "" {
		if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(out), err)
		}
		f, err := os.Create(out) //nolint:gosec // operator-supplied path is intentional
		if err != nil {
			return fmt.Errorf("create %s: %w", out, err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := r.Render(context.Background(), findings, nil, w); err != nil {
		return fmt.Errorf("render %s: %w", format, err)
	}
	if out != "" {
		fmt.Fprintf(stdout, "wrote %s (%d findings, format=%s)\n", out, len(findings), format)
	}
	return nil
}
