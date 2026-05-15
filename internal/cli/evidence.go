package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/config"
	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/evidence"
	"github.com/darpanzope/compliancekit/internal/frameworks"
)

// evidenceOptions are the flags accepted by `compliancekit evidence`.
type evidenceOptions struct {
	in         string
	out        string
	period     string
	includeRaw bool
	configPath string
	envName    string
}

func newEvidenceCmd() *cobra.Command {
	var opts evidenceOptions

	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Generate an audit-ready evidence pack from a scan",
		Long: `Evidence assembles an auditor-ready folder from a previous scan's
findings.json. Output includes:

  - per-framework, per-control folders with findings.json + control.md
  - control-mapping.csv (importable into Drata, Vanta, AuditBoard)
  - summary.html (auditor-readable index)
  - MANIFEST.sha256 (tamper-evidence; verify with 'sha256sum -c')

Frameworks shipped today: SOC 2 (TSC), ISO 27001:2022 Annex A, CIS
Controls v8.

By default, sensitive tokens (AWS keys, GitHub PATs, Slack tokens,
bearer headers, email addresses) are redacted from finding messages.
Pass --include-raw to disable redaction for the auditor-trusted case.

Examples:
  compliancekit evidence --in findings.json --out evidence/2026-Q2/
  compliancekit evidence --in findings.json --out pack/ --period 2026-05`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEvidence(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.in, "in", "findings.json", "path to a scan's findings.json")
	cmd.Flags().StringVar(&opts.out, "out", "", "output directory for the evidence pack (required)")
	cmd.Flags().StringVar(&opts.period, "period", "", "audit period label, e.g. 2026-Q2 (defaults to current quarter)")
	cmd.Flags().BoolVar(&opts.includeRaw, "include-raw", false, "skip redaction of sensitive tokens in finding messages")
	cmd.Flags().StringVar(&opts.configPath, "config", "", "path to compliancekit.yaml (loads tailoring rules from frameworks.tailoring)")
	cmd.Flags().StringVar(&opts.envName, "env", "", "load compliancekit.<env>.yaml")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

// runEvidence is the action body; split from the cobra wiring so it
// is unit-testable with explicit io.Writer + options.
func runEvidence(ctx context.Context, w io.Writer, opts evidenceOptions) error {
	if opts.in == "" {
		return fmt.Errorf("--in is required")
	}
	if opts.out == "" {
		return fmt.Errorf("--out is required")
	}

	findings, err := loadFindings(opts.in)
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		return fmt.Errorf("no findings in %s; nothing to package", opts.in)
	}

	fmt.Fprintf(w, "Generating evidence pack from %s (%d findings)...\n", opts.in, len(findings))

	tailoring, err := loadTailoring(opts.configPath, opts.envName, w)
	if err != nil {
		return fmt.Errorf("tailoring: %w", err)
	}

	res, err := evidence.Generate(ctx, findings, evidence.Options{
		OutDir:     opts.out,
		Period:     opts.period,
		IncludeRaw: opts.includeRaw,
		Generated:  time.Time{}, // let the package stamp it
		Tailoring:  tailoring,
	})
	if err != nil {
		return fmt.Errorf("evidence: %w", err)
	}

	printEvidenceSummary(w, res)
	return nil
}

// loadTailoring reads the v0.12+ frameworks.tailoring block from
// compliancekit.yaml (when --config is provided), validates it
// against the loaded framework catalog, and returns the resulting
// Tailoring. Returns (nil, nil) when no config path or no rules are
// declared so older flows pass through unchanged.
func loadTailoring(configPath, envName string, w io.Writer) (*frameworks.Tailoring, error) {
	if configPath == "" {
		return nil, nil //nolint:nilnil // intentional: "no config means no tailoring"
	}
	cfg, err := config.Load(config.LoadOptions{
		ConfigPath: configPath,
		EnvName:    envName,
	})
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if len(cfg.Tailoring) == 0 {
		return nil, nil //nolint:nilnil // config loaded but no rules declared — pass through unchanged
	}
	rules := make([]frameworks.TailoringRule, 0, len(cfg.Tailoring))
	for _, r := range cfg.Tailoring {
		rules = append(rules, frameworks.TailoringRule{
			Framework:     r.Framework,
			Control:       r.Control,
			Justification: r.Justification,
		})
	}
	t, err := frameworks.NewTailoring(rules)
	if err != nil {
		return nil, err
	}
	if probs := t.Validate(); len(probs) > 0 {
		for _, p := range probs {
			fmt.Fprintf(w, "  warning: %v\n", p)
		}
	}
	return t, nil
}

// findingsEnvelope is the minimal shape needed to read a scan's
// findings.json. The JSON reporter wraps the array in an envelope
// (schema, generated_at, summary, findings); we only need findings.
type findingsEnvelope struct {
	Findings []core.Finding `json:"findings"`
}

// loadFindings reads either a wrapped scan envelope or a raw findings
// array from path. Accepting both lets the operator hand-craft a
// subset file with `jq` and still feed it to `evidence`. The shape
// is detected from the first non-whitespace byte: '{' means envelope,
// '[' means raw array; anything else is rejected.
func loadFindings(path string) ([]core.Finding, error) {
	// G304: path is operator-supplied; this is the documented input.
	//nolint:gosec // operator-supplied input path
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("parse %s: file is empty", path)
	}
	switch trimmed[0] {
	case '{':
		var env findingsEnvelope
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

// printEvidenceSummary mirrors the shape promised in the ROADMAP demo
// (`SOC 2: 23 controls covered, 4 with findings`).
func printEvidenceSummary(w io.Writer, res evidence.Result) {
	for _, fr := range res.FrameworkResults {
		fmt.Fprintf(w, "%s: %d controls covered, %d with open findings\n",
			fr.FrameworkName, fr.ControlsCovered, fr.ControlsWithFail)
	}
	fmt.Fprintf(w, "Output: %s (%d files, MANIFEST.sha256 written)\n",
		res.OutDir, res.FilesWritten)
	fmt.Fprintf(w, "Auditor index: %s\n", res.SummaryHTMLPath)
	fmt.Fprintf(w, "Control mapping: %s\n", res.MappingCSVPath)
	if res.TailoringCount > 0 {
		fmt.Fprintf(w, "Tailoring: %s (%d controls scoped out)\n", res.TailoringPath, res.TailoringCount)
	}
}
