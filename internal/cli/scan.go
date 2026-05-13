package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	do "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/config"
	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/engine"
	"github.com/darpanzope/compliancekit/internal/report"
)

type scanOptions struct {
	configPath string
	envName    string
	outDir     string
	formats    []string
	failOn     string
}

func newScanCmd() *cobra.Command {
	var opts scanOptions

	cmd := &cobra.Command{
		Use:   "scan [provider]",
		Short: "Scan enabled providers and report findings",
		Long: `Scan runs every check registered for the enabled providers and
writes findings in the configured output formats.

Optional positional argument restricts the scan to a single provider
(e.g. 'compliancekit scan digitalocean').

Exit codes:
  0  no findings at or above --fail-on severity
  1  generic error (config, network, build)
  2  findings at or above --fail-on severity present
  5  authentication failure`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var providerFilter string
			if len(args) > 0 {
				providerFilter = args[0]
			}
			return runScan(cmd.Context(), cmd.OutOrStdout(), opts, providerFilter)
		},
	}

	cmd.Flags().StringVar(&opts.configPath, "config", "", "path to compliancekit.yaml")
	cmd.Flags().StringVar(&opts.envName, "env", "", "load compliancekit.<env>.yaml")
	cmd.Flags().StringVar(&opts.outDir, "out-dir", "", "output directory (overrides config)")
	cmd.Flags().StringSliceVar(&opts.formats, "output", nil, "output format(s) (overrides config)")
	cmd.Flags().StringVar(&opts.failOn, "fail-on", "", "severity threshold for non-zero exit (overrides config)")

	return cmd
}

func runScan(ctx context.Context, w io.Writer, opts scanOptions, providerFilter string) error {
	cfg, err := config.Load(config.LoadOptions{
		ConfigPath: opts.configPath,
		EnvName:    opts.envName,
	})
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Flag overrides on config.
	if opts.outDir != "" {
		cfg.Output.OutDir = opts.outDir
	}
	if len(opts.formats) > 0 {
		cfg.Output.Format = opts.formats
	}
	if opts.failOn != "" {
		cfg.Severity.FailOn = opts.failOn
	}
	failOnLevel, err := cfg.Severity.FailOnLevel()
	if err != nil {
		return fmt.Errorf("invalid fail_on severity: %w", err)
	}

	collectors, err := buildCollectors(cfg, providerFilter)
	if err != nil {
		return err
	}
	if len(collectors) == 0 {
		return fmt.Errorf("no providers enabled or selected")
	}

	reporters, err := buildReporters(cfg.Output.Format)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "scanning %s (%d checks)...\n",
		describeCollectors(collectors), core.RegisteredCount())

	eng := engine.New(collectors, core.DefaultRegistry())
	result, err := eng.Run(ctx)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	if err := os.MkdirAll(cfg.Output.OutDir, 0o755); err != nil {
		return fmt.Errorf("create out_dir %s: %w", cfg.Output.OutDir, err)
	}
	for _, r := range reporters {
		path := filepath.Join(cfg.Output.OutDir, "findings."+r.Format())
		if err := writeReport(ctx, r, result, path); err != nil {
			return err
		}
		fmt.Fprintf(w, "wrote %s\n", path)
	}

	printSummary(w, result.Findings)

	if hasActionableAtOrAbove(result.Findings, failOnLevel) {
		return NewExitCode(2, "findings at or above %s severity present", failOnLevel)
	}
	return nil
}

// buildCollectors constructs the set of collectors from config. The
// providerFilter, when non-empty, restricts the result to a single
// provider (matches the positional argument to `scan`).
func buildCollectors(cfg *config.Config, providerFilter string) ([]core.Collector, error) {
	var collectors []core.Collector

	if cfg.Providers.DigitalOcean.Enabled && (providerFilter == "" || providerFilter == "digitalocean") {
		tokenEnv := cfg.Providers.DigitalOcean.TokenEnv
		token := os.Getenv(tokenEnv)
		if token == "" {
			return nil, NewExitCode(5, "env var %s is unset; cannot scan digitalocean", tokenEnv)
		}
		collectors = append(collectors, do.New(token))
	}

	// Future: linux (v0.2), kubernetes (v0.8), hetzner (v0.7).

	return collectors, nil
}

// buildReporters constructs the reporter set from the configured format list.
func buildReporters(formats []string) ([]core.Reporter, error) {
	if len(formats) == 0 {
		formats = []string{report.FormatJSON}
	}
	var reporters []core.Reporter
	for _, f := range formats {
		r, err := report.New(f)
		if err != nil {
			return nil, fmt.Errorf("output format %q: %w", f, err)
		}
		reporters = append(reporters, r)
	}
	return reporters, nil
}

// writeReport opens path and invokes r.Render.
func writeReport(ctx context.Context, r core.Reporter, result engine.Result, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if err := r.Render(ctx, result.Findings, result.Graph, f); err != nil {
		return fmt.Errorf("render %s: %w", r.Format(), err)
	}
	return nil
}

// hasActionableAtOrAbove reports whether any Fail or Error finding is
// at or above the given severity.
func hasActionableAtOrAbove(findings []core.Finding, level core.Severity) bool {
	for _, f := range findings {
		if f.Status.IsActionable() && f.Severity >= level {
			return true
		}
	}
	return false
}

func describeCollectors(cs []core.Collector) string {
	if len(cs) == 1 {
		return cs[0].Name()
	}
	out := ""
	for i, c := range cs {
		if i > 0 {
			out += ", "
		}
		out += c.Name()
	}
	return out
}

// printSummary writes the end-of-scan summary to w. Matches the shape
// shown in ROADMAP.md's v0.1 demo block.
func printSummary(w io.Writer, findings []core.Finding) {
	var (
		fail, errored int
		critical, high, medium, low, info int
	)
	for _, f := range findings {
		switch f.Status {
		case core.StatusFail:
			fail++
		case core.StatusError:
			errored++
		}
		if !f.Status.IsActionable() {
			continue
		}
		switch f.Severity {
		case core.SeverityCritical:
			critical++
		case core.SeverityHigh:
			high++
		case core.SeverityMedium:
			medium++
		case core.SeverityLow:
			low++
		case core.SeverityInfo:
			info++
		}
	}

	fmt.Fprintf(w, "\n%d findings", fail+errored)
	if critical+high+medium+low+info > 0 {
		fmt.Fprintf(w, " (")
		first := true
		writeCount := func(label string, n int) {
			if n == 0 {
				return
			}
			if !first {
				fmt.Fprintf(w, ", ")
			}
			fmt.Fprintf(w, "%d %s", n, label)
			first = false
		}
		writeCount("critical", critical)
		writeCount("high", high)
		writeCount("medium", medium)
		writeCount("low", low)
		writeCount("info", info)
		fmt.Fprintf(w, ")")
	}
	fmt.Fprintln(w)
}
