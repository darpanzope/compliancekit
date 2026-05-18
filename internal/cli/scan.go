package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	do "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	hetznercol "github.com/darpanzope/compliancekit/internal/collectors/hetzner"
	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/config"
	"github.com/darpanzope/compliancekit/internal/engine"
	"github.com/darpanzope/compliancekit/internal/profile"
	"github.com/darpanzope/compliancekit/internal/report"
	"github.com/darpanzope/compliancekit/internal/score"
	"github.com/darpanzope/compliancekit/internal/ui"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"

	// v0.22.1 — side-effect imports register every remediation
	// Strategy with remediate.Default so the HTML reporter can pull
	// per-format snippets inline (one tab per format under the
	// "Remediation" details block per finding). Without these imports
	// the registry would be empty at scan time + the HTML report
	// would surface only the static Check.Remediation text.
	_ "github.com/darpanzope/compliancekit/internal/remediate/ansible"
	_ "github.com/darpanzope/compliancekit/internal/remediate/awscli"
	_ "github.com/darpanzope/compliancekit/internal/remediate/azcli"
	_ "github.com/darpanzope/compliancekit/internal/remediate/bash"
	_ "github.com/darpanzope/compliancekit/internal/remediate/doctl"
	_ "github.com/darpanzope/compliancekit/internal/remediate/gcloud"
	_ "github.com/darpanzope/compliancekit/internal/remediate/hcloud"
	_ "github.com/darpanzope/compliancekit/internal/remediate/helm"
	_ "github.com/darpanzope/compliancekit/internal/remediate/kubectl"
	_ "github.com/darpanzope/compliancekit/internal/remediate/terraform"
)

type scanOptions struct {
	configPath   string
	envName      string
	outDir       string
	formats      []string
	failOn       string
	profile      string
	pushServer   string
	pushAPIToken string
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
			return runScan(cmd.Context(), cmd.OutOrStdout(), stylerFor(cmd), opts, providerFilter)
		},
	}

	cmd.Flags().StringVar(&opts.configPath, "config", "", "path to compliancekit.yaml")
	cmd.Flags().StringVar(&opts.envName, "env", "", "load compliancekit.<env>.yaml")
	cmd.Flags().StringVar(&opts.outDir, "out-dir", "", "output directory (overrides config)")
	cmd.Flags().StringSliceVar(&opts.formats, "output", nil, "output format(s) (overrides config)")
	cmd.Flags().StringVar(&opts.failOn, "fail-on", "", "severity threshold for non-zero exit (overrides config)")
	cmd.Flags().StringVar(&opts.profile, "profile", "", "named profile from compliancekit.yaml `profiles:` to restrict which checks run")
	cmd.Flags().StringVar(&opts.pushServer, "push-to-server", "", "after the scan completes, POST findings to a compliancekit daemon (e.g. https://compliance.acme.com)")
	cmd.Flags().StringVar(&opts.pushAPIToken, "api-token", "", "Bearer token for --push-to-server (defaults to $CK_API_TOKEN)")

	return cmd
}

//nolint:gocyclo // sequential pipeline (config → collect → reporters → register → run → ingest → waivers → output → summary → push) — splitting any further would hide the order
func runScan(ctx context.Context, w io.Writer, st *ui.Styler, opts scanOptions, providerFilter string) error {
	cfg, err := config.Load(config.LoadOptions{
		ConfigPath: opts.configPath,
		EnvName:    opts.envName,
	})
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	applyScanFlagOverrides(cfg, opts)
	failOnLevel, err := cfg.Severity.FailOnLevel()
	if err != nil {
		return fmt.Errorf("invalid fail_on severity: %w", err)
	}

	collectors, err := buildCollectors(ctx, cfg, providerFilter)
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

	registry, err := buildRegistry(cfg)
	if err != nil {
		return err
	}

	if cfg.Profile != "" {
		fmt.Fprintf(w, "%s scanning %s (profile=%s, %s checks)...\n",
			st.Glyph("arrow"), st.Accent(describeCollectors(collectors)),
			st.Bold(cfg.Profile), st.Accent(fmt.Sprintf("%d", len(registry.Checks()))))
	} else {
		fmt.Fprintf(w, "%s scanning %s (%s checks)...\n",
			st.Glyph("arrow"), st.Accent(describeCollectors(collectors)),
			st.Accent(fmt.Sprintf("%d", len(registry.Checks()))))
	}

	eng := engine.New(collectors, registry)
	result, err := eng.Run(ctx)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	if err := mergeConfigIngest(ctx, w, &result, cfg.Ingest); err != nil {
		return err
	}

	if err := applyWaivers(w, &result, cfg); err != nil {
		return err
	}

	if err := os.MkdirAll(cfg.Output.OutDir, 0o750); err != nil {
		return fmt.Errorf("create out_dir %s: %w", cfg.Output.OutDir, err)
	}
	for _, r := range reporters {
		path := filepath.Join(cfg.Output.OutDir, "findings."+r.Format())
		if err := writeReport(ctx, r, result, path); err != nil {
			return err
		}
		fmt.Fprintf(w, "%s wrote %s\n", st.Muted("·"), st.Muted(path))
	}

	printSummary(w, st, result.Findings)

	if opts.pushServer != "" {
		maybePushScan(ctx, w, st, opts, cfg, collectors, result)
	}

	if hasActionableAtOrAbove(result.Findings, failOnLevel) {
		return NewExitCode(2, "findings at or above %s severity present", failOnLevel)
	}
	return nil
}

// providerSlice extracts the slice of provider names from the
// collectors used in the scan; the daemon's scans table stores them
// as a JSON array so the UI can filter by source provider.
func providerSlice(collectors []compliancekit.Collector) []string {
	out := make([]string, 0, len(collectors))
	for _, c := range collectors {
		out = append(out, c.Name())
	}
	return out
}

// maybePushScan is split out of runScan so the cyclomatic-complexity
// linter doesn't complain about the conditional push branch. Same
// observable behavior as inlining it: token resolution + push +
// pass/fail logging.
func maybePushScan(ctx context.Context, w io.Writer, st *ui.Styler, opts scanOptions, cfg *config.Config, collectors []compliancekit.Collector, result engine.Result) {
	token := opts.pushAPIToken
	if token == "" {
		token = os.Getenv("CK_API_TOKEN")
	}
	providers := providerSlice(collectors)
	frameworks := append([]string(nil), cfg.Frameworks...)
	scanID, pushErr := pushToServer(ctx, opts.pushServer, token, result, providers, frameworks)
	if pushErr != nil {
		fmt.Fprintf(w, "%s push to %s failed: %v (local scan results unaffected)\n",
			st.Glyph("warn"), opts.pushServer, pushErr)
		return
	}
	fmt.Fprintf(w, "%s pushed to %s (scan_id=%s)\n",
		st.Glyph("pass"), st.Accent(opts.pushServer), st.Muted(scanID))
}

// buildCollectors constructs the set of collectors from config. The
// providerFilter, when non-empty, restricts the result to a single
// provider (matches the positional argument to `scan`).
//
// Per-provider construction lives in individual buildXCollector
// helpers so this function stays under gocyclo's 15-edge ceiling
// as new providers land.
func buildCollectors(ctx context.Context, cfg *config.Config, providerFilter string) ([]compliancekit.Collector, error) {
	var collectors []compliancekit.Collector
	for _, build := range []func(context.Context, *config.Config, string) (compliancekit.Collector, error){
		buildDOCollector,
		buildLinuxCollector,
		buildAWSCollector,
		buildGCPCollector,
		buildHetznerCollector,
		buildKubernetesCollector,
	} {
		c, err := build(ctx, cfg, providerFilter)
		if err != nil {
			return nil, err
		}
		if c != nil {
			collectors = append(collectors, c)
		}
	}
	return collectors, nil
}

func providerSelected(name, filter string) bool {
	return filter == "" || filter == name
}

func buildDOCollector(_ context.Context, cfg *config.Config, filter string) (compliancekit.Collector, error) {
	if !cfg.Providers.DigitalOcean.Enabled || !providerSelected("digitalocean", filter) {
		return nil, nil
	}
	tokenEnv := cfg.Providers.DigitalOcean.TokenEnv
	token := os.Getenv(tokenEnv)
	if token == "" {
		return nil, NewExitCode(5, "env var %s is unset; cannot scan digitalocean", tokenEnv)
	}
	return do.New(token), nil
}

func buildLinuxCollector(_ context.Context, cfg *config.Config, filter string) (compliancekit.Collector, error) {
	if !cfg.Providers.Linux.Enabled || !providerSelected("linux", filter) {
		return nil, nil
	}
	inv, err := linuxcol.LoadInventory(cfg.Providers.Linux.Inventory)
	if err != nil {
		return nil, fmt.Errorf("linux inventory: %w", err)
	}
	return linuxcol.New(inv, cfg.Providers.Linux.SSH), nil
}

func buildAWSCollector(ctx context.Context, cfg *config.Config, filter string) (compliancekit.Collector, error) {
	if !cfg.Providers.AWS.Enabled || !providerSelected("aws", filter) {
		return nil, nil
	}
	// AWS_PROFILE / AWS_ROLE_ARN env vars are also honored by the
	// SDK directly; only override when the config supplies a value
	// so an operator can mix-and-match config and env.
	if cfg.Providers.AWS.Profile != "" {
		_ = os.Setenv("AWS_PROFILE", cfg.Providers.AWS.Profile)
	}
	if cfg.Providers.AWS.RoleARN != "" {
		_ = os.Setenv("AWS_ROLE_ARN", cfg.Providers.AWS.RoleARN)
	}
	awsCol, err := awscol.New(ctx, awscol.Options{
		Regions: cfg.Providers.AWS.Regions,
	})
	if err != nil {
		return nil, NewExitCode(5, "aws: %v", err)
	}
	return awsCol, nil
}

func buildGCPCollector(ctx context.Context, cfg *config.Config, filter string) (compliancekit.Collector, error) {
	if !cfg.Providers.GCP.Enabled || !providerSelected("gcp", filter) {
		return nil, nil
	}
	// Authentication uses Application Default Credentials --
	// GOOGLE_APPLICATION_CREDENTIALS, gcloud, metadata server,
	// or Workload Identity Federation. Projects defaults to the
	// credential's default project when empty.
	gc, err := gcpcol.New(ctx, gcpcol.Options{
		Projects: cfg.Providers.GCP.Projects,
	})
	if err != nil {
		return nil, NewExitCode(5, "gcp: %v", err)
	}
	return gc, nil
}

func buildHetznerCollector(_ context.Context, cfg *config.Config, filter string) (compliancekit.Collector, error) {
	if !cfg.Providers.Hetzner.Enabled || !providerSelected("hetzner", filter) {
		return nil, nil
	}
	tokenEnv := cfg.Providers.Hetzner.TokenEnv
	token := os.Getenv(tokenEnv)
	if token == "" {
		return nil, NewExitCode(5, "env var %s is unset; cannot scan hetzner", tokenEnv)
	}
	return hetznercol.New(token), nil
}

func buildKubernetesCollector(_ context.Context, cfg *config.Config, filter string) (compliancekit.Collector, error) {
	if !cfg.Providers.Kubernetes.Enabled || !providerSelected("kubernetes", filter) {
		return nil, nil
	}
	// Kubeconfig resolution follows the standard chain: explicit
	// path from config, then KUBECONFIG env, then ~/.kube/config.
	// Auth failure surfaces as exit code 5 like the other clouds.
	col, err := k8scol.New(k8scol.Options{
		KubeconfigPath:    cfg.Providers.Kubernetes.Kubeconfig,
		Contexts:          cfg.Providers.Kubernetes.Contexts,
		Namespaces:        cfg.Providers.Kubernetes.Namespaces,
		ExcludeNamespaces: cfg.Providers.Kubernetes.ExcludeNamespaces,
	})
	if err != nil {
		return nil, NewExitCode(5, "kubernetes: %v", err)
	}
	return col, nil
}

// applyScanFlagOverrides copies non-empty flag values from opts into
// cfg. Split out of runScan so the latter stays under gocyclo's
// 15-edge ceiling now that profile selection is a fourth override.
func applyScanFlagOverrides(cfg *config.Config, opts scanOptions) {
	if opts.outDir != "" {
		cfg.Output.OutDir = opts.outDir
	}
	if len(opts.formats) > 0 {
		cfg.Output.Format = opts.formats
	}
	if opts.failOn != "" {
		cfg.Severity.FailOn = opts.failOn
	}
	if opts.profile != "" {
		cfg.Profile = opts.profile
	}
}

// buildRegistry returns the registry to hand to the engine. With no
// profile set, it's the default registry as-is. With cfg.Profile
// pointing at a named entry under cfg.Profiles, the surviving subset
// is copied into a fresh registry so the engine iterates the smaller
// set without engine.New needing to know about profiles at all.
func buildRegistry(cfg *config.Config) (*compliancekit.Registry, error) {
	if cfg.Profile == "" {
		return compliancekit.DefaultRegistry(), nil
	}
	pc, ok := cfg.Profiles[cfg.Profile]
	if !ok {
		return nil, fmt.Errorf("profile %q is not defined under `profiles:` in %s",
			cfg.Profile, cfg.SourcePath)
	}
	p := profile.Profile{
		Name:              cfg.Profile,
		Description:       pc.Description,
		IncludeProviders:  pc.IncludeProviders,
		ExcludeProviders:  pc.ExcludeProviders,
		IncludeSeverities: pc.IncludeSeverities,
		IncludeFrameworks: pc.IncludeFrameworks,
		IncludeTags:       pc.IncludeTags,
		ExcludeTags:       pc.ExcludeTags,
		IncludeIDs:        pc.IncludeIDs,
		ExcludeIDs:        pc.ExcludeIDs,
	}
	all := compliancekit.DefaultRegistry()
	surviving, err := p.Filter(all.Checks())
	if err != nil {
		return nil, err
	}
	filtered := compliancekit.NewRegistry()
	for _, c := range surviving {
		fn, ok := all.Get(c.ID)
		if !ok {
			// Should not happen -- p.Filter returned a check that the
			// registry doesn't have a function for. Defensive guard.
			return nil, fmt.Errorf("internal: check %q in registry metadata but no func", c.ID)
		}
		filtered.Register(c, fn)
	}
	return filtered, nil
}

// buildReporters constructs the reporter set from the configured format list.
func buildReporters(formats []string) ([]compliancekit.Reporter, error) {
	if len(formats) == 0 {
		formats = []string{report.FormatJSON}
	}
	reporters := make([]compliancekit.Reporter, 0, len(formats))
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
func writeReport(ctx context.Context, r compliancekit.Reporter, result engine.Result, path string) error {
	// path is composed from cfg.Output.OutDir (operator-controlled) and a
	// fixed-suffix filename derived from the reporter format. There is no
	// untrusted input here; the gosec G304 warning is a false positive.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // path derives from operator config
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
func hasActionableAtOrAbove(findings []compliancekit.Finding, level compliancekit.Severity) bool {
	for _, f := range findings {
		if f.Status.IsActionable() && f.Severity >= level {
			return true
		}
	}
	return false
}

func describeCollectors(cs []compliancekit.Collector) string {
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
// shown in ROADMAP.md's v0.1 demo block. The styler colors the per-
// severity counts and the hardening-score band; pass a plain-mode
// styler (Color=false) for byte-stable CI output.
func printSummary(w io.Writer, st *ui.Styler, findings []compliancekit.Finding) {
	var (
		fail, errored                     int
		critical, high, medium, low, info int
	)
	for _, f := range findings {
		switch f.Status {
		case compliancekit.StatusFail:
			fail++
		case compliancekit.StatusError:
			errored++
		}
		if !f.Status.IsActionable() {
			continue
		}
		switch f.Severity {
		case compliancekit.SeverityCritical:
			critical++
		case compliancekit.SeverityHigh:
			high++
		case compliancekit.SeverityMedium:
			medium++
		case compliancekit.SeverityLow:
			low++
		case compliancekit.SeverityInfo:
			info++
		}
	}

	total := fail + errored
	if total == 0 {
		fmt.Fprintf(w, "\n%s 0 findings\n", st.Glyph("pass"))
	} else {
		fmt.Fprintf(w, "\n%s %s findings", st.Glyph("fail"), st.Accent(fmt.Sprintf("%d", total)))
	}

	if critical+high+medium+low+info > 0 {
		fmt.Fprintf(w, " (")
		first := true
		writeCount := func(sev compliancekit.Severity, n int) {
			if n == 0 {
				return
			}
			if !first {
				fmt.Fprintf(w, ", ")
			}
			fmt.Fprintf(w, "%d %s", n, st.SeverityChip(sev))
			first = false
		}
		writeCount(compliancekit.SeverityCritical, critical)
		writeCount(compliancekit.SeverityHigh, high)
		writeCount(compliancekit.SeverityMedium, medium)
		writeCount(compliancekit.SeverityLow, low)
		writeCount(compliancekit.SeverityInfo, info)
		fmt.Fprintf(w, ")")
		fmt.Fprintln(w)
	} else if total > 0 {
		fmt.Fprintln(w)
	}

	// Hardening score per DECISIONS.md ADR-008. Always emitted, even
	// when there are zero findings (empty scan reads as 100/100,
	// honest given the Coverage parallel metric).
	s := score.Compute(findings)
	fmt.Fprintf(w, "Hardening score: %s/100 (coverage %d%%)\n", scoreChip(st, s.Score), s.Coverage)
}

// scoreChip colors the score number per band: ≥90 info (green-ish
// in palette), 70-89 medium, 50-69 high, <50 critical. Falls through
// to plain when the styler is in plain mode.
func scoreChip(st *ui.Styler, score int) string {
	text := fmt.Sprintf("%d", score)
	switch {
	case score >= 90:
		return st.InSeverity(text, compliancekit.SeverityInfo)
	case score >= 70:
		return st.InSeverity(text, compliancekit.SeverityMedium)
	case score >= 50:
		return st.InSeverity(text, compliancekit.SeverityHigh)
	default:
		return st.InSeverity(text, compliancekit.SeverityCritical)
	}
}
