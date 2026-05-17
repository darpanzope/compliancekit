package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	do "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/config"
	"github.com/darpanzope/compliancekit/internal/notify"
)

// doctorOptions holds the parsed flags and dependencies for the doctor
// subcommand. The probe func is overridable so tests can avoid hitting
// the real DO API.
type doctorOptions struct {
	configPath  string
	envName     string
	checkConfig bool

	// doProbe is the DigitalOcean API probe. Defaults to do.Probe (real
	// HTTPS to api.digitalocean.com) when nil; tests inject a stub.
	doProbe func(ctx context.Context, token string) (time.Duration, error)
}

func newDoctorCmd() *cobra.Command {
	var opts doctorOptions

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Validate config and report what would run",
		Long: `Doctor performs a no-side-effects smoke test:

  - Validates the config schema and reports its source
  - Resolves environment variable references for enabled providers
  - Reports which providers would run and which would be skipped

doctor never executes checks; it is safe to run in any environment. Use
it as the first thing you run after editing your config.

Network connectivity probes against provider APIs land in v0.1 phase 4
alongside the DigitalOcean collector.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDoctor(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.configPath, "config", "", "path to compliancekit.yaml")
	cmd.Flags().StringVar(&opts.envName, "env", "", "load compliancekit.<env>.yaml")
	cmd.Flags().BoolVar(&opts.checkConfig, "check-config", false, "validate schema only; skip env-var resolution")

	return cmd
}

func runDoctor(ctx context.Context, w io.Writer, opts doctorOptions) error {
	if opts.doProbe == nil {
		opts.doProbe = do.Probe
	}

	cfg, err := config.Load(config.LoadOptions{
		ConfigPath: opts.configPath,
		EnvName:    opts.envName,
	})
	if err != nil {
		fmt.Fprintf(w, "%s config: %v\n", iconFail, err)
		return err
	}

	if cfg.SourcePath != "" {
		fmt.Fprintf(w, "%s config: loaded from %s\n", iconPass, cfg.SourcePath)
	} else {
		fmt.Fprintf(w, "%s config: using built-in defaults (no file found)\n", iconInfo)
	}

	fmt.Fprintf(w, "%s severity: fail_on=%s, min_report=%s\n",
		iconPass, cfg.Severity.FailOn, cfg.Severity.MinReport)
	fmt.Fprintf(w, "%s frameworks: %s\n", iconPass, strings.Join(cfg.Frameworks, ", "))
	fmt.Fprintf(w, "%s output: format=%s, evidence=%v, out_dir=%s\n",
		iconPass, strings.Join(cfg.Output.Format, ","), cfg.Output.Evidence, cfg.Output.OutDir)

	// Notification sinks report runs regardless of provider config —
	// operators may run `compliancekit notify` against findings JSON
	// generated elsewhere (CI pipelines, ingest, etc.) and want to
	// verify their sink credentials independently.
	reportNotifySinks(w)

	if !cfg.AnyProviderEnabled() {
		fmt.Fprintf(w, "%s no providers enabled in config; enable at least one to scan\n", iconWarn)
		return fmt.Errorf("no providers enabled")
	}

	// Each provider report runs and prints its line(s) even if a peer fails,
	// so the operator sees the full picture in one pass. Errors accumulate
	// and surface as a single non-zero exit at the end.
	var combined error
	combined = errors.Join(combined,
		reportProvider(w, "digitalocean", cfg.Providers.DigitalOcean.Enabled,
			func() error {
				return reportDOProvider(ctx, w, cfg.Providers.DigitalOcean, opts)
			}),
		reportProvider(w, "linux", cfg.Providers.Linux.Enabled,
			func() error {
				return reportLinuxProvider(w, cfg.Providers.Linux)
			}),
		reportProvider(w, "gcp", cfg.Providers.GCP.Enabled,
			func() error {
				return reportGCPProvider(ctx, w, cfg.Providers.GCP, opts.checkConfig)
			}),
		reportProvider(w, "kubernetes", cfg.Providers.Kubernetes.Enabled,
			func() error {
				return reportKubernetesProvider(w, cfg.Providers.Kubernetes, opts.checkConfig)
			}),
		reportProvider(w, "hetzner", cfg.Providers.Hetzner.Enabled,
			func() error {
				return reportHetznerProvider(w, cfg.Providers.Hetzner, opts.checkConfig)
			}),
	)
	return combined
}

// reportNotifySinks prints the per-sink Configured + Threshold
// status. Run unconditionally because v0.17's "missing creds is
// fine" model means there is no error case to gate on — we just
// want operators to see at a glance which channels would receive
// a `compliancekit notify` invocation.
func reportNotifySinks(w io.Writer) {
	sinks := notify.Default.Sinks()
	if len(sinks) == 0 {
		return
	}
	configured := 0
	for _, s := range sinks {
		if s.Configured() {
			configured++
		}
	}
	icon := iconInfo
	if configured > 0 {
		icon = iconPass
	}
	fmt.Fprintf(w, "%s notify: %d sink(s) registered, %d configured\n", icon, len(sinks), configured)
	for _, s := range sinks {
		mark := iconInfo
		if s.Configured() {
			mark = iconPass
		}
		fmt.Fprintf(w, "    %s %s (threshold=%s)\n", mark, s.Name(), s.Threshold())
	}
}

// reportProvider emits the status line(s) for one provider. The error is
// returned so runDoctor can aggregate them via errors.Join and produce a
// non-zero exit code without short-circuiting later providers.
func reportProvider(w io.Writer, name string, enabled bool, details func() error) error {
	if !enabled {
		fmt.Fprintf(w, "%s providers.%s: disabled\n", iconInfo, name)
		return nil
	}
	if details == nil {
		fmt.Fprintf(w, "%s providers.%s: enabled (no details available yet)\n", iconInfo, name)
		return nil
	}
	if err := details(); err != nil {
		fmt.Fprintf(w, "%s providers.%s: %v\n", iconFail, name, err)
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func reportDOProvider(ctx context.Context, w io.Writer, cfg config.DigitalOceanConfig, opts doctorOptions) error {
	if opts.checkConfig {
		fmt.Fprintf(w, "%s providers.digitalocean: enabled, token_env=%s (skipping env resolution and API probe)\n",
			iconInfo, cfg.TokenEnv)
		return nil
	}
	token := os.Getenv(cfg.TokenEnv)
	if token == "" {
		return fmt.Errorf("env var %s is unset", cfg.TokenEnv)
	}
	fmt.Fprintf(w, "%s providers.digitalocean: %s resolved (token length: %d)\n",
		iconPass, cfg.TokenEnv, len(token))

	dur, err := opts.doProbe(ctx, token)
	if err != nil {
		return fmt.Errorf("API probe: %w", err)
	}
	fmt.Fprintf(w, "%s providers.digitalocean: API reachable (%dms)\n",
		iconPass, dur.Milliseconds())
	return nil
}

// reportGCPProvider resolves Application Default Credentials and
// reports the project list that would be scanned. Skipped under
// --check-config so the doctor can run with no GCP credentials
// at hand.
func reportGCPProvider(ctx context.Context, w io.Writer, cfg config.GCPConfig, checkConfigOnly bool) error {
	if checkConfigOnly {
		projects := "credential default"
		if len(cfg.Projects) > 0 {
			projects = strings.Join(cfg.Projects, ", ")
		}
		fmt.Fprintf(w, "%s providers.gcp: enabled, projects=%s (skipping ADC resolution)\n",
			iconInfo, projects)
		return nil
	}
	gc, err := gcpcol.New(ctx, gcpcol.Options{Projects: cfg.Projects})
	if err != nil {
		return fmt.Errorf("ADC: %w", err)
	}
	fmt.Fprintf(w, "%s providers.gcp: %d project(s): %s\n",
		iconPass, len(gc.Projects()), strings.Join(gc.Projects(), ", "))
	return nil
}

func reportHetznerProvider(w io.Writer, cfg config.HetznerConfig, checkConfigOnly bool) error {
	if checkConfigOnly {
		fmt.Fprintf(w, "%s providers.hetzner: enabled, token_env=%s (skipping env resolution)\n",
			iconInfo, cfg.TokenEnv)
		return nil
	}
	token := os.Getenv(cfg.TokenEnv)
	if token == "" {
		return fmt.Errorf("env var %s is unset", cfg.TokenEnv)
	}
	fmt.Fprintf(w, "%s providers.hetzner: %s resolved (token length: %d)\n",
		iconPass, cfg.TokenEnv, len(token))
	return nil
}

func reportKubernetesProvider(w io.Writer, cfg config.KubernetesConfig, checkConfigOnly bool) error {
	source := cfg.Kubeconfig
	if source == "" {
		if env := os.Getenv("KUBECONFIG"); env != "" {
			source = env + " (from KUBECONFIG)"
		} else {
			source = "~/.kube/config (default)"
		}
	}
	if checkConfigOnly {
		fmt.Fprintf(w, "%s providers.kubernetes: enabled, kubeconfig=%s (skipping context resolution)\n",
			iconInfo, source)
		return nil
	}
	col, err := k8scol.New(k8scol.Options{
		KubeconfigPath:    cfg.Kubeconfig,
		Contexts:          cfg.Contexts,
		Namespaces:        cfg.Namespaces,
		ExcludeNamespaces: cfg.ExcludeNamespaces,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "%s providers.kubernetes: %d context(s): %s\n",
		iconPass, len(col.Contexts()), strings.Join(col.Contexts(), ", "))
	return nil
}

func reportLinuxProvider(w io.Writer, cfg config.LinuxConfig) error {
	if _, err := os.Stat(cfg.Inventory); err != nil {
		return fmt.Errorf("inventory file %s: %w", cfg.Inventory, err)
	}
	inv, err := linuxcol.LoadInventory(cfg.Inventory)
	if err != nil {
		return fmt.Errorf("parse inventory: %w", err)
	}
	hosts := inv.AllHosts()
	fmt.Fprintf(w, "%s providers.linux: %d host(s) across %d group(s) in %s\n",
		iconPass, len(hosts), len(inv.Groups), cfg.Inventory)
	return nil
}

// Status icons. UTF-8 glyphs match the CLI.md example and how modern
// security tools (Trivy, kubectl) render check output. Windows Terminal,
// iTerm2, all macOS terminals, and every GitHub Actions runner render
// these correctly; legacy cmd.exe is the only environment that does not.
const (
	iconPass = "✓"
	iconFail = "✗"
	iconWarn = "⚠"
	iconInfo = "·"
)
