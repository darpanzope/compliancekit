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
	"github.com/darpanzope/compliancekit/internal/ui"
	"github.com/darpanzope/compliancekit/internal/waivers"
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

Output is colorized + sorted with failures first so a long doctor run
surfaces problems at the top of the scroll-back. NO_COLOR / --no-color
disables the colors for CI / piped output.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDoctor(cmd.Context(), cmd.OutOrStdout(), stylerFor(cmd), opts)
		},
	}

	cmd.Flags().StringVar(&opts.configPath, "config", "", "path to compliancekit.yaml")
	cmd.Flags().StringVar(&opts.envName, "env", "", "load compliancekit.<env>.yaml")
	cmd.Flags().BoolVar(&opts.checkConfig, "check-config", false, "validate schema only; skip env-var resolution")

	return cmd
}

// runDoctor walks the config + every enabled provider, accumulating
// probe results into a probeBuf. At the end it renders the buf in
// failures-first order. The accumulator pattern lets the renderer
// sort + style consistently; the per-provider reporters stay focused
// on logic rather than presentation.
//
// w + st are decoupled from any cobra.Command so the function is
// directly testable: tests pass a bytes.Buffer + a plainStyler() and
// inspect the rendered output without spinning up a cobra tree.
func runDoctor(ctx context.Context, w io.Writer, st *ui.Styler, opts doctorOptions) error {
	if opts.doProbe == nil {
		opts.doProbe = do.Probe
	}

	pb := &probeBuf{}

	cfg, err := config.Load(config.LoadOptions{
		ConfigPath: opts.configPath,
		EnvName:    opts.envName,
	})
	if err != nil {
		pb.Fail("config", err.Error())
		pb.Render(w, st)
		return err
	}

	if cfg.SourcePath != "" {
		pb.Pass("config", "loaded from "+cfg.SourcePath)
	} else {
		pb.Info("config", "using built-in defaults (no file found)")
	}

	pb.Pass("severity", fmt.Sprintf("fail_on=%s, min_report=%s", cfg.Severity.FailOn, cfg.Severity.MinReport))
	pb.Pass("frameworks", strings.Join(cfg.Frameworks, ", "))
	pb.Pass("output", fmt.Sprintf("format=%s, evidence=%v, out_dir=%s",
		strings.Join(cfg.Output.Format, ","), cfg.Output.Evidence, cfg.Output.OutDir))

	reportNotifySinks(pb)
	reportWaivers(pb, cfg.Waivers.File)

	if !cfg.AnyProviderEnabled() {
		pb.Warn("providers", "no providers enabled in config; enable at least one to scan")
		pb.Render(w, st)
		return fmt.Errorf("no providers enabled")
	}

	// Each provider report runs and accumulates its probe(s) even if
	// a peer fails, so the operator sees the full picture in one
	// pass. Errors accumulate and surface as a single non-zero exit
	// at the end.
	var combined error
	combined = errors.Join(combined,
		reportProvider(pb, "digitalocean", cfg.Providers.DigitalOcean.Enabled,
			func() error {
				return reportDOProvider(ctx, pb, cfg.Providers.DigitalOcean, opts)
			}),
		reportProvider(pb, "linux", cfg.Providers.Linux.Enabled,
			func() error {
				return reportLinuxProvider(pb, cfg.Providers.Linux)
			}),
		reportProvider(pb, "gcp", cfg.Providers.GCP.Enabled,
			func() error {
				return reportGCPProvider(ctx, pb, cfg.Providers.GCP, opts.checkConfig)
			}),
		reportProvider(pb, "kubernetes", cfg.Providers.Kubernetes.Enabled,
			func() error {
				return reportKubernetesProvider(pb, cfg.Providers.Kubernetes, opts.checkConfig)
			}),
		reportProvider(pb, "hetzner", cfg.Providers.Hetzner.Enabled,
			func() error {
				return reportHetznerProvider(pb, cfg.Providers.Hetzner, opts.checkConfig)
			}),
	)

	pb.Render(w, st)
	return combined
}

// reportNotifySinks adds the per-sink Configured + Threshold status
// to pb. Run unconditionally because v0.17's "missing creds is fine"
// model means there is no error case to gate on — we just want
// operators to see at a glance which channels would receive a
// `compliancekit notify` invocation.
func reportNotifySinks(pb *probeBuf) {
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
	if configured > 0 {
		pb.Pass("notify", fmt.Sprintf("%d sink(s) registered, %d configured", len(sinks), configured))
	} else {
		pb.Info("notify", fmt.Sprintf("%d sink(s) registered, 0 configured", len(sinks)))
	}
	for _, s := range sinks {
		status := probeInfo
		if s.Configured() {
			status = probePass
		}
		pb.AddChild(status, s.Name(), fmt.Sprintf("threshold=%s", s.Threshold()))
	}
}

// reportWaivers adds the waivers health probe to pb. Three counts:
// active, expired, expiring within 30 days. Missing path means
// waivers feature off — a single info probe and exit. v0.18+.
func reportWaivers(pb *probeBuf, path string) {
	if path == "" {
		pb.Info("waivers", "feature disabled (set `waivers.file` in config to enable)")
		return
	}
	now := time.Now().UTC()
	list, errs := waivers.LoadFile(path, now)
	if len(errs) > 0 {
		// Errors here would have failed `scan` outright; surface
		// them so operators can fix without running scan.
		pb.Fail("waivers", fmt.Sprintf("%s — %d load error(s)", path, len(errs)))
		for _, e := range errs {
			pb.AddChild(probeFail, "load error", e.Error())
		}
		return
	}
	active, expired, expiring := list.Counts(now)
	detail := fmt.Sprintf("%s — %d active, %d expired, %d expiring within 30d", path, active, expired, expiring)
	if expired > 0 || expiring > 0 {
		pb.Warn("waivers", detail)
	} else {
		pb.Pass("waivers", detail)
	}
}

// reportProvider emits the status probe(s) for one provider. The error
// is returned so runDoctor can aggregate them via errors.Join and
// produce a non-zero exit code without short-circuiting later
// providers.
func reportProvider(pb *probeBuf, name string, enabled bool, details func() error) error {
	probeName := "providers." + name
	if !enabled {
		pb.Info(probeName, "disabled")
		return nil
	}
	if details == nil {
		pb.Info(probeName, "enabled (no details available yet)")
		return nil
	}
	if err := details(); err != nil {
		pb.Fail(probeName, err.Error())
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func reportDOProvider(ctx context.Context, pb *probeBuf, cfg config.DigitalOceanConfig, opts doctorOptions) error {
	if opts.checkConfig {
		pb.Info("providers.digitalocean", fmt.Sprintf("enabled, token_env=%s (skipping env resolution and API probe)", cfg.TokenEnv))
		return nil
	}
	token := os.Getenv(cfg.TokenEnv)
	if token == "" {
		return fmt.Errorf("env var %s is unset", cfg.TokenEnv)
	}
	pb.Pass("providers.digitalocean", fmt.Sprintf("%s resolved (token length: %d)", cfg.TokenEnv, len(token)))

	dur, err := opts.doProbe(ctx, token)
	if err != nil {
		return fmt.Errorf("API probe: %w", err)
	}
	pb.PassWithLatency("providers.digitalocean", "API reachable", dur)
	return nil
}

// reportGCPProvider resolves Application Default Credentials and
// reports the project list that would be scanned. Skipped under
// --check-config so the doctor can run with no GCP credentials
// at hand.
func reportGCPProvider(ctx context.Context, pb *probeBuf, cfg config.GCPConfig, checkConfigOnly bool) error {
	if checkConfigOnly {
		projects := "credential default"
		if len(cfg.Projects) > 0 {
			projects = strings.Join(cfg.Projects, ", ")
		}
		pb.Info("providers.gcp", fmt.Sprintf("enabled, projects=%s (skipping ADC resolution)", projects))
		return nil
	}
	gc, err := gcpcol.New(ctx, gcpcol.Options{Projects: cfg.Projects})
	if err != nil {
		return fmt.Errorf("ADC: %w", err)
	}
	pb.Pass("providers.gcp", fmt.Sprintf("%d project(s): %s", len(gc.Projects()), strings.Join(gc.Projects(), ", ")))
	return nil
}

func reportHetznerProvider(pb *probeBuf, cfg config.HetznerConfig, checkConfigOnly bool) error {
	if checkConfigOnly {
		pb.Info("providers.hetzner", fmt.Sprintf("enabled, token_env=%s (skipping env resolution)", cfg.TokenEnv))
		return nil
	}
	token := os.Getenv(cfg.TokenEnv)
	if token == "" {
		return fmt.Errorf("env var %s is unset", cfg.TokenEnv)
	}
	pb.Pass("providers.hetzner", fmt.Sprintf("%s resolved (token length: %d)", cfg.TokenEnv, len(token)))
	return nil
}

func reportKubernetesProvider(pb *probeBuf, cfg config.KubernetesConfig, checkConfigOnly bool) error {
	source := cfg.Kubeconfig
	if source == "" {
		if env := os.Getenv("KUBECONFIG"); env != "" {
			source = env + " (from KUBECONFIG)"
		} else {
			source = "~/.kube/config (default)"
		}
	}
	if checkConfigOnly {
		pb.Info("providers.kubernetes", fmt.Sprintf("enabled, kubeconfig=%s (skipping context resolution)", source))
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
	pb.Pass("providers.kubernetes", fmt.Sprintf("%d context(s): %s", len(col.Contexts()), strings.Join(col.Contexts(), ", ")))
	return nil
}

func reportLinuxProvider(pb *probeBuf, cfg config.LinuxConfig) error {
	if _, err := os.Stat(cfg.Inventory); err != nil {
		return fmt.Errorf("inventory file %s: %w", cfg.Inventory, err)
	}
	inv, err := linuxcol.LoadInventory(cfg.Inventory)
	if err != nil {
		return fmt.Errorf("parse inventory: %w", err)
	}
	hosts := inv.AllHosts()
	pb.Pass("providers.linux", fmt.Sprintf("%d host(s) across %d group(s) in %s", len(hosts), len(inv.Groups), cfg.Inventory))
	return nil
}
