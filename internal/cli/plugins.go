package cli

// v1.13 phase 7 — `compliancekit plugins` CLI surface.
//
// Operators install / list / update / remove / verify plugins
// against the same XDG_DATA directory the daemon discovers from.
// Both surfaces hit the same internal/server/plugins package — what
// the CLI installs, the daemon hot-reloads on its next fsnotify
// tick (no restart needed).
//
//   compliancekit plugins install <ref>       local path | OCI ref (v2.9) | registry name (v2.9)
//   compliancekit plugins list                installed plugins (manifest summary)
//   compliancekit plugins update <name>       re-pull the plugin's source
//   compliancekit plugins remove <name>       rm -rf the plugin dir
//   compliancekit plugins verify [<name>]     re-run signature verification

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/server/plugins"
)

func newPluginsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugins",
		Short: "Install + manage compliancekit plugins (v1.13)",
		Long: `Plugins extend the daemon with custom checks, providers, notifiers,
and reporters. They live under $XDG_DATA_HOME/compliancekit/plugins/
(override with --dir). The daemon discovers them at boot and hot-
reloads them on file change.

Run "compliancekit checks new <id>" to scaffold a starter plugin
directory you can edit + install in two commands.`,
	}
	cmd.AddCommand(newPluginsInstallCmd())
	cmd.AddCommand(newPluginsListCmd())
	cmd.AddCommand(newPluginsUpdateCmd())
	cmd.AddCommand(newPluginsRemoveCmd())
	cmd.AddCommand(newPluginsVerifyCmd())
	return cmd
}

// pluginsDir resolves --dir → CK_PLUGINS_DIR → plugins.DefaultDir().
func pluginsDir(flag string) string {
	if flag != "" {
		return flag
	}
	if env := os.Getenv("CK_PLUGINS_DIR"); env != "" {
		return env
	}
	return plugins.DefaultDir()
}

// allowUnsignedFromFlag mirrors the daemon's --allow-unsigned-plugins
// gate. CLI users can also set CK_ALLOW_UNSIGNED_PLUGINS=1.
func allowUnsignedFromFlag(flag bool) bool {
	if flag {
		return true
	}
	return isTruthy(os.Getenv("CK_ALLOW_UNSIGNED_PLUGINS"))
}

// isTruthy parses the common YAML-ish boolean strings operators reach
// for in environment variables. Single source of truth so the
// CK_ALLOW_UNSIGNED_PLUGINS / CK_SAML_* / future flags all parse
// "true"/"yes"/"on"/"1" identically.
func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case truthyOne, truthyTrue, truthyYes, truthyOn:
		return true
	}
	return false
}

// truthy* names the literal strings isTruthy accepts. Pulled into
// constants so goconst stops flagging the case statement when other
// envBool-style helpers reach for the same vocabulary.
const (
	truthyOne  = "1"
	truthyTrue = "true"
	truthyYes  = "yes"
	truthyOn   = "on"
)

// ─── install ──────────────────────────────────────────────────────

func newPluginsInstallCmd() *cobra.Command {
	var (
		dir           string
		allowUnsigned bool
		pubkey        string
	)
	cmd := &cobra.Command{
		Use:   "install <ref>",
		Short: "Install a plugin from a local directory (OCI / registry refs land at v2.9)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := args[0]
			info, err := os.Stat(ref)
			if err != nil {
				return NewExitCode(2, "install ref must be a local path (OCI + registry land at v2.9): %v", err)
			}
			if !info.IsDir() {
				return NewExitCode(2, "install ref must point at a directory containing manifest.yaml")
			}
			manifestPath := filepath.Join(ref, "manifest.yaml")
			if _, err := os.Stat(manifestPath); err != nil {
				return NewExitCode(2, "no manifest.yaml at %s", ref)
			}
			dst := filepath.Join(pluginsDir(dir), filepath.Base(ref))
			if err := os.MkdirAll(pluginsDir(dir), 0o750); err != nil {
				return fmt.Errorf("mkdir plugins dir: %w", err)
			}
			if _, err := os.Stat(dst); err == nil {
				return NewExitCode(2, "destination %s already exists — uninstall first or use update", dst)
			}
			if err := copyDir(ref, dst); err != nil {
				return fmt.Errorf("install: %w", err)
			}
			// Validate the freshly-installed plugin by running a Catalog
			// refresh against just the plugins dir.
			cat := plugins.New(pluginsDir(dir), allowUnsignedFromFlag(allowUnsigned))
			if pubkey != "" {
				v, err := plugins.NewCosignVerifierFromFile(pubkey)
				if err != nil {
					return fmt.Errorf("load pubkey: %w", err)
				}
				cat.WithVerifier(v)
			}
			res, err := cat.Refresh(cmd.Context())
			if err != nil {
				return fmt.Errorf("verify: %w", err)
			}
			name := filepath.Base(dst)
			if e, bad := res.Errors[name]; bad {
				_ = os.RemoveAll(dst)
				return NewExitCode(3, "plugin refused: %v", e)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "installed %s → %s\n", name, dst)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "plugins directory (default: $XDG_DATA_HOME/compliancekit/plugins)")
	cmd.Flags().BoolVar(&allowUnsigned, "allow-unsigned", false, "accept unsigned plugins (dev only)")
	cmd.Flags().StringVar(&pubkey, "pubkey", "", "PEM file with the cosign public key to verify the manifest signature")
	return cmd
}

// ─── list ─────────────────────────────────────────────────────────

func newPluginsListCmd() *cobra.Command {
	var (
		dir           string
		allowUnsigned bool
		pubkey        string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List installed plugins",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cat, err := buildCatalog(cmd.Context(), pluginsDir(dir), allowUnsignedFromFlag(allowUnsigned), pubkey)
			if err != nil {
				return err
			}
			items := cat.All()
			if len(items) == 0 {
				// v1.15.1 phase 5 — if there are plugins on disk but the
				// catalog filtered them all (unsigned without
				// CK_ALLOW_UNSIGNED_PLUGINS=1 and --allow-unsigned both
				// off), the bare "no plugins installed" message reads
				// like the install never happened. Hint at the cause.
				if d, derr := os.ReadDir(pluginsDir(dir)); derr == nil {
					hidden := 0
					for _, entry := range d {
						if entry.IsDir() {
							hidden++
						}
					}
					if hidden > 0 && !allowUnsignedFromFlag(allowUnsigned) && pubkey == "" {
						fmt.Fprintf(cmd.OutOrStdout(),
							"no plugins installed under %s (%d unsigned hidden — pass --allow-unsigned or set CK_ALLOW_UNSIGNED_PLUGINS=1 to show)\n",
							pluginsDir(dir), hidden)
						return nil
					}
				}
				fmt.Fprintf(cmd.OutOrStdout(), "no plugins installed under %s\n", pluginsDir(dir))
				return nil
			}
			for _, p := range items {
				sig := "unsigned"
				if p.SignatureValid {
					sig = "signed"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%v\t%s\n",
					p.Manifest.Name, p.Manifest.Version, sig, p.Manifest.Kinds, p.Path)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "plugins directory")
	cmd.Flags().BoolVar(&allowUnsigned, "allow-unsigned", false, "accept unsigned plugins")
	cmd.Flags().StringVar(&pubkey, "pubkey", "", "PEM cosign public key")
	return cmd
}

// ─── update ───────────────────────────────────────────────────────

func newPluginsUpdateCmd() *cobra.Command {
	var (
		dir    string
		source string
	)
	cmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Replace an installed plugin from --source (v2.9 will pull from a registry)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if source == "" {
				return NewExitCode(2, "--source <dir> required at v1.13; OCI + registry pulls land at v2.9")
			}
			name := args[0]
			dst := filepath.Join(pluginsDir(dir), name)
			if _, err := os.Stat(dst); err != nil {
				return NewExitCode(2, "plugin %s not installed", name)
			}
			if err := os.RemoveAll(dst); err != nil {
				return fmt.Errorf("remove old: %w", err)
			}
			if err := copyDir(source, dst); err != nil {
				return fmt.Errorf("install update: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "updated %s\n", name)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "plugins directory")
	cmd.Flags().StringVar(&source, "source", "", "local path the replacement is copied from")
	return cmd
}

// ─── remove ───────────────────────────────────────────────────────

func newPluginsRemoveCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Uninstall a plugin (rm -rf the plugin directory)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			dst := filepath.Join(pluginsDir(dir), name)
			if _, err := os.Stat(dst); err != nil {
				return NewExitCode(2, "plugin %s not installed", name)
			}
			if err := os.RemoveAll(dst); err != nil {
				return fmt.Errorf("remove: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", name)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "plugins directory")
	return cmd
}

// ─── verify ───────────────────────────────────────────────────────

func newPluginsVerifyCmd() *cobra.Command {
	var (
		dir    string
		pubkey string
	)
	cmd := &cobra.Command{
		Use:   "verify [<name>]",
		Short: "Re-run signature verification against the configured pubkey",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if pubkey == "" {
				return NewExitCode(2, "--pubkey required to verify")
			}
			cat, err := buildCatalog(cmd.Context(), pluginsDir(dir), false, pubkey)
			if err != nil {
				return err
			}
			items := cat.All()
			only := ""
			if len(args) == 1 {
				only = args[0]
			}
			bad := 0
			for _, p := range items {
				if only != "" && p.Manifest.Name != only {
					continue
				}
				status := "ok"
				if !p.SignatureValid {
					status = "INVALID"
					bad++
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\n", p.Manifest.Name, status)
			}
			if bad > 0 {
				return NewExitCode(1, "%d plugin(s) failed signature verification", bad)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "plugins directory")
	cmd.Flags().StringVar(&pubkey, "pubkey", "", "PEM cosign public key (required)")
	return cmd
}

// buildCatalog is the shared catalog factory the list / verify
// subcommands use.
func buildCatalog(ctx context.Context, dir string, allowUnsigned bool, pubkey string) (*plugins.Catalog, error) {
	cat := plugins.New(dir, allowUnsigned)
	if pubkey != "" {
		v, err := plugins.NewCosignVerifierFromFile(pubkey)
		if err != nil {
			return nil, fmt.Errorf("load pubkey: %w", err)
		}
		cat.WithVerifier(v)
	}
	if _, err := cat.Refresh(ctx); err != nil {
		return nil, err
	}
	return cat, nil
}

// copyDir recursively copies src into dst. Used by install + update;
// kept tiny (no symlink handling, no perm preservation beyond rwx)
// because plugin directories are operator-curated artifacts the CLI
// transports across the filesystem.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // operator-supplied install path
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // dst built from operator-supplied install path
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	_, err = io.Copy(out, in)
	return err
}
