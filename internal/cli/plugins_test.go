package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/server/plugins"
	pubplugin "github.com/darpanzope/compliancekit/pkg/compliancekit/plugin"
)

// writeRegoPlugin lays out a minimal Rego-only plugin in dir.
func writeRegoPlugin(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	manifest := `apiVersion: ` + pubplugin.APIVersion + `
name: ` + name + `
version: v0.1.0
kinds:
  - check
rego_packs:
  - rego/hello.rego
`
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

func runPluginsCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out := &bytes.Buffer{}
	cmd := newPluginsCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func TestPlugins_InstallListRemoveRoundtrip(t *testing.T) {
	t.Setenv("CK_ALLOW_UNSIGNED_PLUGINS", "1")
	pluginsRoot := t.TempDir()
	t.Setenv("CK_PLUGINS_DIR", pluginsRoot)

	src := filepath.Join(t.TempDir(), "demo-pack")
	writeRegoPlugin(t, src, "demo-pack")

	out, err := runPluginsCmd(t, "install", src)
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if !strings.Contains(out, "installed demo-pack") {
		t.Errorf("install output: %s", out)
	}

	out, err = runPluginsCmd(t, "list")
	if err != nil {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if !strings.Contains(out, "demo-pack") {
		t.Errorf("list missing demo-pack: %s", out)
	}

	out, err = runPluginsCmd(t, "remove", "demo-pack")
	if err != nil {
		t.Fatalf("remove: %v\n%s", err, out)
	}
	if !strings.Contains(out, "removed demo-pack") {
		t.Errorf("remove output: %s", out)
	}

	if _, err := os.Stat(filepath.Join(pluginsRoot, "demo-pack")); !os.IsNotExist(err) {
		t.Errorf("plugin dir still present after remove: %v", err)
	}
}

func TestPlugins_InstallRefusesNonDir(t *testing.T) {
	t.Setenv("CK_ALLOW_UNSIGNED_PLUGINS", "1")
	t.Setenv("CK_PLUGINS_DIR", t.TempDir())
	out, err := runPluginsCmd(t, "install", "/etc/hostname")
	if err == nil {
		t.Errorf("install should fail on non-dir, got out=%s", out)
	}
}

func TestPlugins_UpdateRequiresSource(t *testing.T) {
	t.Setenv("CK_PLUGINS_DIR", t.TempDir())
	out, err := runPluginsCmd(t, "update", "nope")
	if err == nil {
		t.Errorf("update without --source should fail, got out=%s", out)
	}
}

// Ensure the catalog factory + the CLI's dir resolution agree.
func TestPluginsDir_ResolutionOrder(t *testing.T) {
	t.Setenv("CK_PLUGINS_DIR", "/from/env")
	if got := pluginsDir(""); got != "/from/env" {
		t.Errorf("env should win: got %q", got)
	}
	if got := pluginsDir("/from/flag"); got != "/from/flag" {
		t.Errorf("flag should win: got %q", got)
	}
}

// Catalog refresh after install should pick up the plugin.
func TestPluginsInstall_ThenCatalogRefresh(t *testing.T) {
	t.Setenv("CK_ALLOW_UNSIGNED_PLUGINS", "1")
	pluginsRoot := t.TempDir()
	t.Setenv("CK_PLUGINS_DIR", pluginsRoot)
	src := filepath.Join(t.TempDir(), "alpha")
	writeRegoPlugin(t, src, "alpha")
	if _, err := runPluginsCmd(t, "install", src); err != nil {
		t.Fatalf("install: %v", err)
	}

	cat := plugins.New(pluginsRoot, true)
	res, err := cat.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if len(res.Plugins) != 1 || res.Plugins[0].Manifest.Name != "alpha" {
		t.Errorf("expected alpha in catalog, got %+v", res)
	}
}

// _ keeps cobra import used so subcommand wiring stays linkable if
// future refactors swap the cobra-aware test helper.
var _ = (*cobra.Command)(nil)
