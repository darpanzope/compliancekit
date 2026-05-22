package plugins

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	pubplugin "github.com/darpanzope/compliancekit/pkg/compliancekit/plugin"
)

func writeManifest(t *testing.T, dir string, m pubplugin.Manifest) {
	t.Helper()
	body, err := yaml.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestCatalogRefresh_AllowUnsigned(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, filepath.Join(root, "hello"), pubplugin.Manifest{
		APIVersion: pubplugin.APIVersion,
		Name:       "hello",
		Version:    "v0.1.0",
		Kinds:      []pubplugin.Kind{pubplugin.KindCheck},
		RegoPacks:  []string{"rego/hello.rego"},
	})
	writeManifest(t, filepath.Join(root, "world"), pubplugin.Manifest{
		APIVersion: pubplugin.APIVersion,
		Name:       "world",
		Version:    "v0.2.0",
		Kinds:      []pubplugin.Kind{pubplugin.KindNotifier},
		Entrypoint: "./bin/world",
	})

	c := New(root, true) // allow unsigned for the test
	res, err := c.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if len(res.Plugins) != 2 {
		t.Errorf("expected 2 plugins, got %d (errors=%v)", len(res.Plugins), res.Errors)
	}
	if len(res.Errors) != 0 {
		t.Errorf("unexpected errors: %v", res.Errors)
	}
	if got := c.All(); len(got) != 2 || got[0].Manifest.Name != "hello" || got[1].Manifest.Name != "world" {
		t.Errorf("All() sort mismatch: %+v", got)
	}
	if _, ok := c.ByName("hello"); !ok {
		t.Errorf("ByName(hello) should hit")
	}
}

func TestCatalogRefresh_RefusesUnsigned(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, filepath.Join(root, "hello"), pubplugin.Manifest{
		APIVersion: pubplugin.APIVersion,
		Name:       "hello",
		Version:    "v0.1.0",
		Kinds:      []pubplugin.Kind{pubplugin.KindCheck},
		RegoPacks:  []string{"rego/hello.rego"},
	})
	c := New(root, false) // unsigned NOT allowed
	res, err := c.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if len(res.Plugins) != 0 {
		t.Errorf("expected no loaded plugins, got %d", len(res.Plugins))
	}
	got, ok := res.Errors["hello"]
	if !ok || !errors.Is(got, ErrUnsigned) {
		t.Errorf("expected ErrUnsigned for hello, got %v", res.Errors)
	}
}

func TestCatalogRefresh_InvalidManifestReported(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "broken")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Manifest is valid YAML but missing required fields.
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"),
		[]byte("apiVersion: compliancekit.io/v1\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c := New(root, true)
	res, _ := c.Refresh(context.Background())
	if _, ok := res.Errors["broken"]; !ok {
		t.Errorf("expected error for broken manifest, got %+v", res)
	}
}

func TestDefaultDirHonorsXDG(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/custom/xdg")
	if got := DefaultDir(); got != "/custom/xdg/compliancekit/plugins" {
		t.Errorf("DefaultDir=%q want /custom/xdg/compliancekit/plugins", got)
	}
}
