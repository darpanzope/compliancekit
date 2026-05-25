package plugins

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"

	pubplugin "github.com/darpanzope/compliancekit/pkg/compliancekit/plugin"
)

func TestRelevantEvent(t *testing.T) {
	for _, name := range []string{"manifest.yaml", "rego/x.rego", "signature.sig"} {
		if !hasSuffix(name, ".yaml") && !hasSuffix(name, ".rego") && !hasSuffix(name, ".sig") {
			t.Errorf("expected suffix match for %q", name)
		}
	}
	if hasSuffix("README.md", ".rego") {
		t.Errorf("README.md should not match .rego")
	}
}

func writeUnsignedManifest(t *testing.T, root, name string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body, _ := yaml.Marshal(pubplugin.Manifest{
		APIVersion: pubplugin.APIVersion,
		Name:       name,
		Version:    "v0.1.0",
		Kinds:      []pubplugin.Kind{pubplugin.KindCheck},
		RegoPacks:  []string{"rego/" + name + ".rego"},
	})
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestWatcher_GenerationBumpsOnReload(t *testing.T) {
	root := t.TempDir()
	writeUnsignedManifest(t, root, "hello")

	c := New(root, true)
	if _, err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}
	w, err := NewWatcher(c, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()

	// Trigger a rego file write that should debounce into a single
	// reload.
	regoDir := filepath.Join(root, "hello", "rego")
	_ = os.MkdirAll(regoDir, 0o750)
	if err := os.WriteFile(filepath.Join(regoDir, "hello.rego"), []byte("# rego v1"), 0o600); err != nil {
		t.Fatalf("write rego: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if g := w.Generation("hello"); g >= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("generation never bumped: got %d", w.Generation("hello"))
}
