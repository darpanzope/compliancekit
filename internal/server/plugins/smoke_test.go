package plugins

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pubplugin "github.com/darpanzope/compliancekit/pkg/compliancekit/plugin"
)

// TestReferencePlugin_HelloDiscoverable proves the v1.13 phase 9
// example pack under examples/plugins/hello/ parses cleanly + loads
// through the unsigned catalog path. Doubles as the "how to write a
// plugin" smoke test the v1.13 DoD calls out.
func TestReferencePlugin_HelloDiscoverable(t *testing.T) {
	// Resolve the example pack relative to the repo root. The test
	// runs from internal/server/plugins/ so we walk up two levels.
	helloSrc := mustAbs(t, filepath.Join("..", "..", "..", "examples", "plugins", "hello"))
	if _, err := os.Stat(helloSrc); err != nil {
		t.Fatalf("hello pack missing at %s: %v", helloSrc, err)
	}

	// Stage a fresh plugins root, copy the example in, then refresh
	// the catalog.
	root := t.TempDir()
	staged := filepath.Join(root, "hello")
	if err := copyTree(helloSrc, staged); err != nil {
		t.Fatalf("copy: %v", err)
	}

	cat := New(root, true) // unsigned OK for the smoke test
	res, err := cat.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("expected no errors, got %+v", res.Errors)
	}
	if len(res.Plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(res.Plugins))
	}
	p := res.Plugins[0]
	if p.Manifest.Name != "hello" {
		t.Errorf("name=%q want hello", p.Manifest.Name)
	}
	if len(p.Manifest.RegoPacks) != 1 || p.Manifest.RegoPacks[0] != "rego/hello.rego" {
		t.Errorf("rego_packs=%v want [rego/hello.rego]", p.Manifest.RegoPacks)
	}
	if len(p.Manifest.Kinds) != 1 || p.Manifest.Kinds[0] != pubplugin.KindCheck {
		t.Errorf("kinds=%v want [check]", p.Manifest.Kinds)
	}

	// The rego file referenced by the manifest must exist on disk —
	// the v1.13.x Rego loader will fail catastrophically otherwise.
	regoPath := filepath.Join(staged, p.Manifest.RegoPacks[0])
	if _, err := os.Stat(regoPath); err != nil {
		t.Errorf("rego file missing: %v", err)
	}
}

func mustAbs(t *testing.T, rel string) string {
	t.Helper()
	abs, err := filepath.Abs(rel)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return abs
}

// copyTree is a tiny recursive copy lifted from internal/cli to avoid
// the import cycle. Test-only.
func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		body, err := os.ReadFile(path) //nolint:gosec // test fixture
		if err != nil {
			return err
		}
		return os.WriteFile(target, body, 0o600)
	})
}
