// Package plugins owns the v1.13 daemon-side plugin runtime: filesystem
// discovery, manifest parsing, cosign signature verification, sandbox
// dial-time egress enforcement, and hot-reload of Rego packs.
//
// The public types (Manifest, Plugin, Kind, Catalog) live under
// pkg/compliancekit/plugin so embedders see a stable surface; this
// package is the daemon's private wiring.
//
// Discovery (phase 2): walk $XDG_DATA_HOME/compliancekit/plugins/ (or
// the explicit --plugins-dir override) and load every direct
// subdirectory that contains a manifest.yaml. Each subdirectory is
// one plugin; the directory name doesn't have to match the manifest's
// `name` field but the daemon emits a warning when they diverge.
package plugins

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	yaml "go.yaml.in/yaml/v3"

	pubplugin "github.com/darpanzope/compliancekit/pkg/compliancekit/plugin"
)

// DefaultDirName is the relative XDG directory the daemon scans
// when --plugins-dir is unset.
const DefaultDirName = "compliancekit/plugins"

// DefaultDir returns the absolute path the daemon discovers plugins
// from. Honors $XDG_DATA_HOME; falls back to $HOME/.local/share on
// Linux / macOS and a sensible default on Windows.
func DefaultDir() string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, DefaultDirName)
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "share", DefaultDirName)
	}
	return "./plugins"
}

// Discovered is the result of one Catalog.Refresh() walk. Splits the
// successfully-loaded plugins from the per-directory load errors so
// the operator can see which packs failed without blocking the
// healthy ones.
type Discovered struct {
	Plugins []*pubplugin.Plugin
	Errors  map[string]error // keyed by directory name
}

// Catalog tracks the set of installed plugins under Dir. The daemon
// constructs one at boot, calls Refresh(), and re-calls it on
// fsnotify writes from the phase-5 hot-reload watcher.
type Catalog struct {
	Dir           string
	AllowUnsigned bool
	verifier      SignatureVerifier // nil at phase 2; populated in phase 3

	mu      sync.RWMutex
	plugins map[string]*pubplugin.Plugin
}

// New returns a Catalog rooted at dir. dir is created if absent so
// the daemon doesn't fail to boot just because the operator hasn't
// installed any plugins yet.
func New(dir string, allowUnsigned bool) *Catalog {
	if dir == "" {
		dir = DefaultDir()
	}
	return &Catalog{
		Dir:           dir,
		AllowUnsigned: allowUnsigned,
		plugins:       make(map[string]*pubplugin.Plugin),
	}
}

// WithVerifier installs the signature verifier used during Refresh.
// nil = no verification (phase 2 fallback).
func (c *Catalog) WithVerifier(v SignatureVerifier) *Catalog {
	c.verifier = v
	return c
}

// All returns every loaded plugin, sorted by manifest.Name. Returns a
// fresh slice on every call so callers can mutate without locking
// the catalog.
func (c *Catalog) All() []*pubplugin.Plugin {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*pubplugin.Plugin, 0, len(c.plugins))
	for _, p := range c.plugins {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.Name < out[j].Manifest.Name })
	return out
}

// ByName returns the plugin keyed by manifest.Name; reports
// ok=false when absent.
func (c *Catalog) ByName(name string) (*pubplugin.Plugin, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	p, ok := c.plugins[name]
	return p, ok
}

// Refresh walks the plugin directory + replaces the in-memory catalog
// with the current on-disk state. Returns a Discovered report so the
// daemon (or CLI) can surface partial failures.
func (c *Catalog) Refresh(ctx context.Context) (*Discovered, error) {
	_ = ctx
	if err := os.MkdirAll(c.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("plugins: mkdir %s: %w", c.Dir, err)
	}
	entries, err := os.ReadDir(c.Dir)
	if err != nil {
		return nil, fmt.Errorf("plugins: read %s: %w", c.Dir, err)
	}
	res := &Discovered{Errors: map[string]error{}}
	loaded := make(map[string]*pubplugin.Plugin)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(c.Dir, e.Name())
		p, err := c.loadOne(path)
		if err != nil {
			res.Errors[e.Name()] = err
			continue
		}
		loaded[p.Manifest.Name] = p
		res.Plugins = append(res.Plugins, p)
	}
	c.mu.Lock()
	c.plugins = loaded
	c.mu.Unlock()
	sort.Slice(res.Plugins, func(i, j int) bool {
		return res.Plugins[i].Manifest.Name < res.Plugins[j].Manifest.Name
	})
	return res, nil
}

// loadOne parses a single plugin directory.
func (c *Catalog) loadOne(path string) (*pubplugin.Plugin, error) {
	manifestPath := filepath.Join(path, "manifest.yaml")
	body, err := os.ReadFile(manifestPath) //nolint:gosec // path under operator-controlled plugins dir
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m pubplugin.Manifest
	if err := yaml.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("validate manifest: %w", err)
	}
	sigValid := false
	if c.verifier != nil {
		ok, err := c.verifier.Verify(path, &m)
		if err != nil && !c.AllowUnsigned {
			return nil, fmt.Errorf("verify signature: %w", err)
		}
		sigValid = ok
	}
	if !sigValid && !c.AllowUnsigned {
		return nil, ErrUnsigned
	}
	stat, _ := os.Stat(manifestPath)
	installedAt := time.Now().UTC()
	if stat != nil {
		installedAt = stat.ModTime().UTC()
	}
	return &pubplugin.Plugin{
		Manifest:       m,
		Path:           path,
		SignatureValid: sigValid,
		InstalledAt:    installedAt,
	}, nil
}

// SignatureVerifier validates a plugin's signature.sig against the
// manifest.yaml in the same directory. Phase 3 wires the
// cosign-backed implementation.
type SignatureVerifier interface {
	Verify(pluginDir string, m *pubplugin.Manifest) (ok bool, err error)
}
