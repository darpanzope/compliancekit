package plugins

// v1.13 phase 5 — hot-reload of Rego packs.
//
// fsnotify watches the plugins directory + every plugin subdirectory.
// File-write bursts (editors save in 2-4 inotify events; archive
// extractors fire dozens) are coalesced through a 500ms debounce so
// the catalog refreshes once per logical change instead of once per
// inotify event.
//
// Each successful refresh bumps the plugin's Generation counter. In-
// flight scans cache the generation they started with so a mid-scan
// reload doesn't shuffle their policy set.

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// DefaultDebounce is the burst-coalescing window. 500ms balances
// "fast enough to feel live" against "slow enough that a tar
// extraction doesn't trigger N reloads."
const DefaultDebounce = 500 * time.Millisecond

// Watcher debounces fsnotify events into Catalog.Refresh calls.
// Construct via NewWatcher; Start launches the background loop; Stop
// closes the underlying watcher.
type Watcher struct {
	catalog  *Catalog
	debounce time.Duration

	mu         sync.Mutex
	generation map[string]int // pluginName -> generation; protected by mu

	fsw     *fsnotify.Watcher
	cancel  context.CancelFunc
	stopped chan struct{}
}

// NewWatcher returns a Watcher bound to cat. Callers may override
// debounce; passing 0 uses DefaultDebounce.
func NewWatcher(cat *Catalog, debounce time.Duration) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if debounce == 0 {
		debounce = DefaultDebounce
	}
	return &Watcher{
		catalog:    cat,
		debounce:   debounce,
		fsw:        fsw,
		generation: make(map[string]int),
		stopped:    make(chan struct{}),
	}, nil
}

// Generation returns the most recent generation counter for plugin
// name. Scans cache this at start time + carry the cached value
// through the scan even if the catalog later reloads.
func (w *Watcher) Generation(name string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.generation[name]
}

// Start launches the watch + debounce loop. ctx cancellation triggers
// a clean shutdown. The function returns immediately; the caller is
// responsible for ctx lifetime.
func (w *Watcher) Start(ctx context.Context) error {
	if err := w.fsw.Add(w.catalog.Dir); err != nil {
		return err
	}
	// fsnotify is non-recursive — explicitly add every subdirectory
	// under each plugin so rego/*.rego + nested manifest changes fire
	// events. New subdirectories (created post-Start) get added on
	// their CREATE event inside the loop.
	for _, p := range w.catalog.All() {
		_ = w.addRecursive(p.Path)
	}
	wctx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	go w.loop(wctx)
	return nil
}

// Stop signals the background loop to exit + closes the watcher.
// Safe to call multiple times.
func (w *Watcher) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	_ = w.fsw.Close()
	<-w.stopped
}

// loop coalesces events into a single Refresh per debounce window.
func (w *Watcher) loop(ctx context.Context) {
	defer close(w.stopped)
	var timer *time.Timer
	fire := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, err := w.catalog.Refresh(ctx)
		if err != nil {
			slog.Warn("plugins: hot-reload refresh failed", "err", err)
			return
		}
		w.mu.Lock()
		for _, p := range res.Plugins {
			w.generation[p.Manifest.Name]++
			p.Generation = w.generation[p.Manifest.Name]
		}
		w.mu.Unlock()
		slog.Info("plugins: hot-reload",
			"loaded", len(res.Plugins),
			"errors", len(res.Errors))
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			// New directory created → start watching it so writes to
			// rego/*.rego or other nested files generate events. Also
			// counts as a relevant trigger so we refresh once the dir
			// is established (and any files written in the same burst
			// land in the debounce window).
			triggered := relevantEvent(ev)
			if ev.Op&fsnotify.Create != 0 {
				if fi, err := os.Stat(ev.Name); err == nil && fi.IsDir() {
					_ = w.addRecursive(ev.Name)
					triggered = true
				}
			}
			if !triggered {
				continue
			}
			if timer != nil {
				timer.Stop()
			}
			timer = time.AfterFunc(w.debounce, fire)
		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			slog.Warn("plugins: watcher error", "err", err)
		}
	}
}

// relevantEvent filters out the noise events (CHMOD-only on macOS,
// temporary editor swap files). Only writes / creates / removes /
// renames of .yaml + .rego + manifest files count.
func relevantEvent(ev fsnotify.Event) bool {
	if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) == 0 {
		return false
	}
	name := ev.Name
	switch {
	case hasSuffix(name, ".rego"),
		hasSuffix(name, ".yaml"),
		hasSuffix(name, ".yml"),
		hasSuffix(name, ".sig"):
		return true
	}
	return false
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// addRecursive walks every subdirectory under root + registers each
// one with fsnotify. fsnotify is non-recursive on every supported OS
// so the daemon walks it explicitly.
func (w *Watcher) addRecursive(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err //nolint:nilerr // surface walk errors to caller
		}
		if info.IsDir() {
			_ = w.fsw.Add(path)
		}
		return nil
	})
}
