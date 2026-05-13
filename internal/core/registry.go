package core

import (
	"fmt"
	"sort"
	"sync"
)

// Registry maps check IDs to both their Check metadata and their
// CheckFunc implementation.
//
// Checks register themselves at package init time via Register; the
// engine looks up the function at scan time, and reporters / the
// `checks list` command look up the metadata. The registry is the
// single source of truth for "which checks exist and what they are."
//
// A test may construct an isolated *Registry; the package-level
// functions operate on a default global registry intended for
// production use.
type Registry struct {
	mu     sync.RWMutex
	funcs  map[string]CheckFunc
	checks map[string]Check
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		funcs:  make(map[string]CheckFunc),
		checks: make(map[string]Check),
	}
}

// Register associates check.ID with both the metadata and the
// implementation function. Re-registering the same id panics:
// duplicate check IDs indicate a programming error (two checks claiming
// the same identity), not a recoverable runtime condition.
func (r *Registry) Register(check Check, fn CheckFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.funcs[check.ID]; exists {
		panic(fmt.Sprintf("core: duplicate check registration: %s", check.ID))
	}
	r.funcs[check.ID] = fn
	r.checks[check.ID] = check
}

// Get returns the CheckFunc for id and whether it is registered.
func (r *Registry) Get(id string) (CheckFunc, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.funcs[id]
	return fn, ok
}

// Check returns the Check metadata for id and whether it is registered.
func (r *Registry) Check(id string) (Check, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.checks[id]
	return c, ok
}

// Checks returns every registered Check, sorted by ID for stable output.
func (r *Registry) Checks() []Check {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Check, 0, len(r.checks))
	ids := make([]string, 0, len(r.checks))
	for id := range r.checks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		out = append(out, r.checks[id])
	}
	return out
}

// IDs returns the registered check IDs in sorted order. Stable ordering
// matters for `checks list` output and for deterministic test fixtures.
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.funcs))
	for id := range r.funcs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Count returns the number of registered checks.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.funcs)
}

// defaultRegistry is the package-level registry used for production
// checks. Test code should prefer NewRegistry for isolation; production
// code uses the package-level helpers below or DefaultRegistry() when
// passing the registry to another package (e.g. the engine).
var defaultRegistry = NewRegistry()

// DefaultRegistry returns the package-level registry that production
// checks register themselves into via init(). The engine accepts a
// *Registry so tests can substitute an isolated one.
func DefaultRegistry() *Registry { return defaultRegistry }

// Register registers a check in the default registry.
func Register(check Check, fn CheckFunc) { defaultRegistry.Register(check, fn) }

// Lookup returns the CheckFunc for a check ID from the default registry.
func Lookup(id string) (CheckFunc, bool) { return defaultRegistry.Get(id) }

// LookupCheck returns the Check metadata for an ID from the default registry.
func LookupCheck(id string) (Check, bool) { return defaultRegistry.Check(id) }

// RegisteredChecks returns every Check, sorted by ID.
func RegisteredChecks() []Check { return defaultRegistry.Checks() }

// RegisteredIDs returns sorted IDs from the default registry.
func RegisteredIDs() []string { return defaultRegistry.IDs() }

// RegisteredCount returns the count of checks in the default registry.
func RegisteredCount() int { return defaultRegistry.Count() }
