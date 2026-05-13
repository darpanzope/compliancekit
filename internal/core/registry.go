package core

import (
	"fmt"
	"sort"
	"sync"
)

// Registry maps check IDs to their CheckFunc implementations.
//
// Checks register themselves at package init time via Register; the
// engine looks them up by ID at scan time. The registry is the single
// source of truth for "which checks exist."
//
// A test may construct an isolated *Registry; the package-level
// functions operate on a default global registry intended for
// production use.
type Registry struct {
	mu     sync.RWMutex
	checks map[string]CheckFunc
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{checks: make(map[string]CheckFunc)}
}

// Register associates id with fn. Re-registering the same id panics:
// duplicate check IDs indicate a programming error (two checks claiming
// the same identity), not a recoverable runtime condition.
func (r *Registry) Register(id string, fn CheckFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.checks[id]; exists {
		panic(fmt.Sprintf("core: duplicate check registration: %s", id))
	}
	r.checks[id] = fn
}

// Get returns the CheckFunc for id and whether it is registered.
func (r *Registry) Get(id string) (CheckFunc, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.checks[id]
	return fn, ok
}

// IDs returns the registered check IDs in sorted order. Stable ordering
// matters for `checks list` output and for deterministic test fixtures.
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.checks))
	for id := range r.checks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Count returns the number of registered checks.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.checks)
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
func Register(id string, fn CheckFunc) { defaultRegistry.Register(id, fn) }

// Lookup returns a check from the default registry.
func Lookup(id string) (CheckFunc, bool) { return defaultRegistry.Get(id) }

// RegisteredIDs returns sorted IDs from the default registry.
func RegisteredIDs() []string { return defaultRegistry.IDs() }

// RegisteredCount returns the count of checks in the default registry.
func RegisteredCount() int { return defaultRegistry.Count() }
