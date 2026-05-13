package core

import "context"

// Collector fetches data from a provider and emits typed Resources for
// the ResourceGraph.
//
// A Collector is constructed with its provider-specific configuration
// (DO token, SSH inventory, kubeconfig path); Collect performs the
// actual fetch and is the only method the engine invokes. Splitting
// construction from execution lets the engine validate every
// collector's config (and surface friendly errors) before spending any
// time on network I/O.
//
// Collectors MUST honor ctx.Done() -- long-running provider scans get
// canceled on user interrupt (Ctrl-C) and on engine-side timeouts.
//
// See DECISIONS.md ADR-001 for the reasoning behind splitting collection
// from evaluation.
type Collector interface {
	// Name returns the provider identifier, e.g. "digitalocean" or "linux".
	// Used in logs, error messages, and the resource ID prefix.
	Name() string

	// Collect fetches resources from the provider. The returned slice is
	// added to the engine's ResourceGraph; the engine handles ordering
	// and de-duplication across collectors.
	Collect(ctx context.Context) ([]Resource, error)
}
