// Package ingest reads findings produced by external security tools
// (Trivy, Checkov, KICS, AWS Security Hub, GCP SCC, Defender, …) and
// projects them onto compliancekit's resource graph + framework
// catalog. Each external wire format (SARIF, OCSF, OSCAL Assessment
// Results) gets its own adapter; all adapters share a common
// Ingester interface so the CLI and scan engine route work uniformly.
//
// v0.13+. ROADMAP § v0.13 details the broader composition goal:
// don't re-implement detection (Trivy + Grype already do that well);
// add value by joining external findings to cloud resources and
// mapping them to framework controls. That mapping turns "image X
// has CVE-Y" into "image X has CVE-Y, runs on droplet Z in SOC 2
// CC7.1 scope, partial tailoring justification noted, evidence
// pack regenerated."
package ingest

import (
	"context"
	"fmt"
	"io"
	"sort"
	"sync"
)

// Ingester is the contract every adapter implements. Implementations
// must be stateless: the same instance may be reused across scans
// and ingest invocations. All per-call state (graph projection,
// mapping table, provenance metadata) flows through IngestOptions.
type Ingester interface {
	// Format returns the canonical format identifier ("sarif", "ocsf",
	// "oscal-ar", "oscal-catalog"). The CLI's --format flag matches
	// against this value; the registry uses it as the lookup key.
	Format() string

	// Description is a one-line human-readable summary surfaced by
	// `compliancekit ingest --list` and the doctor command. Should
	// name the tool family the adapter consumes, e.g.
	// "SARIF 2.1.0 — Trivy, Checkov, KICS, Terrascan, GitHub
	// CodeQL".
	Description() string

	// Ingest decodes bytes from r and returns the projected findings
	// plus any phantom resources the adapter created. Adapters must
	// not write to opts.Graph directly — caller stitches Resources
	// into the live graph after Ingest returns so a parse error
	// leaves no half-applied state.
	Ingest(ctx context.Context, r io.Reader, opts Options) (Result, error)
}

// Registry holds the set of registered Ingester implementations.
// Adapters self-register via Register in their package init(), so
// importing the adapter package is enough to make `--format=<name>`
// resolve. Concurrency-safe.
type Registry struct {
	mu        sync.RWMutex
	ingesters map[string]Ingester
}

// NewRegistry returns an empty Registry. The CLI uses Default;
// tests use NewRegistry to isolate registrations.
func NewRegistry() *Registry {
	return &Registry{ingesters: map[string]Ingester{}}
}

// Register adds an ingester to the registry. Panics on duplicate
// format names — a duplicate registration is a programmer error,
// not a runtime condition.
func (r *Registry) Register(i Ingester) {
	r.mu.Lock()
	defer r.mu.Unlock()
	format := i.Format()
	if format == "" {
		panic("ingest: Ingester.Format() returned empty string")
	}
	if _, exists := r.ingesters[format]; exists {
		panic(fmt.Sprintf("ingest: duplicate Ingester for format %q", format))
	}
	r.ingesters[format] = i
}

// Lookup returns the ingester registered for format, or (nil, false)
// if no adapter handles it.
func (r *Registry) Lookup(format string) (Ingester, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	i, ok := r.ingesters[format]
	return i, ok
}

// Formats returns the sorted list of registered format identifiers.
// Used by `compliancekit ingest --list` and by error messages on
// unknown --format values.
func (r *Registry) Formats() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.ingesters))
	for f := range r.ingesters {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// Default is the process-wide registry adapter packages register
// against. The CLI calls Default.Lookup. Tests that need to isolate
// state instantiate their own via NewRegistry.
var Default = NewRegistry()

// Register installs an ingester into the Default registry. Adapter
// packages call this from init().
func Register(i Ingester) {
	Default.Register(i)
}
