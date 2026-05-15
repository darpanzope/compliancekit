package remediate

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/darpanzope/compliancekit/internal/core"
)

// Registry indexes Strategy implementations by CheckID for fast
// per-finding dispatch. Each subpackage in internal/remediate/<format>
// calls Register from its init(); the CLI side-effect-imports each
// subpackage so the Default registry is fully populated by start of
// run.
//
// A CheckID may resolve to several strategies (e.g. one Terraform
// strategy + one AWS-CLI strategy for the same S3 finding). Render
// picks the first strategy that supports the requested Format.
type Registry struct {
	mu         sync.RWMutex
	byCheckID  map[string][]Strategy
	wildcards  []Strategy
	registered map[string]Strategy // by Strategy.Name() — dedup
}

// NewRegistry returns an empty Registry. Tests use this to isolate
// strategy registrations; production code goes through Default.
func NewRegistry() *Registry {
	return &Registry{
		byCheckID:  map[string][]Strategy{},
		wildcards:  nil,
		registered: map[string]Strategy{},
	}
}

// Register adds a strategy to the registry. Panics on duplicate
// Strategy.Name() values — a duplicate registration is a programmer
// error caught at init-time, not a runtime condition.
//
// A Strategy with CheckIDs() == ["*"] is filed under wildcards and
// considered only when no concrete strategy claims the CheckID. A
// Strategy with an empty Formats() slice panics; a Strategy with no
// CheckIDs at all panics (there is nothing to register against).
func (r *Registry) Register(s Strategy) {
	if s == nil {
		panic("remediate: Register called with nil strategy")
	}
	name := s.Name()
	if name == "" {
		panic("remediate: Strategy.Name() returned empty string")
	}
	ids := s.CheckIDs()
	if len(ids) == 0 {
		panic(fmt.Sprintf("remediate: strategy %q registered with no CheckIDs", name))
	}
	if len(s.Formats()) == 0 {
		panic(fmt.Sprintf("remediate: strategy %q registered with no Formats", name))
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.registered[name]; exists {
		panic(fmt.Sprintf("remediate: duplicate strategy name %q", name))
	}
	r.registered[name] = s

	for _, id := range ids {
		if id == "*" {
			r.wildcards = append(r.wildcards, s)
			continue
		}
		r.byCheckID[id] = append(r.byCheckID[id], s)
	}
}

// StrategiesFor returns the strategies that handle checkID, in
// registration order. Returns wildcards only if no concrete strategy
// matches. Empty result means no remediation is generatable for that
// CheckID; the CLI routes such findings to POA&M manual-action.
func (r *Registry) StrategiesFor(checkID string) []Strategy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if ss, ok := r.byCheckID[checkID]; ok && len(ss) > 0 {
		out := make([]Strategy, len(ss))
		copy(out, ss)
		return out
	}
	if len(r.wildcards) > 0 {
		out := make([]Strategy, len(r.wildcards))
		copy(out, r.wildcards)
		return out
	}
	return nil
}

// Render produces a Snippet for the (finding, format) pair, trying
// each registered Strategy in order until one supports format. Returns
// ErrNoStrategy if no strategy is registered for the CheckID; returns
// ErrFormatUnsupported if strategies are registered but none can emit
// the requested format.
//
// Strategies that recognize the finding but cannot auto-remediate
// (e.g. credential rotation) MUST return a Snippet with Risk=RiskManual
// and a populated Notes field rather than an error — the caller treats
// "manual" snippets as actionable POA&M input.
func (r *Registry) Render(f core.Finding, format Format) (Snippet, error) {
	strategies := r.StrategiesFor(f.CheckID)
	if len(strategies) == 0 {
		return Snippet{}, fmt.Errorf("%w: %q", ErrNoStrategy, f.CheckID)
	}
	for _, s := range strategies {
		if !supportsFormat(s, format) {
			continue
		}
		snip, err := s.Render(f, format)
		if err != nil {
			if errors.Is(err, ErrFormatUnsupported) {
				continue
			}
			return Snippet{}, fmt.Errorf("remediate: %s: %w", s.Name(), err)
		}
		// Ensure CheckID + Format + Resource are populated even if the
		// strategy forgot to set them. Cheap defensive copy.
		if snip.CheckID == "" {
			snip.CheckID = f.CheckID
		}
		if snip.Format == "" {
			snip.Format = format
		}
		if snip.Resource.ID == "" {
			snip.Resource = f.Resource
		}
		return snip, nil
	}
	return Snippet{}, fmt.Errorf("%w: %s (format=%s)", ErrFormatUnsupported, f.CheckID, format)
}

// RenderAll produces a Snippet for every (finding × format) pair the
// registry can serve. Findings with no registered strategy are
// reported via the unmatched return value so callers can route them
// to POA&M manual-action. Formats a finding's strategies do not
// support are silently skipped (a CVE finding has no kubectl patch).
//
// Order: outer loop over findings (stable), inner loop over AllFormats
// (canonical order). Output is deterministic for a given input slice.
func (r *Registry) RenderAll(findings []core.Finding) (snippets []Snippet, unmatched []core.Finding) {
	for _, f := range findings {
		strategies := r.StrategiesFor(f.CheckID)
		if len(strategies) == 0 {
			unmatched = append(unmatched, f)
			continue
		}
		anyMatched := false
		for _, format := range AllFormats {
			snip, err := r.Render(f, format)
			if err == nil {
				snippets = append(snippets, snip)
				anyMatched = true
			}
		}
		if !anyMatched {
			unmatched = append(unmatched, f)
		}
	}
	return snippets, unmatched
}

// RegisteredCheckIDs returns the sorted union of CheckIDs every
// registered strategy claims. Used by `compliancekit remediate --list`
// to advertise coverage and by CI to assert that every active check
// has at least one strategy (per issue #14 DoD).
func (r *Registry) RegisteredCheckIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := map[string]struct{}{}
	for id := range r.byCheckID {
		seen[id] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// RegisteredStrategies returns every registered Strategy, sorted by
// Strategy.Name(). Used by `compliancekit remediate --list` to print
// the coverage table.
func (r *Registry) RegisteredStrategies() []Strategy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Strategy, 0, len(r.registered))
	for _, s := range r.registered {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// supportsFormat reports whether s declares format in its Formats().
func supportsFormat(s Strategy, format Format) bool {
	for _, f := range s.Formats() {
		if f == format {
			return true
		}
	}
	return false
}

// Default is the process-wide registry every strategy package
// registers against. The CLI calls Default.RenderAll; tests build
// isolated registries via NewRegistry.
var Default = NewRegistry()

// Register installs s into Default. Strategy packages call this
// from init().
func Register(s Strategy) { Default.Register(s) }
