// Package profile is the v0.6 named-subset-of-checks abstraction.
//
// A Profile is a declarative filter over the registered check catalog:
// "only critical and high findings on the digitalocean provider" is
// the ci-fast profile; "only checks that map to soc2" is the
// pre-audit profile; etc.
//
// Profiles live in compliancekit.yaml under the `profiles:` key. The
// `--profile <name>` flag on `scan` selects one; without it, the full
// catalog runs (current v0.5 behavior preserved).
//
// Profiles are pure filters. They never mutate check metadata, never
// rewrite framework mappings, never add new checks. A profile that
// names zero checks is an error -- almost certainly a typo in the
// selector that would silently skip the whole scan otherwise.
package profile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/darpanzope/compliancekit/internal/core"
)

// Profile is one named filter. All selectors are AND-composed: a
// check must pass every populated selector to be included. Empty
// selectors are no-ops (don't filter on that dimension).
type Profile struct {
	// Name is the lookup key under `profiles:`. Populated from the
	// map key by the loader; kept on the struct so passing it around
	// without the map key is unambiguous.
	Name string `yaml:"-"`

	// Description is freeform text the `compliancekit checks list
	// --profile` command surfaces. Optional.
	Description string `yaml:"description,omitempty"`

	// IncludeProviders restricts to checks whose Provider matches.
	IncludeProviders []string `yaml:"include_providers,omitempty"`

	// ExcludeProviders drops checks whose Provider matches.
	ExcludeProviders []string `yaml:"exclude_providers,omitempty"`

	// IncludeSeverities restricts to checks whose Severity matches.
	// Values are the lowercase severity names ("critical", "high"...).
	IncludeSeverities []string `yaml:"include_severities,omitempty"`

	// IncludeFrameworks restricts to checks that map to at least
	// one control in at least one of the listed frameworks.
	IncludeFrameworks []string `yaml:"include_frameworks,omitempty"`

	// IncludeTags restricts to checks carrying at least one of
	// these tags.
	IncludeTags []string `yaml:"include_tags,omitempty"`

	// ExcludeTags drops checks carrying any of these tags.
	ExcludeTags []string `yaml:"exclude_tags,omitempty"`

	// IncludeIDs is an explicit allow-list; the escape hatch for
	// "just these specific check IDs, nothing else." When set, it
	// overrides every other Include* selector (Exclude* still apply).
	IncludeIDs []string `yaml:"include_ids,omitempty"`

	// ExcludeIDs is the explicit reject-list, applied last.
	ExcludeIDs []string `yaml:"exclude_ids,omitempty"`
}

// Filter applies p to checks and returns the surviving subset, sorted
// by ID for deterministic output. Returns an error when the profile
// selectors produce zero checks -- that almost always means a typo,
// and a silent zero-check scan is worse than a loud error.
func (p Profile) Filter(checks []core.Check) ([]core.Check, error) {
	out := make([]core.Check, 0, len(checks))
	for _, c := range checks {
		if p.matches(c) {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("profile %q matches no checks (check selectors against `compliancekit checks list`)", p.Name)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// matches is the per-check selector. Order matters only for short-
// circuiting (cheap checks first); the semantics is pure AND-of-
// populated-selectors.
func (p Profile) matches(c core.Check) bool {
	// Explicit allow-list short-circuits the include* selectors.
	if len(p.IncludeIDs) > 0 {
		if !containsCI(p.IncludeIDs, c.ID) {
			return false
		}
		// Even when IncludeIDs is set, Exclude* still applies.
	} else {
		if len(p.IncludeProviders) > 0 && !containsCI(p.IncludeProviders, c.Provider) {
			return false
		}
		if len(p.IncludeSeverities) > 0 && !containsCI(p.IncludeSeverities, c.Severity.String()) {
			return false
		}
		if len(p.IncludeTags) > 0 && !anyTagMatch(c.Tags, p.IncludeTags) {
			return false
		}
		if len(p.IncludeFrameworks) > 0 && !anyFrameworkMatch(c.Frameworks, p.IncludeFrameworks) {
			return false
		}
	}

	if containsCI(p.ExcludeIDs, c.ID) {
		return false
	}
	if containsCI(p.ExcludeProviders, c.Provider) {
		return false
	}
	if anyTagMatch(c.Tags, p.ExcludeTags) {
		return false
	}
	return true
}

// containsCI is case-insensitive equality. Severities + provider IDs
// are lowercased in the codebase already, but normalizing at the
// selector boundary lets operators write the more readable
// "Critical" or "DigitalOcean" in their yaml without surprise.
func containsCI(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

func anyTagMatch(checkTags, selectorTags []string) bool {
	for _, t := range selectorTags {
		if containsCI(checkTags, t) {
			return true
		}
	}
	return false
}

func anyFrameworkMatch(checkFrameworks map[string][]string, selectorFrameworks []string) bool {
	for _, fw := range selectorFrameworks {
		if _, ok := checkFrameworks[strings.ToLower(fw)]; ok {
			return true
		}
	}
	return false
}
