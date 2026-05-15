package ingest

import "sync"

// MappingProvider returns the built-in mapping table for a given tool
// id, or (nil, false) if the provider has no built-in coverage. The
// SARIF and OCSF subpackages each implement one and register via
// RegisterMappingProvider during init().
type MappingProvider interface {
	// BuiltinTools is the sorted list of tool / product identifiers
	// this provider ships built-in mappings for.
	BuiltinTools() []string

	// Mapping returns the built-in mapping table for toolID, or
	// (nil, false) if no built-in entry covers it.
	Mapping(toolID string) (*MappingTable, bool)
}

var (
	providerMu   sync.RWMutex
	mapProviders = []MappingProvider{}
)

// RegisterMappingProvider installs a provider into the unified
// registry. Each format's subpackage calls this from init() (or its
// adapter's init()) so `compliancekit mapping list` can enumerate
// every embedded table without the CLI knowing about each subpackage
// explicitly.
func RegisterMappingProvider(p MappingProvider) {
	providerMu.Lock()
	defer providerMu.Unlock()
	mapProviders = append(mapProviders, p)
}

// AllBuiltinMappings returns every built-in mapping table across
// registered providers. Keyed by tool/product id; collisions
// (two providers shipping a table for the same id) keep the first
// registered entry — adapter packages must register unique ids.
func AllBuiltinMappings() map[string]*MappingTable {
	providerMu.RLock()
	defer providerMu.RUnlock()

	out := map[string]*MappingTable{}
	for _, p := range mapProviders {
		for _, id := range p.BuiltinTools() {
			if _, dup := out[id]; dup {
				continue
			}
			if tab, ok := p.Mapping(id); ok && tab != nil {
				out[id] = tab
			}
		}
	}
	return out
}

// LookupBuiltinMapping returns the built-in mapping table for toolID,
// or (nil, false) if no provider ships one for that id.
func LookupBuiltinMapping(toolID string) (*MappingTable, bool) {
	providerMu.RLock()
	defer providerMu.RUnlock()

	for _, p := range mapProviders {
		if tab, ok := p.Mapping(toolID); ok && tab != nil {
			return tab, true
		}
	}
	return nil, false
}
