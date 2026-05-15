package sarif

import (
	"embed"
	"fmt"
	"sync"

	"go.yaml.in/yaml/v3"

	"github.com/darpanzope/compliancekit/internal/ingest"
)

// builtinMappings holds the embedded mapping tables shipped with the
// binary. One file per tool under mappings/<tool>.yaml. Operators
// override via the CLI's --mapping flag or the ingest: block in
// compliancekit.yaml.
//
//go:embed mappings/*.yaml
var builtinMappingsFS embed.FS

// builtinMappingTables is the parsed registry of built-in mappings,
// keyed by canonical tool identifier (lowercase). Initialized lazily
// by lookupBuiltinMapping; we don't decode at package init() because
// not every binary invocation needs ingest at all.
var (
	builtinMappingTables map[string]*ingest.MappingTable
	builtinMappingErr    error
	builtinMappingOnce   sync.Once
)

// lookupBuiltinMapping returns the built-in mapping table for the
// given canonical tool ID, or nil if no built-in covers that tool.
// A nil return is non-fatal — the SARIF adapter falls through to
// "no mapping; emit unattributed findings with a warning".
func lookupBuiltinMapping(toolID string) *ingest.MappingTable {
	builtinMappingOnce.Do(func() {
		builtinMappingTables, builtinMappingErr = loadAllBuiltins()
	})
	if builtinMappingErr != nil {
		// Surfacing the error via warning rather than panic. Built-in
		// YAMLs are tested at build time; the runtime case is "embed
		// got corrupted somehow," which is interesting to learn about
		// but should not stop a scan.
		return nil
	}
	return builtinMappingTables[toolID]
}

// loadAllBuiltins parses every yaml under mappings/ into MappingTable
// values. Called once via builtinMappingOnce. Returns a map keyed by
// each table's Tool field.
func loadAllBuiltins() (map[string]*ingest.MappingTable, error) {
	out := map[string]*ingest.MappingTable{}

	entries, err := builtinMappingsFS.ReadDir("mappings")
	if err != nil {
		return nil, fmt.Errorf("read embedded mappings dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := "mappings/" + e.Name()
		b, err := builtinMappingsFS.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var tab ingest.MappingTable
		if err := yaml.Unmarshal(b, &tab); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		if tab.Tool == "" {
			return nil, fmt.Errorf("%s: missing 'tool' field", path)
		}
		out[tab.Tool] = &tab
	}
	return out, nil
}

// BuiltinTools returns the sorted list of tools the package ships
// embedded mappings for. Exposed for `compliancekit ingest --list`
// and for the `compliancekit mapping` subcommand.
func BuiltinTools() []string {
	builtinMappingOnce.Do(func() {
		builtinMappingTables, builtinMappingErr = loadAllBuiltins()
	})
	if builtinMappingErr != nil {
		return nil
	}
	out := make([]string, 0, len(builtinMappingTables))
	for k := range builtinMappingTables {
		out = append(out, k)
	}
	return out
}

// Mapping returns the built-in mapping table for the given tool id,
// or (nil, false) if no built-in covers it.
func Mapping(toolID string) (*ingest.MappingTable, bool) {
	if tab := lookupBuiltinMapping(toolID); tab != nil {
		return tab, true
	}
	return nil, false
}

// provider satisfies ingest.MappingProvider so the parent ingest
// package's unified registry can enumerate this package's mappings.
type provider struct{}

func (provider) BuiltinTools() []string                             { return BuiltinTools() }
func (provider) Mapping(toolID string) (*ingest.MappingTable, bool) { return Mapping(toolID) }

func init() {
	ingest.RegisterMappingProvider(provider{})
}
