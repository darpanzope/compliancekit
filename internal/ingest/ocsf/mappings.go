package ocsf

import (
	"embed"
	"fmt"
	"sync"

	"go.yaml.in/yaml/v3"

	"github.com/darpanzope/compliancekit/internal/ingest"
)

//go:embed mappings/*.yaml
var builtinMappingsFS embed.FS

var (
	builtinMappingTables map[string]*ingest.MappingTable
	builtinMappingErr    error
	builtinMappingOnce   sync.Once
)

func lookupBuiltinMapping(productID string) *ingest.MappingTable {
	builtinMappingOnce.Do(func() {
		builtinMappingTables, builtinMappingErr = loadAllBuiltins()
	})
	if builtinMappingErr != nil {
		return nil
	}
	return builtinMappingTables[productID]
}

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

// BuiltinProducts returns the sorted list of OCSF producer products
// for which the package ships embedded mappings.
func BuiltinProducts() []string {
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
