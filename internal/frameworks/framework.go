// Package frameworks loads compliance framework definitions from
// embedded YAML files and exposes them for the reporters and the
// `checks list` / `checks show` commands.
//
// Each framework file lives under internal/frameworks/<id>.yaml and is
// baked into the binary via go:embed -- compliancekit stays operable
// air-gapped per ARCHITECTURE.md §13.
//
// As of v1.0 the catalog *types* (Framework, Control, Tactic,
// ResolvedControl) live in pkg/compliancekit and are part of the
// SemVer-stable surface; this package keeps the YAML loader, the
// merged-with-runtime registry, and the bundled embed.FS but does
// not own the type shapes.
package frameworks

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"

	yaml "go.yaml.in/yaml/v3"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// embedded contains every framework YAML in this directory.
//
//go:embed *.yaml
var embedded embed.FS

// CategoryCompliance / CategoryThreatModel re-export the v1.0
// public constants so existing internal callers don't have to swap
// imports during the migration window.
const (
	CategoryCompliance  = compliancekit.CategoryCompliance
	CategoryThreatModel = compliancekit.CategoryThreatModel
)

// Framework, Tactic, Control, and ResolvedControl alias the v1.0
// public catalog types. YAML loading + the runtime registry keep
// operating against the aliased shapes; embedders building their
// own catalog import pkg/compliancekit directly.
type (
	Framework       = compliancekit.Framework
	Tactic          = compliancekit.Tactic
	Control         = compliancekit.Control
	ResolvedControl = compliancekit.ResolvedControl
)

// LoadAll reads every embedded framework YAML and returns a map keyed
// by framework ID. Called once per process via the cached helpers below.
func LoadAll() (map[string]*Framework, error) {
	out := map[string]*Framework{}
	err := fs.WalkDir(embedded, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".yaml" {
			return nil
		}
		data, err := embedded.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		var fw Framework
		if err := yaml.Unmarshal(data, &fw); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if fw.ID == "" {
			return fmt.Errorf("parse %s: framework has empty 'id'", path)
		}
		// Backfill the ID field on every Control from its map key so
		// callers iterating fw.Controls don't have to thread the key
		// alongside the value.
		for id, ctrl := range fw.Controls {
			ctrl.ID = id
			fw.Controls[id] = ctrl
		}
		if _, dup := out[fw.ID]; dup {
			return fmt.Errorf("duplicate framework id %q in %s", fw.ID, path)
		}
		out[fw.ID] = &fw
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var (
	loadOnce  sync.Once
	loadCache map[string]*Framework
	loadErr   error

	runtimeMu sync.RWMutex
	runtime   = map[string]*Framework{}
)

// All returns the loaded framework set, parsing the embedded YAML on
// first call and caching for subsequent calls, then merging any
// runtime-registered frameworks (see Register). Runtime entries take
// precedence over embedded entries with the same ID so operators
// can override a built-in catalog by providing their own via
// OSCAL-Catalog ingest at scan time. The map keys are framework IDs
// ("soc2", "cis-v8", "custom-internal"); values are owned by the
// cache and must not be mutated by callers.
func All() (map[string]*Framework, error) {
	loadOnce.Do(func() {
		loadCache, loadErr = LoadAll()
	})
	if loadErr != nil {
		return nil, loadErr
	}

	runtimeMu.RLock()
	defer runtimeMu.RUnlock()

	// Build a fresh merged map per call so callers can't accidentally
	// mutate the cache by writing to the returned map.
	merged := make(map[string]*Framework, len(loadCache)+len(runtime))
	for k, v := range loadCache {
		merged[k] = v
	}
	for k, v := range runtime {
		merged[k] = v
	}
	return merged, nil
}

// Get returns one framework by ID, or (nil, false) if the ID is
// unknown or framework loading failed. Runtime registrations
// (frameworks.Register) take precedence over embedded entries.
func Get(id string) (*Framework, bool) {
	runtimeMu.RLock()
	if fw, ok := runtime[id]; ok {
		runtimeMu.RUnlock()
		return fw, true
	}
	runtimeMu.RUnlock()

	all, err := All()
	if err != nil {
		return nil, false
	}
	fw, ok := all[id]
	return fw, ok
}

// Register installs a framework into the runtime registry. v0.13+
// uses this to bind frameworks loaded from external OSCAL Catalogs
// at scan time, so a customer's bespoke FedRAMP-style framework
// becomes scannable without writing a new embedded YAML.
//
// Registering a framework whose ID matches an embedded one is
// allowed and intentional: the operator's runtime version takes
// precedence, which is how OSCAL Catalog ingest can shadow the
// bundled NIST 800-53 catalog with a customer-tailored variant.
//
// Returns ErrFrameworkInvalid if fw is nil or has empty ID; in
// that case the registry is unchanged.
func Register(fw *Framework) error {
	if fw == nil {
		return ErrFrameworkInvalid
	}
	if fw.ID == "" {
		return ErrFrameworkInvalid
	}
	runtimeMu.Lock()
	defer runtimeMu.Unlock()
	runtime[fw.ID] = fw
	return nil
}

// Unregister removes a runtime-registered framework. Returns true if
// the entry existed. Embedded frameworks cannot be removed via this
// path — only runtime entries; the embedded set is always available
// to Get/All as the fallback layer.
func Unregister(id string) bool {
	runtimeMu.Lock()
	defer runtimeMu.Unlock()
	if _, ok := runtime[id]; !ok {
		return false
	}
	delete(runtime, id)
	return true
}

// RegisteredRuntime returns the IDs of frameworks added via Register.
// Sorted. Useful for the doctor command and for tests that need to
// isolate registry state. Excludes embedded frameworks.
func RegisteredRuntime() []string {
	runtimeMu.RLock()
	defer runtimeMu.RUnlock()
	out := make([]string, 0, len(runtime))
	for id := range runtime {
		out = append(out, id)
	}
	// Sort for deterministic output.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// ErrFrameworkInvalid is returned by Register when its argument is
// nil or has empty ID. Treat as a programmer error.
var ErrFrameworkInvalid = fmt.Errorf("framework is nil or has empty ID")

// ResolveCheckControls walks a check's Frameworks map and returns
// every (framework, control) pair it claims. Unknown framework IDs
// and unknown control IDs are silently skipped so a check referencing
// a framework not yet bundled in the binary still produces partial
// resolution rather than an error.
func ResolveCheckControls(checkFrameworks map[string][]string) []ResolvedControl {
	all, err := All()
	if err != nil {
		return nil
	}
	var out []ResolvedControl
	for fwID, controlIDs := range checkFrameworks {
		fw, ok := all[fwID]
		if !ok {
			continue
		}
		for _, cid := range controlIDs {
			ctrl, ok := fw.Controls[cid]
			if !ok {
				continue
			}
			out = append(out, ResolvedControl{Framework: fw, Control: ctrl})
		}
	}
	return out
}

// reset is used by tests to flush the cache.
func reset() {
	loadOnce = sync.Once{}
	loadCache = nil
	loadErr = nil
}
