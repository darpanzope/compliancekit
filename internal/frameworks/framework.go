// Package frameworks loads compliance framework definitions from
// embedded YAML files and exposes them for the reporters and the
// `checks list` / `checks show` commands.
//
// Each framework file lives under internal/frameworks/<id>.yaml and is
// baked into the binary via go:embed -- compliancekit stays operable
// air-gapped per ARCHITECTURE.md §13.
//
// At v0.3 two frameworks ship: SOC 2 Trust Services Criteria (soc2)
// and CIS Controls v8 (cis-v8). ISO 27001 Annex A lands at v0.4
// alongside the evidence pack; NIST 800-53 r5, HIPAA, PCI-DSS, and
// MITRE ATT&CK land at v0.9.
package frameworks

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"

	yaml "go.yaml.in/yaml/v3"
)

// embedded contains every framework YAML in this directory.
//
//go:embed *.yaml
var embedded embed.FS

// Framework is a compliance standard with a named set of controls.
type Framework struct {
	ID          string             `yaml:"id"`
	Name        string             `yaml:"name"`
	Version     string             `yaml:"version,omitempty"`
	Description string             `yaml:"description,omitempty"`
	URL         string             `yaml:"url,omitempty"`
	Controls    map[string]Control `yaml:"controls"`
}

// Control is a single named requirement within a framework. The ID is
// the map key from YAML; backfilled into the struct by LoadAll so
// callers iterating Controls don't have to track the key separately.
type Control struct {
	ID          string `yaml:"-"`
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
}

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
)

// All returns the loaded framework set, parsing the embedded YAML on
// first call and caching for subsequent calls. The map keys are
// framework IDs ("soc2", "cis-v8"); values are owned by the cache and
// must not be mutated by callers.
func All() (map[string]*Framework, error) {
	loadOnce.Do(func() {
		loadCache, loadErr = LoadAll()
	})
	return loadCache, loadErr
}

// Get returns one framework by ID, or (nil, false) if the ID is
// unknown or framework loading failed.
func Get(id string) (*Framework, bool) {
	all, err := All()
	if err != nil {
		return nil, false
	}
	fw, ok := all[id]
	return fw, ok
}

// ResolvedControl pairs a Control with the Framework it belongs to,
// useful when iterating across the controls a single Check references.
type ResolvedControl struct {
	Framework *Framework
	Control   Control
}

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
