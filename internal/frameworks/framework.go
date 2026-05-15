// Package frameworks loads compliance framework definitions from
// embedded YAML files and exposes them for the reporters and the
// `checks list` / `checks show` commands.
//
// Each framework file lives under internal/frameworks/<id>.yaml and is
// baked into the binary via go:embed -- compliancekit stays operable
// air-gapped per ARCHITECTURE.md §13.
//
// At v0.11 three frameworks ship in production: SOC 2 Trust Services
// Criteria (soc2), ISO 27001:2022 Annex A (iso27001), and CIS Controls
// v8 (cis-v8). v0.12 expands every existing catalog to its full
// control surface and adds four more frameworks: NIST 800-53 r5,
// HIPAA Security Rule, PCI-DSS v4, and MITRE ATT&CK Enterprise
// (the last is special-cased — see Framework.Category).
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

// CategoryCompliance / CategoryThreatModel classify a framework. Most
// frameworks are audit-shaped: a finite control catalog that a check
// either reaches or does not. MITRE ATT&CK is different — it maps to
// tactics + techniques along the kill chain, so the reporter renders
// it as a matrix view rather than a control checklist. Frameworks
// default to compliance when Category is empty.
const (
	CategoryCompliance  = "compliance"
	CategoryThreatModel = "threat_model"
)

// Framework is a compliance standard with a named set of controls.
type Framework struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Version     string `yaml:"version,omitempty"`
	Description string `yaml:"description,omitempty"`
	URL         string `yaml:"url,omitempty"`
	// Category distinguishes audit-shaped compliance frameworks
	// (default) from threat-model frameworks like MITRE ATT&CK.
	// Empty == compliance for back-compat with v0.3-era yamls.
	Category string `yaml:"category,omitempty"`
	// Source cites the authoritative document the catalog was
	// derived from, for auditor transparency.
	Source string `yaml:"source,omitempty"`
	// Tactics is populated only for threat-model frameworks
	// (Category=threat_model). Ordered along the kill chain.
	Tactics  []Tactic           `yaml:"tactics,omitempty"`
	Controls map[string]Control `yaml:"controls"`
}

// IsThreatModel reports whether this framework renders as an ATT&CK-
// style matrix rather than a control checklist.
func (f *Framework) IsThreatModel() bool {
	return f.Category == CategoryThreatModel
}

// Tactic is a phase in a threat-model kill chain (MITRE ATT&CK uses
// "Initial Access", "Execution", ..., "Impact"). Each tactic has an
// ID like TA0001 and references the techniques mapped to it. Tactics
// are ignored for compliance-category frameworks.
type Tactic struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	Techniques  []string `yaml:"techniques,omitempty"`
}

// Control is a single named requirement within a framework. The ID is
// the map key from YAML; backfilled into the struct by LoadAll so
// callers iterating Controls don't have to track the key separately.
//
// Optional fields support framework-specific metadata that the
// reporter surfaces conditionally:
//   - Family (NIST 800-53): "AC" for Access Control, "AU" for Audit, etc.
//   - Tags (CIS v8): "ig1"/"ig2"/"ig3" Implementation Group; (HIPAA):
//     "required" / "addressable" implementation specification class;
//     (ATT&CK technique): tactic ID(s) the technique belongs to.
//   - References: pointer back to authoritative paragraph numbers.
type Control struct {
	ID          string   `yaml:"-"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	Family      string   `yaml:"family,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	References  []string `yaml:"references,omitempty"`
}

// HasTag reports whether the control carries the given tag. Case-
// insensitive to keep yaml editing friction low ("IG1" vs "ig1").
func (c Control) HasTag(tag string) bool {
	for _, t := range c.Tags {
		if equalFold(t, tag) {
			return true
		}
	}
	return false
}

// equalFold avoids pulling strings.EqualFold up to the package level
// just for one use site.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
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
