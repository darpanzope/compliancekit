// Package linux is the Linux SSH collector (v0.2+).
//
// It parses inventory.yaml (this file), opens pooled SSH connections
// (ssh.go, v0.2 Phase 1b), runs read-only fact-gathering snippets
// remotely, and emits typed Resources for each host. Checks under
// internal/checks/linux/ consume the emitted Resources.
//
// At v0.2 Phase 1a, only the inventory parser lives here; the SSH and
// fact-gathering layers land in subsequent phases.
package linux

import (
	"fmt"
	"os"
	"sort"

	yaml "go.yaml.in/yaml/v3"
)

// Inventory describes the hosts and groups the linux collector will scan.
// See CONFIGURATION.md for the schema reference.
type Inventory struct {
	// Hosts is the flat list of ungrouped targets.
	Hosts []Host `yaml:"hosts,omitempty"`

	// Groups is named collections of hosts. Group names are arbitrary
	// labels; checks may filter on them in future versions.
	Groups map[string]Group `yaml:"groups,omitempty"`
}

// Host is a single SSH target. Fields that are empty fall back to the
// defaults declared in compliancekit.yaml under providers.linux.ssh.
type Host struct {
	// Host is the address (DNS name or IP). Required.
	Host string `yaml:"host"`

	// User overrides providers.linux.ssh.user for this host.
	User string `yaml:"user,omitempty"`

	// Port overrides providers.linux.ssh.port (default 22).
	Port int `yaml:"port,omitempty"`

	// SSH carries per-host overrides for finer-grained settings.
	SSH *HostSSH `yaml:"ssh,omitempty"`

	// Tags propagate to every Resource the collector emits for this host.
	// Checks can filter on tags via the --tags CLI flag.
	Tags []string `yaml:"tags,omitempty"`

	// Group is the parent group name, populated by AllHosts. Empty for
	// hosts declared at the top level. Not present in YAML; do not set.
	Group string `yaml:"-"`
}

// Group is a named collection of hosts.
type Group struct {
	Hosts []Host `yaml:"hosts"`
}

// HostSSH overrides default SSH parameters for one host. nil fields
// fall through to the providers.linux.ssh defaults.
type HostSSH struct {
	// KeyFile is the path to the private key. Falls back to SSH agent
	// (and then to providers.linux.ssh.key_file) when empty.
	KeyFile string `yaml:"key_file,omitempty"`

	// Timeout is the connection timeout (Go duration syntax: "10s").
	// Stored as string at this layer; parsed when the connection is built.
	Timeout string `yaml:"timeout,omitempty"`

	// StrictHostKey overrides providers.linux.ssh.strict_host_key.
	// Pointer so a false setting differs from "unset" (a non-pointer
	// bool would default to false, indistinguishable from "use the
	// global default of true").
	StrictHostKey *bool `yaml:"strict_host_key,omitempty"`
}

// LoadInventory reads and validates an inventory YAML file.
func LoadInventory(path string) (*Inventory, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied via config
	if err != nil {
		return nil, fmt.Errorf("read inventory %s: %w", path, err)
	}
	return ParseInventory(data)
}

// ParseInventory parses a byte slice in the same format as LoadInventory.
// Useful for tests and for embedding inventories from elsewhere.
func ParseInventory(data []byte) (*Inventory, error) {
	var inv Inventory
	if err := yaml.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("parse inventory: %w", err)
	}
	if err := inv.Validate(); err != nil {
		return nil, fmt.Errorf("invalid inventory: %w", err)
	}
	return &inv, nil
}

// Validate reports structural issues with the inventory: empty content,
// missing host names, duplicate hosts.
func (i *Inventory) Validate() error {
	if len(i.Hosts) == 0 && len(i.Groups) == 0 {
		return fmt.Errorf("inventory contains no hosts or groups")
	}

	seen := map[string]string{} // host -> source ("top-level" or "group:<name>")
	check := func(h Host, source string) error {
		if h.Host == "" {
			return fmt.Errorf("%s: host with empty 'host' field", source)
		}
		if prev, exists := seen[h.Host]; exists {
			return fmt.Errorf("host %q appears in both %s and %s", h.Host, prev, source)
		}
		seen[h.Host] = source
		return nil
	}

	for _, h := range i.Hosts {
		if err := check(h, "top-level"); err != nil {
			return err
		}
	}
	for name, g := range i.Groups {
		for _, h := range g.Hosts {
			if err := check(h, "group:"+name); err != nil {
				return err
			}
		}
	}
	return nil
}

// AllHosts returns every host across top-level and groups, flattened.
//
// Ordering is deterministic: top-level hosts first (in YAML order),
// then groups in lexicographic order of group name, hosts within each
// group preserving YAML order. Deterministic ordering matters for
// finding ordering and for diff stability across runs.
func (i *Inventory) AllHosts() []Host {
	out := make([]Host, 0, len(i.Hosts))
	out = append(out, i.Hosts...)

	names := make([]string, 0, len(i.Groups))
	for name := range i.Groups {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, h := range i.Groups[name].Hosts {
			h.Group = name
			out = append(out, h)
		}
	}
	return out
}
