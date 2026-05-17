package linux

import (
	"context"
	"fmt"
	"sync"

	"github.com/darpanzope/compliancekit/internal/config"
	"github.com/darpanzope/compliancekit/internal/core"
)

// HostType is the core.Resource Type emitted per inventory host.
// Exported so check packages can reference it without hard-coding.
const HostType = "linux.host"

// Compile-time assertion that *Collector satisfies core.Collector.
var _ core.Collector = (*Collector)(nil)

// Collector implements core.Collector for SSH-reachable Linux hosts.
//
// At v0.2 it gathers sshd configuration; later phases extend the same
// per-host fan-out with firewall, audit, filesystem, user, kernel,
// service, network, logging, and time gatherers. Each gatherer adds
// one attribute to the Resource emitted per host.
type Collector struct {
	inventory   *Inventory
	sshDefaults config.SSHConfig
	maxParallel int
}

// New constructs a Collector. inventory is the parsed inventory.yaml;
// sshDefaults is the providers.linux.ssh block from compliancekit.yaml.
//
// maxParallel falls back to defaultMaxParallel when sshDefaults sets
// it to zero (a developer who forgets to populate the field still gets
// reasonable concurrency).
func New(inventory *Inventory, sshDefaults config.SSHConfig) *Collector {
	mp := sshDefaults.MaxParallel
	if mp <= 0 {
		mp = defaultMaxParallel
	}
	return &Collector{
		inventory:   inventory,
		sshDefaults: sshDefaults,
		maxParallel: mp,
	}
}

// defaultMaxParallel is the fallback fan-out when neither config nor
// CLI specifies one. Matches the value in CONFIGURATION.md.
const defaultMaxParallel = 16

// Name returns the provider identifier.
func (c *Collector) Name() string { return "linux" }

// Collect fans out across every host in the inventory, gathers facts
// over SSH, and returns one core.Resource per host.
//
// One unreachable host does NOT abort the scan -- it produces a
// Resource with reachable=false plus unreachable_reason, and checks
// can decide to skip or emit StatusError. This matches ROADMAP.md's
// v0.2 DoD: "one bad host doesn't kill the run."
func (c *Collector) Collect(ctx context.Context) ([]core.Resource, error) {
	hosts := c.inventory.AllHosts()
	results := make([]core.Resource, len(hosts))

	sem := make(chan struct{}, c.maxParallel)
	var wg sync.WaitGroup

	for i, h := range hosts {
		i, h := i, h
		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Done()
			results[i] = unreachableResource(h, "scan canceled")
			continue
		}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = c.gatherOne(ctx, h)
		}()
	}
	wg.Wait()

	return results, nil
}

// gatherOne dials a single host and runs every supported fact gatherer
// against the resulting client. Any dial / merge failure produces an
// unreachable Resource; individual gatherer failures attach an
// error attribute so checks can decide whether to skip or fail.
func (c *Collector) gatherOne(ctx context.Context, host Host) core.Resource {
	opts, err := MergeHost(host, c.sshDefaults)
	if err != nil {
		return unreachableResource(host, fmt.Sprintf("merge host: %v", err))
	}

	client, err := Dial(ctx, opts)
	if err != nil {
		return unreachableResource(host, fmt.Sprintf("dial: %v", err))
	}
	defer func() { _ = client.Close() }()

	attrs := map[string]any{"reachable": true}

	// v0.20 phase 1 — distro detection runs FIRST so downstream
	// gatherers + checks can branch on os_release.id without
	// re-probing. The map shape keeps the typed OSRelease struct
	// (osrelease.go) reachable for typed unpacking in the checks.
	if rel, err := gatherOSRelease(ctx, client); err == nil {
		attrs["os_release"] = rel
		attrs["distro_id"] = rel.ID
		attrs["distro_id_like"] = rel.IDLike
		attrs["distro_version"] = rel.VersionID
		attrs["distro_pretty_name"] = rel.PrettyName
	} else {
		attrs["os_release_error"] = err.Error()
	}

	if sshd, err := gatherSSHDConfig(ctx, client); err == nil {
		attrs["sshd_config"] = sshd
	} else {
		attrs["sshd_error"] = err.Error()
	}

	if fw, err := gatherFirewall(ctx, client); err == nil {
		attrs["firewall"] = fw
	} else {
		attrs["firewall_error"] = err.Error()
	}

	if audit, err := gatherAudit(ctx, client); err == nil {
		attrs["audit"] = audit
	} else {
		attrs["audit_error"] = err.Error()
	}

	if fs, err := gatherFilesystem(ctx, client); err == nil {
		attrs["filesystem"] = fs
	} else {
		attrs["filesystem_error"] = err.Error()
	}

	if users, err := gatherUsers(ctx, client); err == nil {
		attrs["users"] = users
	} else {
		attrs["users_error"] = err.Error()
	}

	if kernel, err := gatherKernel(ctx, client); err == nil {
		attrs["kernel"] = kernel
	} else {
		attrs["kernel_error"] = err.Error()
	}

	return core.Resource{
		ID:         "linux.host." + host.Host,
		Type:       HostType,
		Name:       host.Host,
		Provider:   "linux",
		Attributes: attrs,
		Tags:       host.Tags,
	}
}

// unreachableResource is the placeholder Resource emitted when a host
// cannot be reached. The "reachable" attribute is set so checks can
// detect this state with a single Attr() lookup.
func unreachableResource(host Host, reason string) core.Resource {
	return core.Resource{
		ID:       "linux.host." + host.Host,
		Type:     HostType,
		Name:     host.Host,
		Provider: "linux",
		Attributes: map[string]any{
			"reachable":          false,
			"unreachable_reason": reason,
		},
		Tags: host.Tags,
	}
}
