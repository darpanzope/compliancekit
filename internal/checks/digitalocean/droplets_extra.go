package digitalocean

import (
	"context"
	"fmt"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

// dropletHasFeature returns true if the droplet's features slice
// contains the given feature name. Used by the monitoring and
// private-networking checks. Tolerant of the godo features slice
// being either []string (collector path) or []any (test fixtures
// that go through map[string]any).
func dropletHasFeature(d core.Resource, name string) bool {
	switch features := d.Attributes["features"].(type) {
	case []string:
		for _, f := range features {
			if f == name {
				return true
			}
		}
	case []any:
		for _, f := range features {
			if s, ok := f.(string); ok && s == name {
				return true
			}
		}
	}
	return false
}

// CheckDropletMonitoring requires the DO monitoring agent be on.
// Without it, the operator cannot alert on CPU, disk, or memory
// pressure -- and the broader monitoring + alerting story
// degrades to "ssh in and run top."
var CheckDropletMonitoring = core.Check{
	ID:           "do-droplet-monitoring-disabled",
	Title:        "Droplets should have the DigitalOcean monitoring agent enabled",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "droplets",
	ResourceType: docol.DropletType,
	Description: "DigitalOcean's monitoring agent (do-agent) is required " +
		"for the platform's alerting and dashboard story. Without it, " +
		"resource-level metrics (CPU, memory, disk, network) are not " +
		"reported and the alerts API has nothing to fire on. SOC 2 " +
		"CC7.2 + CC7.3 and ISO 27001 A.8.16 both require continuous " +
		"operational monitoring of production resources.",
	Remediation: "Enable monitoring via 'doctl compute droplet-action " +
		"enable-monitoring <id>' or set 'monitoring = true' in the " +
		"Terraform digitalocean_droplet resource. New droplets " +
		"created via the UI have a checkbox for this at create time.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2", "CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"droplet", "monitoring", "alerting"},
	Scanner: "droplets.MonitoringEnabled",
}

func DropletMonitoring(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(docol.DropletType) {
		on := dropletHasFeature(d, "monitoring")
		f := core.Finding{
			CheckID:  CheckDropletMonitoring.ID,
			Severity: CheckDropletMonitoring.Severity,
			Resource: d.Ref(),
			Tags:     CheckDropletMonitoring.Tags,
		}
		if on {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("droplet %q: monitoring agent enabled", d.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("droplet %q: monitoring agent NOT enabled", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckDropletInVPC requires every droplet have a vpc_uuid -- i.e.
// belong to some VPC, default or named. Old DO droplets created
// before VPCs landed at GA in 2020 have no VPC association and
// expose the droplet on the legacy shared private network.
var CheckDropletInVPC = core.Check{
	ID:           "do-droplet-no-vpc",
	Title:        "Droplets must belong to a VPC",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "droplets",
	ResourceType: docol.DropletType,
	Description: "DigitalOcean droplets created before mid-2020 may not be " +
		"associated with a VPC. Without VPC membership the droplet sits " +
		"on a region-wide shared private network where every droplet in " +
		"the region can reach every other droplet's private interface. " +
		"VPC isolation is the modern baseline; a missing vpc_uuid is " +
		"almost certainly a legacy droplet that should be migrated.",
	Remediation: "Create or pick a VPC: 'doctl vpcs list'. Move the " +
		"droplet by destroying and recreating inside the VPC (DO does " +
		"not support migrating an existing droplet across VPCs in " +
		"place; the move is destructive). Take a snapshot first.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"12.2", "12.4"},
	},
	Tags:    []string{"droplet", "network", "segmentation"},
	Scanner: "droplets.InVPC",
}

func DropletInVPC(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(docol.DropletType) {
		vpc, _ := d.Attributes["vpc_uuid"].(string)
		f := core.Finding{
			CheckID:  CheckDropletInVPC.ID,
			Severity: CheckDropletInVPC.Severity,
			Resource: d.Ref(),
			Tags:     CheckDropletInVPC.Tags,
		}
		if vpc != "" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("droplet %q: in VPC %s", d.Name, vpc)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("droplet %q: no VPC association (legacy shared private network)", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckDropletPrivateNetworking requires the "private_networking"
// feature. Without it the droplet has no private interface at all
// and every internal call goes over the public Internet.
var CheckDropletPrivateNetworking = core.Check{
	ID:           "do-droplet-private-networking-disabled",
	Title:        "Droplets must have private networking enabled",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "droplets",
	ResourceType: docol.DropletType,
	Description: "Without the 'private_networking' feature, a droplet " +
		"has no internal interface; every connection to a peer in the " +
		"same region routes over the public Internet, bypasses the " +
		"firewall's allow-from-private-only rules, and inflates egress " +
		"bandwidth bills. Modern DO droplets enable this by default; " +
		"legacy droplets sometimes have it disabled.",
	Remediation: "DO does not support enabling private networking on an " +
		"existing droplet -- the droplet must be recreated. Take a " +
		"snapshot, destroy the droplet, recreate from the snapshot " +
		"with the 'private_networking' feature enabled (default for " +
		"new droplets since 2022).",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"12.2", "12.4"},
	},
	Tags:    []string{"droplet", "network", "private-networking"},
	Scanner: "droplets.PrivateNetworking",
}

func DropletPrivateNetworking(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(docol.DropletType) {
		on := dropletHasFeature(d, "private_networking")
		f := core.Finding{
			CheckID:  CheckDropletPrivateNetworking.ID,
			Severity: CheckDropletPrivateNetworking.Severity,
			Resource: d.Ref(),
			Tags:     CheckDropletPrivateNetworking.Tags,
		}
		if on {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("droplet %q: private networking enabled", d.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("droplet %q: private networking NOT enabled", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckDropletStatusActive flags droplets that are not in the
// "active" state. "off" droplets still bill, "archived" droplets
// indicate possible decommissioning underway, "new"/"unknown"
// suggest the droplet is mid-provision and could be incomplete.
var CheckDropletStatusActive = core.Check{
	ID:           "do-droplet-status-non-active",
	Title:        "Droplets should be in 'active' status",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "droplets",
	ResourceType: docol.DropletType,
	Description: "A droplet in any state other than 'active' is either " +
		"powered off (still billing, not running services), partially " +
		"provisioned (state new), archived, or in an unknown state " +
		"the API can't classify. Each of these is a posture signal " +
		"worth reviewing -- powered-off droplets in particular often " +
		"indicate forgotten environments that still cost money and " +
		"still have attack surface (their public IPs are reserved).",
	Remediation: "List non-active droplets with " +
		"'doctl compute droplet list --format Name,Status'. For each, " +
		"decide: bring it back online (power-on), destroy if obsolete, " +
		"or document the reason in the resource tags.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1", "1.2"},
	},
	Tags:    []string{"droplet", "hygiene"},
	Scanner: "droplets.StatusActive",
}

func DropletStatusActive(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(docol.DropletType) {
		status, _ := d.Attributes["status"].(string)
		f := core.Finding{
			CheckID:  CheckDropletStatusActive.ID,
			Severity: CheckDropletStatusActive.Severity,
			Resource: d.Ref(),
			Tags:     CheckDropletStatusActive.Tags,
		}
		if status == "active" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("droplet %q: active", d.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("droplet %q: status=%q", d.Name, status)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckDropletMonitoring, DropletMonitoring)
	core.Register(CheckDropletInVPC, DropletInVPC)
	core.Register(CheckDropletPrivateNetworking, DropletPrivateNetworking)
	core.Register(CheckDropletStatusActive, DropletStatusActive)
}
