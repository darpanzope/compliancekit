package digitalocean

import (
	"context"
	"fmt"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

// CheckVPCDefaultNotInUse flags accounts where any non-default VPC
// exists but a droplet still sits in the default VPC. The default
// VPC is shared by every droplet a new account creates; production
// workloads belong in a named VPC for segmentation + naming
// hygiene.
var CheckVPCDefaultNotInUse = core.Check{
	ID:           "do-vpc-default-not-in-use",
	Title:        "Default VPC should not host production droplets",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "vpcs",
	ResourceType: docol.VPCType,
	Description: "DigitalOcean creates a default VPC per region the first " +
		"time an account creates a resource there. The default VPC is " +
		"convenient for experiments but a posture-anti-pattern for " +
		"production: any droplet without an explicit VPC choice lands " +
		"in it, mixing prod and dev traffic on the same broadcast " +
		"domain. A named VPC per environment is the modern baseline.",
	Remediation: "Create a named VPC per environment: 'doctl vpcs create " +
		"--name prod-nyc3 --region nyc3 --ip-range 10.10.0.0/16'. " +
		"Move droplets by snapshotting + recreating into the named " +
		"VPC (DO does not support in-place VPC migration).",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"12.2", "12.4"},
	},
	Tags:    []string{"network", "segmentation"},
	Scanner: "vpcs.DefaultNotInUse",
}

func VPCDefaultNotInUse(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, v := range g.ByType(docol.VPCType) {
		f := core.Finding{
			CheckID:  CheckVPCDefaultNotInUse.ID,
			Severity: CheckVPCDefaultNotInUse.Severity,
			Resource: v.Ref(),
			Tags:     CheckVPCDefaultNotInUse.Tags,
		}
		isDefault, _ := v.Attributes["is_default"].(bool)
		members, _ := v.Attributes["member_count"].(int)
		if !isDefault {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("vpc %q: not the default VPC", v.Name)
			findings = append(findings, f)
			continue
		}
		if members <= 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("vpc %q: default VPC has no members", v.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("vpc %q: default VPC has %d member(s) (should use a named VPC)", v.Name, members)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckVPCOrphan flags non-default VPCs with zero members. They
// were created and then forgotten; either delete or attach.
var CheckVPCOrphan = core.Check{
	ID:           "do-vpc-orphan",
	Title:        "Non-default VPCs should have at least one member",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "vpcs",
	ResourceType: docol.VPCType,
	Description: "A non-default VPC with zero members is dead weight: it " +
		"reserves an IP range, shows up in firewall and routing audits, " +
		"and contributes to incident-response confusion ('which VPC " +
		"protects this droplet?'). Either attach resources or delete it.",
	Remediation: "List VPCs and members: 'doctl vpcs list' followed by " +
		"'doctl vpcs members <vpc-id>'. For empty named VPCs, either " +
		"move resources in or 'doctl vpcs delete <vpc-id>'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"network", "hygiene"},
	Scanner: "vpcs.Orphan",
}

func VPCOrphan(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, v := range g.ByType(docol.VPCType) {
		isDefault, _ := v.Attributes["is_default"].(bool)
		if isDefault {
			continue
		}
		members, _ := v.Attributes["member_count"].(int)
		f := core.Finding{
			CheckID:  CheckVPCOrphan.ID,
			Severity: CheckVPCOrphan.Severity,
			Resource: v.Ref(),
			Tags:     CheckVPCOrphan.Tags,
		}
		switch {
		case members < 0:
			// member_count = -1 means lookup failed.
			f.Status = core.StatusSkip
			f.Message = fmt.Sprintf("vpc %q: member count unavailable (permission denied?)", v.Name)
		case members == 0:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("vpc %q: zero members", v.Name)
		default:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("vpc %q: %d member(s)", v.Name, members)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckVPCPeeringActive flags VPC peerings whose status is not
// "ACTIVE". Stuck-in-PENDING peerings are usually a sign of a
// half-completed setup, often by a former operator.
var CheckVPCPeeringActive = core.Check{
	ID:           "do-vpc-peering-not-active",
	Title:        "VPC peerings should be in ACTIVE status",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "vpcs",
	ResourceType: docol.VPCPeeringType,
	Description: "A VPC peering in PENDING or other non-ACTIVE status is " +
		"either a half-completed setup (the peering was initiated and " +
		"never accepted on the other side) or an in-progress " +
		"administrative action. Stuck peerings can hide misrouted " +
		"traffic; clean them up.",
	Remediation: "List peerings: 'doctl vpcs peerings list'. For non-ACTIVE " +
		"entries, either complete the peering (accept on the other side) " +
		"or delete: 'doctl vpcs peerings delete <id>'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.22"},
		"cis-v8":   {"12.2"},
	},
	Tags:    []string{"network", "peering", "hygiene"},
	Scanner: "vpcs.PeeringActive",
}

func VPCPeeringActive(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(docol.VPCPeeringType) {
		status, _ := p.Attributes["status"].(string)
		f := core.Finding{
			CheckID:  CheckVPCPeeringActive.ID,
			Severity: CheckVPCPeeringActive.Severity,
			Resource: p.Ref(),
			Tags:     CheckVPCPeeringActive.Tags,
		}
		if status == "ACTIVE" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("peering %q: ACTIVE", p.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("peering %q: status=%q", p.Name, status)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckVPCDefaultNotInUse, VPCDefaultNotInUse)
	core.Register(CheckVPCOrphan, VPCOrphan)
	core.Register(CheckVPCPeeringActive, VPCPeeringActive)
}
