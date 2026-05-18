package terraform

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/remediate/render"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func init() {
	register("tf-hetzner-fw-default-deny",
		[]string{
			"hetzner-firewall-allow-any-source",
			"hetzner-firewall-allow-all-ports",
		},
		renderHetznerFirewallTighten)
	register("tf-hetzner-server-no-public-only",
		[]string{"hetzner-server-public-only"},
		renderHetznerServerNetwork)
	register("tf-hetzner-server-backups",
		[]string{"hetzner-server-no-backups"},
		renderHetznerServerBackups)
}

func renderHetznerFirewallTighten(f compliancekit.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "hcloud_firewall", tfIdent(name))
	b.Attr("# NOTE: replace any 0.0.0.0/0 rule with a tighter source_ips list", "")
	b.Attr("name", name)
	rule := b.SubBlock("rule")
	rule.Attr("direction", "in")
	rule.Attr("protocol", "tcp")
	rule.Attr("port", "443")
	rule.Attr("source_ips", []string{"YOUR.OFFICE.CIDR/32"})
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("hcloud firewall describe %s -o format='{{json .}}'", render.ShellQuote(name)),
		Notes:      "Replace YOUR.OFFICE.CIDR/32 with the actual source range you trust. For public-facing web traffic prefer a Hetzner Cloud Load Balancer in front of the servers, not direct ingress.",
		Refs: []string{
			"https://docs.hetzner.com/cloud/firewalls/overview",
		},
	}, nil
}

func renderHetznerServerNetwork(f compliancekit.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "hcloud_server", tfIdent(name))
	b.Attr("# NOTE: attach to a private network on existing hcloud_server", "")
	b.Attr("name", name)
	net := b.SubBlock("network")
	net.RawAttr("network_id", "hcloud_network.private.id")
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		Notes:      "Requires a hcloud_network resource. East-west traffic between servers should route via the private network; public IP can stay attached for ingress from the internet — disable public_net.ipv4 only if all north-south traffic goes through a load balancer.",
		Refs: []string{
			"https://docs.hetzner.com/cloud/networks/overview",
		},
	}, nil
}

func renderHetznerServerBackups(f compliancekit.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "hcloud_server", tfIdent(name))
	b.Attr("# NOTE: enable Hetzner's daily backup feature on existing hcloud_server", "")
	b.Attr("name", name)
	b.Attr("backups", true)
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("hcloud server describe %s -o format='{{.BackupWindow}}'", render.ShellQuote(name)),
		Notes:      "Adds ~20% to server cost; provides 7 rolling daily snapshots. For databases prefer hcloud_volume snapshots or external backup tooling.",
		Refs: []string{
			"https://docs.hetzner.com/cloud/servers/backups-snapshots/overview",
		},
	}, nil
}
