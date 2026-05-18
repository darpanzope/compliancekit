// Package hcloud implements remediate.Strategy renderers for the
// FormatHcloud output. One-liner hcloud commands for native Hetzner
// CheckIDs, paired with internal/remediate/terraform/hetzner.go.
package hcloud

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/remediate/render"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

type strategyFunc func(compliancekit.Finding) (remediate.Snippet, error)

type strategy struct {
	name string
	ids  []string
	fn   strategyFunc
}

func (s *strategy) Name() string                { return s.name }
func (s *strategy) CheckIDs() []string          { return s.ids }
func (s *strategy) Formats() []remediate.Format { return []remediate.Format{remediate.FormatHcloud} }
func (s *strategy) Render(f compliancekit.Finding, format remediate.Format) (remediate.Snippet, error) {
	if format != remediate.FormatHcloud {
		return remediate.Snippet{}, remediate.ErrFormatUnsupported
	}
	return s.fn(f)
}

func register(name string, ids []string, fn strategyFunc) {
	remediate.Register(&strategy{name: name, ids: ids, fn: fn})
}

func init() {
	register("hcloud-firewall-list",
		[]string{
			"hetzner-firewall-allow-any-source",
			"hetzner-firewall-allow-all-ports",
		}, renderFirewallInspect)
	register("hcloud-server-backups",
		[]string{"hetzner-server-no-backups"}, renderServerBackups)
	register("hcloud-server-private-network",
		[]string{"hetzner-server-public-only"}, renderServerPrivateNetwork)
}

func renderFirewallInspect(f compliancekit.Finding) (remediate.Snippet, error) {
	id := f.Resource.Name
	if id == "" {
		id = "FIREWALL_ID"
	}
	cmd := fmt.Sprintf(
		`# Inspect the firewall — look for 0.0.0.0/0 sources or wide port ranges.
hcloud firewall describe %s

# Replace the wide rule (this example pins TCP/443 to a corporate CIDR).
# hcloud firewall delete-rule %s --direction in --port 443 --protocol tcp --source-ips 0.0.0.0/0
# hcloud firewall add-rule    %s --direction in --port 443 --protocol tcp --source-ips YOUR.CIDR/32`,
		render.ShellQuote(id), render.ShellQuote(id), render.ShellQuote(id))
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: cmd,
		Notes: "Hetzner firewalls are stateless ACLs. Public web traffic should go through a Hetzner Cloud Load Balancer.",
	}, nil
}

func renderServerBackups(f compliancekit.Finding) (remediate.Snippet, error) {
	id := f.Resource.Name
	if id == "" {
		id = "SERVER_ID"
	}
	cmd := fmt.Sprintf("hcloud server enable-backup %s", render.ShellQuote(id))
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: cmd,
		VerifyCmd:   fmt.Sprintf("hcloud server describe %s -o format='{{.BackupWindow}}'", render.ShellQuote(id)),
		RollbackCmd: fmt.Sprintf("hcloud server disable-backup %s", render.ShellQuote(id)),
		Notes:       "Daily snapshots, 7 rolling. ~20% billing surcharge. For databases, prefer per-volume snapshots or external backup tooling.",
	}, nil
}

func renderServerPrivateNetwork(f compliancekit.Finding) (remediate.Snippet, error) {
	id := f.Resource.Name
	if id == "" {
		id = "SERVER_ID"
	}
	cmd := fmt.Sprintf(
		`# Attach server to an existing private network. The network must already exist.
hcloud network list
# hcloud server attach-to-network %s --network $NETWORK_NAME --ip 10.0.0.10`,
		render.ShellQuote(id))
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: cmd,
		VerifyCmd: fmt.Sprintf("hcloud server describe %s -o format='{{.PrivateNet}}'", render.ShellQuote(id)),
		Notes:     "Public IP stays attached. East-west traffic should prefer the private network address; lock down sshd to bind on it instead of 0.0.0.0.",
	}, nil
}
