// Package doctl implements remediate.Strategy renderers for the
// FormatDoctl output. One-liner doctl commands for native DigitalOcean
// CheckIDs, paired with internal/remediate/terraform/do.go for format
// parity.
package doctl

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/remediate/render"
)

type strategyFunc func(core.Finding) (remediate.Snippet, error)

type strategy struct {
	name string
	ids  []string
	fn   strategyFunc
}

func (s *strategy) Name() string                { return s.name }
func (s *strategy) CheckIDs() []string          { return s.ids }
func (s *strategy) Formats() []remediate.Format { return []remediate.Format{remediate.FormatDoctl} }
func (s *strategy) Render(f core.Finding, format remediate.Format) (remediate.Snippet, error) {
	if format != remediate.FormatDoctl {
		return remediate.Snippet{}, remediate.ErrFormatUnsupported
	}
	return s.fn(f)
}

func register(name string, ids []string, fn strategyFunc) {
	remediate.Register(&strategy{name: name, ids: ids, fn: fn})
}

func init() {
	register("doctl-db-firewall",
		[]string{"do-db-firewall-includes-public", "do-db-no-firewall-rules"},
		renderDBFirewall)
	register("doctl-db-maintenance",
		[]string{"do-db-no-maintenance-window"}, renderDBMaintenance)
	register("doctl-firewall-list",
		[]string{"do-fw-allow-any-source", "do-fw-allow-all-ports"}, renderFirewallListInspect)
	register("doctl-droplet-list",
		[]string{"do-droplet-no-vpc"}, renderDropletInspect)
	register("doctl-certificate-near-expiry",
		[]string{"do-certificate-near-expiry"}, renderCertificateReissue)
	register("doctl-spaces-manual",
		[]string{"do-spaces-public-acl"}, renderSpacesACLManual)
	register("doctl-app-alerts",
		[]string{"do-app-no-alerts"}, renderAppAlertsManual)
}

func renderDBFirewall(f core.Finding) (remediate.Snippet, error) {
	id := f.Resource.Name
	if id == "" {
		id = "DB_CLUSTER_ID"
	}
	cmd := fmt.Sprintf(
		`# List current firewall rules.
doctl databases firewalls list %s

# Replace 0.0.0.0/0 with specific droplet tags or VPC sources.
# doctl databases firewalls replace %s --rule "tag:app-droplets" --rule "ip_addr:10.0.0.0/8"`,
		render.ShellQuote(id), render.ShellQuote(id))
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: cmd,
		VerifyCmd: fmt.Sprintf("doctl databases firewalls list %s --format Type,Value", render.ShellQuote(id)),
		Notes:     "Replacement requires knowing which sources legitimately need access — inspect before replacing. Prefer tag:droplet-tag or droplet IDs over IP ranges.",
	}, nil
}

func renderDBMaintenance(f core.Finding) (remediate.Snippet, error) {
	id := f.Resource.Name
	if id == "" {
		id = "DB_CLUSTER_ID"
	}
	cmd := fmt.Sprintf(
		"doctl databases maintenance-window update %s --day sunday --hour 04:00:00",
		render.ShellQuote(id))
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: cmd,
		VerifyCmd: fmt.Sprintf("doctl databases get %s --format MaintenanceWindow", render.ShellQuote(id)),
	}, nil
}

func renderFirewallListInspect(f core.Finding) (remediate.Snippet, error) {
	id := f.Resource.Name
	if id == "" {
		id = "FIREWALL_ID"
	}
	cmd := fmt.Sprintf(
		`# Inspect inbound rules — look for 0.0.0.0/0 sources or any-port.
doctl compute firewall get %s

# Remove a wide rule (replace TCP:443 + 0.0.0.0/0 with actual values from the inspect).
# doctl compute firewall remove-rules %s --inbound-rules "protocol:tcp,ports:443,address:0.0.0.0/0"
# doctl compute firewall add-rules    %s --inbound-rules "protocol:tcp,ports:443,address:YOUR.CIDR/32"`,
		render.ShellQuote(id), render.ShellQuote(id), render.ShellQuote(id))
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: cmd,
		Notes: "Tighten ingress to specific droplet tags or VPC ranges. Public web traffic should go via a Load Balancer, not direct droplet ingress.",
	}, nil
}

func renderDropletInspect(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = "DROPLET_NAME"
	}
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false,
		Content: fmt.Sprintf(
			"# Droplet VPC attachment can't be changed in-place; rebuild required.\n"+
				"doctl compute droplet get %s --format ID,Name,VPCUUID\n"+
				"# Plan a recreate into the VPC:\n"+
				"# doctl compute droplet create %s-new --image $IMAGE --size $SIZE --region $REGION --vpc-uuid $VPC_UUID --ssh-keys $SSH_KEYS\n"+
				"# Migrate state (snapshots, attached volumes), cut traffic, delete the old one.",
			render.ShellQuote(name), render.ShellQuote(name)),
		Notes: "DigitalOcean does not support in-place VPC reassignment for existing droplets. Plan a rolling rebuild.",
	}, nil
}

func renderCertificateReissue(f core.Finding) (remediate.Snippet, error) {
	id := f.Resource.Name
	if id == "" {
		id = "CERT_ID"
	}
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false,
		Content: fmt.Sprintf(
			"# Reissue (Let's Encrypt — DO-managed cert).\n"+
				"doctl compute certificate list\n"+
				"# doctl compute certificate delete %s\n"+
				"# doctl compute certificate create --name $NAME --type lets_encrypt --dns-names $DOMAINS",
			render.ShellQuote(id)),
		Notes: "DO-managed Let's Encrypt certs renew automatically; if you're seeing near-expiry, the auto-renewal is broken (DNS validation failing, ownership lost). For uploaded custom certs, generate a new one and re-upload before the old expires.",
	}, nil
}

func renderSpacesACLManual(f core.Finding) (remediate.Snippet, error) {
	bucket := f.Resource.Name
	region := f.Resource.Region
	if region == "" {
		region = "nyc3"
	}
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true,
		Content: fmt.Sprintf(
			"# doctl doesn't manage Spaces ACLs directly; use the s3 CLI against the Spaces endpoint.\n"+
				"aws s3api put-bucket-acl --bucket %s --acl private \\\n"+
				"  --endpoint-url https://%s.digitaloceanspaces.com",
			render.ShellQuote(bucket), region),
		VerifyCmd: fmt.Sprintf(
			"aws s3api get-bucket-acl --bucket %s --endpoint-url https://%s.digitaloceanspaces.com",
			render.ShellQuote(bucket), region),
		Notes: "Spaces is S3-API compatible. Requires DO API key configured as the AWS profile + the Spaces endpoint. Removes public-read on the bucket.",
	}, nil
}

func renderAppAlertsManual(f core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false,
		Content: fmt.Sprintf(
			"# App Platform alerts are configured via the API or control panel (no doctl subcommand at the time of writing).\n"+
				"# 1) Get app ID: doctl apps list --format ID,Spec.Name\n"+
				"# 2) PATCH the app spec with alerts on CPU + Restart + Domain via:\n"+
				"#    https://docs.digitalocean.com/reference/api/api-reference/#operation/apps_create_alert\n"+
				"# Finding %q.",
			f.CheckID),
		Notes: "Recommended alerts: CPU > 80%% for 5 min, RestartCount > 0, DeploymentFailed, DomainFailed.",
	}, nil
}
