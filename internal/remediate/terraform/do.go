package terraform

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/remediate/render"
)

func init() {
	register("tf-do-db-tls",
		[]string{"do-db-tls-disabled"},
		renderDODatabaseTLS)
	register("tf-do-db-no-vpc",
		[]string{"do-db-no-vpc"},
		renderDODatabaseVPC)
	register("tf-do-db-backups",
		[]string{"do-db-no-maintenance-window"},
		renderDODatabaseMaintenance)
	register("tf-do-spaces-public",
		[]string{"do-spaces-public-acl"},
		renderDOSpacesPrivate)
	register("tf-do-droplet-no-public-ip",
		[]string{"do-droplet-no-vpc", "do-droplet-public-only"},
		renderDODropletVPC)
	register("tf-do-firewall-default-deny",
		[]string{"do-fw-allow-any-source", "do-fw-allow-all-ports"},
		renderDOFirewallTighten)
	register("tf-do-app-no-vpc",
		[]string{"do-app-no-vpc"},
		renderDOAppVPC)
	register("tf-do-domain-no-caa",
		[]string{"do-domain-no-caa"},
		renderDODomainCAA)
}

func renderDODatabaseTLS(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "digitalocean_database_cluster", tfIdent(name))
	b.Attr("# NOTE: append the firewall rule and rotate connection strings to use ?ssl=require", "")
	b.Attr("name", name)
	b.Attr("private_network_uuid", "")
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String() + "\n# Then update every connection string in applications to require TLS:\n#   postgres://user:pass@host:25060/db?sslmode=require\n",
		VerifyCmd:  fmt.Sprintf("doctl databases connection %s --format URI", render.ShellQuote(name)),
		Notes:      "DigitalOcean Managed Databases support TLS out of the box; the finding fires when clients are using non-TLS connection strings. The fix is on the application side — flip every client to sslmode=require / sslMode=REQUIRED depending on the driver.",
		Refs: []string{
			"https://docs.digitalocean.com/products/databases/postgresql/how-to/secure/",
		},
	}, nil
}

func renderDODatabaseVPC(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "digitalocean_database_cluster", tfIdent(name))
	b.Attr("# NOTE: attach the database to a VPC", "")
	b.Attr("name", name)
	b.RawAttr("private_network_uuid", "digitalocean_vpc.private.id")
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("doctl databases get %s --format PrivateNetworkUUID", render.ShellQuote(name)),
		Notes:      "Requires a separately-defined digitalocean_vpc. Database migration to a VPC requires a maintenance window — DO rebuilds the cluster into the VPC and connection strings change.",
		Refs: []string{
			"https://docs.digitalocean.com/products/databases/postgresql/how-to/connect-with-private-network/",
		},
	}, nil
}

func renderDODatabaseMaintenance(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "digitalocean_database_cluster", tfIdent(name))
	b.Attr("# NOTE: pin a maintenance window on existing digitalocean_database_cluster", "")
	b.Attr("name", name)
	mw := b.SubBlock("maintenance_window")
	mw.Attr("day", "sunday")
	mw.Attr("hour", "04:00:00")
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    b.String(),
		Notes:      "Pinning a maintenance window means DO applies kernel + engine upgrades during a predictable hour. Default (no window) means upgrades happen any time DO chooses.",
		Refs: []string{
			"https://docs.digitalocean.com/products/databases/postgresql/how-to/upgrade-cluster/",
		},
	}, nil
}

func renderDOSpacesPrivate(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "digitalocean_spaces_bucket", tfIdent(name))
	b.Attr("# NOTE: flip acl from public-read to private", "")
	b.Attr("name", name)
	b.Attr("region", "nyc3")
	b.Attr("acl", "private")
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		Notes:      "Removes public-read on the bucket. Public asset distribution should move to a CDN with signed URLs or a separate explicitly-public bucket — flipping THIS one to private may break legitimate public reads.",
		Refs: []string{
			"https://docs.digitalocean.com/products/spaces/how-to/restrict-access/",
		},
	}, nil
}

func renderDODropletVPC(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "digitalocean_droplet", tfIdent(name))
	b.Attr("# NOTE: attach droplet to a private VPC", "")
	b.Attr("name", name)
	b.RawAttr("vpc_uuid", "digitalocean_vpc.private.id")
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		Notes:      "Migrating an existing droplet to a VPC requires destroying and recreating — DO does not support in-place VPC reassignment. Plan for the IP change.",
		Refs: []string{
			"https://docs.digitalocean.com/products/networking/vpc/",
		},
	}, nil
}

func renderDOFirewallTighten(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "digitalocean_firewall", tfIdent(name))
	b.Attr("# NOTE: replace the 0.0.0.0/0 inbound rule with a tighter source CIDR", "")
	b.Attr("name", name)
	rule := b.SubBlock("inbound_rule")
	rule.Attr("protocol", "tcp")
	rule.Attr("port_range", "443")
	rule.Attr("source_addresses", []string{"YOUR.OFFICE.CIDR/32"})
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		Notes:      "Replace YOUR.OFFICE.CIDR/32 with the actual source you trust. Public web traffic should go to a load balancer, not direct droplet ingress.",
		Refs: []string{
			"https://docs.digitalocean.com/products/networking/firewalls/",
		},
	}, nil
}

func renderDOAppVPC(f core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk:       remediate.RiskManual,
		Idempotent: false,
		Content:    "# Manual remediation required — App Platform VPC attachment is a UI/API setting.\n",
		Notes: fmt.Sprintf(
			"App Platform doesn't expose VPC attachment via the Terraform digitalocean_app resource at the time of writing (provider v2.x). Attach via the DO control panel: App → Settings → Networking → VPC, or via the DO API. Track via POA&M. (Finding %q.)",
			f.CheckID),
		Refs: []string{
			"https://docs.digitalocean.com/products/app-platform/how-to/manage-networking/",
		},
	}, nil
}

func renderDODomainCAA(f core.Finding) (remediate.Snippet, error) {
	domain := f.Resource.Name
	if domain == "" {
		domain = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "digitalocean_record", "caa_letsencrypt_"+tfIdent(domain))
	b.Attr("domain", domain)
	b.Attr("type", "CAA")
	b.Attr("name", "@")
	b.Attr("flags", 0)
	b.Attr("tag", "issue")
	b.Attr("value", "letsencrypt.org")
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("dig +short CAA %s", render.ShellQuote(domain)),
		Notes:      "Adds a CAA record locking certificate issuance to Let's Encrypt. Add additional digitalocean_record resources if you also use other CAs (DigiCert, Sectigo). Without CAA, ANY CA can issue for your domain.",
		Refs: []string{
			"https://letsencrypt.org/docs/caa/",
		},
	}, nil
}
