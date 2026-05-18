package terraform

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.19 phase 7 — Terraform strategies for the 10 networking-depth
// checks (firewall dedup + ICMP + outbound, VPC peering, reserved IP,
// LB TLS + cookie + proxy-protocol + cipher).

func init() {
	register("tf-do-fw-inbound-duplicates",
		[]string{"do-fw-inbound-rules-duplicated"}, renderTFFWInboundDupes)
	register("tf-do-fw-outbound-unrestricted",
		[]string{"do-fw-outbound-unrestricted"}, renderTFFWOutbound)
	register("tf-do-fw-icmp-from-any",
		[]string{"do-fw-icmp-from-any"}, renderTFFWICMP)
	register("tf-do-fw-empty-tag-source",
		[]string{"do-fw-empty-tag-source"}, renderTFFWEmptyTag)
	register("tf-do-vpc-peering-cross-region",
		[]string{"do-vpc-peering-cross-region"}, renderTFVPCPeering)
	register("tf-do-reserved-ip-no-region",
		[]string{"do-reserved-ip-no-region"}, renderTFReservedIP)
	register("tf-do-lb-tls-passthrough",
		[]string{"do-lb-tls-passthrough-misconfigured"}, renderTFLBTLSPassthrough)
	register("tf-do-lb-sticky-cookie-httponly",
		[]string{"do-lb-sticky-cookie-no-httponly"}, renderTFLBStickyCookie)
	register("tf-do-lb-proxy-protocol",
		[]string{"do-lb-proxy-protocol-mismatch"}, renderTFLBProxyProtocol)
	register("tf-do-lb-ssl-cipher-floor",
		[]string{"do-lb-ssl-cipher-floor"}, renderTFLBSSLCipher)
}

func renderTFFWInboundDupes(f compliancekit.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "FIREWALL")
	body := fmt.Sprintf(`# De-duplicate the firewall's inbound_rule blocks. Terraform doesn't
# merge identical inline blocks; pull current state with 'terraform
# state show' + manually trim duplicates from the .tf source.

resource "digitalocean_firewall" %q {
  name = %q
  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0"]
  }
  # ... drop dup blocks ...
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf("doctl compute firewall get %s --format InboundRules", name),
	}, nil
}

func renderTFFWOutbound(f compliancekit.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "FIREWALL")
	body := fmt.Sprintf(`resource "digitalocean_firewall" %q {
  name = %q
  # ... existing inbound_rule blocks ...
  outbound_rule {
    protocol              = "tcp"
    port_range            = "443"
    destination_addresses = ["0.0.0.0/0"]
  }
  outbound_rule {
    protocol              = "udp"
    port_range            = "53"
    destination_addresses = ["1.1.1.1/32", "8.8.8.8/32"]
  }
  outbound_rule {
    protocol              = "tcp"
    port_range            = "5432"
    destination_addresses = ["10.10.0.0/16"]   # private DB subnet
  }
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Adjust destinations to your workload. Anything not enumerated is dropped.",
	}, nil
}

func renderTFFWICMP(f compliancekit.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "FIREWALL")
	body := fmt.Sprintf(`resource "digitalocean_firewall" %q {
  name = %q
  # Replace any 0.0.0.0/0 ICMP rule with a tight monitoring CIDR:
  inbound_rule {
    protocol         = "icmp"
    source_addresses = ["10.0.0.0/8"]   # internal monitoring
  }
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
	}, nil
}

func renderTFFWEmptyTag(_ compliancekit.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"firewall tag-source resolution is a runtime concept; TF can't verify droplet-count under a tag",
		"https://cloud.digitalocean.com/networking/firewalls",
		"Run `doctl compute droplet list --tag-name <tag>` per tag")
}

func renderTFVPCPeering(_ compliancekit.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"DO does not support cross-region VPC peering; the existing peering should be deleted",
		"https://cloud.digitalocean.com/networking/vpc",
		"`doctl vpcs peerings delete <id>`; use a VPN tunnel for cross-region connectivity")
}

func renderTFReservedIP(f compliancekit.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "RESERVED_IP")
	body := fmt.Sprintf(`resource "digitalocean_reserved_ip" %q {
  region     = "nyc3"
  droplet_id = digitalocean_droplet.web.id
}
`, tfIdent(name))
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Recreate with explicit region; reserved IPs are region-pinned.",
	}, nil
}

func renderTFLBTLSPassthrough(f compliancekit.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "LB")
	body := fmt.Sprintf(`resource "digitalocean_loadbalancer" %q {
  name   = %q
  region = "nyc3"

  # Option A: terminate TLS at the LB (default + recommended).
  forwarding_rule {
    entry_port       = 443
    entry_protocol   = "https"
    target_port      = 80
    target_protocol  = "http"
    certificate_name = digitalocean_certificate.app.name
  }

  # Option B: passthrough — backend MUST speak TLS on the entry port.
  # forwarding_rule {
  #   entry_port       = 443
  #   entry_protocol   = "https"
  #   target_port      = 443
  #   target_protocol  = "https"
  #   tls_passthrough  = true
  # }
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Pick A or B based on backend capabilities. Most app stacks pick A — easier cert management.",
	}, nil
}

func renderTFLBStickyCookie(_ compliancekit.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"DO LB sticky-cookie flags are not configurable; verify via curl or move stickiness to the app",
		"https://docs.digitalocean.com/products/networking/load-balancers/",
		"Terminate stickiness at the app layer with cookies under your control")
}

func renderTFLBProxyProtocol(f compliancekit.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "LB")
	body := fmt.Sprintf(`resource "digitalocean_loadbalancer" %q {
  name           = %q
  region         = "nyc3"
  enable_proxy_protocol = true   # backend must decode (nginx: real_ip_header proxy_protocol)
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Backend nginx config: `real_ip_header proxy_protocol; set_real_ip_from <LB CIDR>;` in the server block.",
	}, nil
}

func renderTFLBSSLCipher(_ compliancekit.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"DO LB cipher/protocol selection is platform-managed",
		"https://www.ssllabs.com/ssltest/",
		"Run testssl.sh / SSL Labs against the LB host and capture the report")
}

// v0.19 phase 9 — legacy backfill for v0.9-vintage networking checks
// (firewalls, load balancers, VPCs, reserved IPs).
var legacyNetworkTFEntries = map[string]legacyTFEntry{
	"do-firewall-any-port-from-any": {risk: remediate.RiskReview,
		content: "# Drop wildcard rule from the firewall:\nresource \"digitalocean_firewall\" \"web\" {\n  inbound_rule { protocol = \"tcp\"; port_range = \"443\"; source_addresses = [\"0.0.0.0/0\"] }\n}\n"},
	"do-firewall-broad-port-range": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_firewall\" \"web\" {\n  inbound_rule { protocol = \"tcp\"; port_range = \"80\";  source_addresses = [\"0.0.0.0/0\"] }\n  inbound_rule { protocol = \"tcp\"; port_range = \"443\"; source_addresses = [\"0.0.0.0/0\"] }\n}\n"},
	"do-firewall-orphan": {risk: remediate.RiskReview,
		content: "# Remove the resource block + `terraform apply`."},
	"do-firewall-outbound-any-to-any": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_firewall\" \"web\" {\n  outbound_rule { protocol = \"tcp\"; port_range = \"443\"; destination_addresses = [\"0.0.0.0/0\"] }\n  outbound_rule { protocol = \"udp\"; port_range = \"53\";  destination_addresses = [\"1.1.1.1/32\", \"8.8.8.8/32\"] }\n}\n"},
	"do-firewall-rdp-from-any": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_firewall\" \"web\" {\n  inbound_rule { protocol = \"tcp\"; port_range = \"3389\"; source_addresses = [\"10.0.0.0/8\"] }\n}\n"},
	"do-firewall-ssh-from-any": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_firewall\" \"web\" {\n  inbound_rule { protocol = \"tcp\"; port_range = \"22\"; source_tags = [\"bastion\"] }\n}\n"},
	"do-lb-health-check-cleartext": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_loadbalancer\" \"web\" {\n  healthcheck { protocol = \"https\"; port = 443; path = \"/healthz\" }\n}\n"},
	"do-lb-no-https-listener": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_loadbalancer\" \"web\" {\n  forwarding_rule {\n    entry_port = 443; entry_protocol = \"https\"\n    target_port = 80; target_protocol = \"http\"\n    certificate_name = digitalocean_certificate.app.name\n  }\n}\n"},
	"do-lb-no-vpc": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_loadbalancer\" \"web\" {\n  vpc_uuid = digitalocean_vpc.prod.id\n}\n"},
	"do-lb-orphan": {risk: remediate.RiskReview,
		content: "# Remove the resource block + `terraform apply`."},
	"do-lb-redirect-http-to-https": {risk: remediate.RiskSafe,
		content: "resource \"digitalocean_loadbalancer\" \"web\" {\n  redirect_http_to_https = true\n}\n"},
	"do-reserved-ip-no-project": {risk: remediate.RiskSafe,
		content: "resource \"digitalocean_project_resources\" \"prod\" {\n  project   = digitalocean_project.prod.id\n  resources = [\"do:reserved_ip:${digitalocean_reserved_ip.failover.ip_address}\"]\n}\n"},
	"do-reserved-ip-orphan": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_reserved_ip\" \"failover\" {\n  droplet_id = digitalocean_droplet.web.id\n  region     = \"nyc3\"\n}\n"},
	"do-vpc-default-not-in-use": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_vpc\" \"prod\" {\n  name     = \"prod\"\n  region   = \"nyc3\"\n  ip_range = \"10.20.0.0/16\"\n}\n# Migrate workloads off the default VPC."},
	"do-vpc-orphan": {risk: remediate.RiskReview,
		content: "# Drop the resource + apply. DO won't delete a VPC with attached resources; move workloads first."},
	"do-vpc-peering-not-active": {risk: remediate.RiskManual,
		content: "# Peering activation is interactive; inspect via `doctl vpcs peerings get PEERING_ID`."},
}

func init() { registerLegacyTF(legacyNetworkTFEntries) }
