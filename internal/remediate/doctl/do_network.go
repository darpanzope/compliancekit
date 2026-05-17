package doctl

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 7 — doctl strategies for networking depth.

func init() {
	register("doctl-do-fw-inbound-duplicates",
		[]string{"do-fw-inbound-rules-duplicated"}, renderDoctlFWInboundDupes)
	register("doctl-do-fw-outbound-unrestricted",
		[]string{"do-fw-outbound-unrestricted"}, renderDoctlFWOutbound)
	register("doctl-do-fw-icmp-from-any",
		[]string{"do-fw-icmp-from-any"}, renderDoctlFWICMP)
	register("doctl-do-fw-empty-tag-source",
		[]string{"do-fw-empty-tag-source"}, renderDoctlFWEmptyTag)
	register("doctl-do-vpc-peering-cross-region",
		[]string{"do-vpc-peering-cross-region"}, renderDoctlVPCPeering)
	register("doctl-do-reserved-ip-no-region",
		[]string{"do-reserved-ip-no-region"}, renderDoctlReservedIP)
	register("doctl-do-lb-tls-passthrough",
		[]string{"do-lb-tls-passthrough-misconfigured"}, renderDoctlLBTLSPassthrough)
	register("doctl-do-lb-sticky-cookie-httponly",
		[]string{"do-lb-sticky-cookie-no-httponly"}, renderDoctlLBStickyCookie)
	register("doctl-do-lb-proxy-protocol",
		[]string{"do-lb-proxy-protocol-mismatch"}, renderDoctlLBProxyProtocol)
	register("doctl-do-lb-ssl-cipher-floor",
		[]string{"do-lb-ssl-cipher-floor"}, renderDoctlLBSSLCipher)
}

func doctlResName(f core.Finding, fallback string) string {
	if f.Resource.Name != "" {
		return f.Resource.Name
	}
	return fallback
}

func renderDoctlFWInboundDupes(f core.Finding) (remediate.Snippet, error) {
	id := doctlResName(f, "FW_ID")
	body := fmt.Sprintf(`# Audit + dedupe inbound rules. doctl shows each rule as its own line.
doctl compute firewall get %s --format InboundRules

# Use remove-rules then add-rules to surgically remove a duplicate:
# doctl compute firewall remove-rules %s --inbound-rules "protocol:tcp,ports:443,address:0.0.0.0/0"
# doctl compute firewall add-rules    %s --inbound-rules "protocol:tcp,ports:443,address:0.0.0.0/0"`, id, id, id)
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
	}, nil
}

func renderDoctlFWOutbound(f core.Finding) (remediate.Snippet, error) {
	id := doctlResName(f, "FW_ID")
	body := fmt.Sprintf(`doctl compute firewall add-rules %s \
  --outbound-rules "protocol:tcp,ports:443,address:0.0.0.0/0" \
  --outbound-rules "protocol:udp,ports:53,address:1.1.1.1" \
  --outbound-rules "protocol:tcp,ports:5432,address:10.10.0.0/16"`, id)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		Notes: "Add the explicit allow set; anything else drops once outbound rules exist.",
	}, nil
}

func renderDoctlFWICMP(f core.Finding) (remediate.Snippet, error) {
	id := doctlResName(f, "FW_ID")
	body := fmt.Sprintf(`# Remove the wide rule + add a tight one.
doctl compute firewall remove-rules %s --inbound-rules "protocol:icmp,address:0.0.0.0/0"
doctl compute firewall add-rules    %s --inbound-rules "protocol:icmp,address:10.0.0.0/8"`, id, id)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: false, Content: body,
	}, nil
}

func renderDoctlFWEmptyTag(f core.Finding) (remediate.Snippet, error) {
	id := doctlResName(f, "FW_ID")
	body := fmt.Sprintf(`# 1. List rules + their tag sources.
doctl compute firewall get %s --format InboundRules

# 2. For each 'tag:X' source, confirm at least one droplet matches:
# doctl compute droplet list --tag-name X --format ID,Name,Tags`, id)
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
	}, nil
}

func renderDoctlVPCPeering(f core.Finding) (remediate.Snippet, error) {
	id := doctlResName(f, "PEERING_ID")
	body := fmt.Sprintf(`# Cross-region peering is unsupported; delete the record.
doctl vpcs peerings delete %s --force

# For real cross-region connectivity, terminate WireGuard / OpenVPN on droplets in each VPC.`, id)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
	}, nil
}

func renderDoctlReservedIP(f core.Finding) (remediate.Snippet, error) {
	ip := doctlResName(f, "RESERVED_IP")
	body := fmt.Sprintf(`# Recreate the reserved IP with an explicit region.
doctl compute reserved-ip delete %s --force
doctl compute reserved-ip create --region nyc3`, ip)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
	}, nil
}

func renderDoctlLBTLSPassthrough(f core.Finding) (remediate.Snippet, error) {
	id := doctlResName(f, "LB_ID")
	body := fmt.Sprintf(`# Inspect current forwarding rules.
doctl compute load-balancer get %s --format ForwardingRules

# Update the LB to terminate TLS at the edge:
# (use the full --forwarding-rules flag with comma-separated entries — see doctl docs)`, id)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		Notes: "doctl LB update is verbose; for any non-trivial spec change prefer the TF resource.",
	}, nil
}

func renderDoctlLBStickyCookie(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"LB sticky cookie flags",
		"https://docs.digitalocean.com/products/networking/load-balancers/",
		"`curl -sI https://<lb-host>/` + inspect Set-Cookie flags; if non-compliant, move stickiness to the app layer")
}

func renderDoctlLBProxyProtocol(f core.Finding) (remediate.Snippet, error) {
	id := doctlResName(f, "LB_ID")
	body := fmt.Sprintf(`# Check the LB's proxy_protocol setting.
doctl compute load-balancer get %s --format EnableProxyProtocol

# Verify backend understanding (nginx example):
# server { listen 80 proxy_protocol; real_ip_header proxy_protocol; set_real_ip_from <LB-CIDR>; ... }`, id)
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
	}, nil
}

func renderDoctlLBSSLCipher(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"LB TLS cipher / protocol audit",
		"https://www.ssllabs.com/ssltest/",
		"Run testssl.sh against the LB host; capture protocol + cipher report for the audit pack")
}

// v0.19 phase 9 — legacy backfill for networking checks.
var legacyNetworkDoctlEntries = map[string]legacyDoctlEntry{
	"do-firewall-any-port-from-any":   {risk: remediate.RiskReview, content: "doctl compute firewall remove-rules FW_ID --inbound-rules \"protocol:tcp,ports:all,address:0.0.0.0/0\""},
	"do-firewall-broad-port-range":    {risk: remediate.RiskManual, content: "doctl compute firewall get FW_ID --format InboundRules"},
	"do-firewall-orphan":              {risk: remediate.RiskReview, content: "doctl compute firewall delete FW_ID --force"},
	"do-firewall-outbound-any-to-any": {risk: remediate.RiskReview, content: "doctl compute firewall remove-rules FW_ID --outbound-rules \"protocol:tcp,ports:all,address:0.0.0.0/0\""},
	"do-firewall-rdp-from-any":        {risk: remediate.RiskReview, content: "doctl compute firewall remove-rules FW_ID --inbound-rules \"protocol:tcp,ports:3389,address:0.0.0.0/0\""},
	"do-firewall-ssh-from-any":        {risk: remediate.RiskReview, content: "doctl compute firewall remove-rules FW_ID --inbound-rules \"protocol:tcp,ports:22,address:0.0.0.0/0\"\ndoctl compute firewall add-rules    FW_ID --inbound-rules \"protocol:tcp,ports:22,address:YOUR.IP/32\""},
	"do-lb-health-check-cleartext":    {risk: remediate.RiskReview, content: "# Set healthcheck.protocol=https via TF or spec replacement.\ndoctl compute load-balancer get LB_ID"},
	"do-lb-no-https-listener":         {risk: remediate.RiskReview, content: "# Update LB to add HTTPS forwarding rule via TF or spec replacement."},
	"do-lb-no-vpc":                    {risk: remediate.RiskReview, content: "# LB VPC is set at create; recreate in VPC.\ndoctl compute load-balancer create --name new-lb --region nyc3 --vpc-uuid VPC_UUID"},
	"do-lb-orphan":                    {risk: remediate.RiskReview, content: "doctl compute load-balancer delete LB_ID --force"},
	"do-lb-redirect-http-to-https":    {risk: remediate.RiskReview, content: "# Enable redirect_http_to_https via TF (doctl flag surface limited)."},
	"do-reserved-ip-no-project":       {risk: remediate.RiskSafe, content: "doctl projects resources assign PROJECT_ID --resource do:reserved_ip:1.2.3.4"},
	"do-reserved-ip-orphan":           {risk: remediate.RiskReview, content: "doctl compute reserved-ip delete RESERVED_IP --force"},
	"do-vpc-default-not-in-use":       {risk: remediate.RiskReview, content: "doctl vpcs create --name custom-prod --region nyc3 --ip-range 10.20.0.0/16"},
	"do-vpc-orphan":                   {risk: remediate.RiskReview, content: "doctl vpcs delete VPC_UUID --force"},
	"do-vpc-peering-not-active":       {risk: remediate.RiskManual, content: "doctl vpcs peerings get PEERING_ID"},
}

func init() { registerLegacyDoctl(legacyNetworkDoctlEntries) }
