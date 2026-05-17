package bash

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 7 — bash strategies for networking depth.

func init() {
	register("bash-do-fw-inbound-duplicates",
		[]string{"do-fw-inbound-rules-duplicated"}, renderBashFWInboundDupes)
	register("bash-do-fw-outbound-unrestricted",
		[]string{"do-fw-outbound-unrestricted"}, renderBashFWOutbound)
	register("bash-do-fw-icmp-from-any",
		[]string{"do-fw-icmp-from-any"}, renderBashFWICMP)
	register("bash-do-fw-empty-tag-source",
		[]string{"do-fw-empty-tag-source"}, renderBashFWEmptyTag)
	register("bash-do-vpc-peering-cross-region",
		[]string{"do-vpc-peering-cross-region"}, renderBashVPCPeering)
	register("bash-do-reserved-ip-no-region",
		[]string{"do-reserved-ip-no-region"}, renderBashReservedIP)
	register("bash-do-lb-tls-passthrough",
		[]string{"do-lb-tls-passthrough-misconfigured"}, renderBashLBTLSPassthrough)
	register("bash-do-lb-sticky-cookie-httponly",
		[]string{"do-lb-sticky-cookie-no-httponly"}, renderBashLBStickyCookie)
	register("bash-do-lb-proxy-protocol",
		[]string{"do-lb-proxy-protocol-mismatch"}, renderBashLBProxyProtocol)
	register("bash-do-lb-ssl-cipher-floor",
		[]string{"do-lb-ssl-cipher-floor"}, renderBashLBSSLCipher)
}

func bashResName(f core.Finding, fallback string) string {
	if f.Resource.Name != "" {
		return f.Resource.Name
	}
	return fallback
}

func renderBashFWInboundDupes(f core.Finding) (remediate.Snippet, error) {
	id := bashResName(f, "FW_ID")
	body := fmt.Sprintf(`fw=%q
# Dump rules + show duplicate sigs.
doctl compute firewall get "$fw" -o json \
  | jq -r '.[0].inbound_rules[] | "\(.protocol)|\(.ports)|\(.sources.addresses // [] | join(","))|\(.sources.tags // [] | join(","))"' \
  | sort | uniq -c | awk '$1 > 1 {print}'`, id)
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
		Notes: "Manual remove-rules per dup. doctl doesn't have a dedup primitive.",
	}, nil
}

func renderBashFWOutbound(f core.Finding) (remediate.Snippet, error) {
	id := bashResName(f, "FW_ID")
	body := fmt.Sprintf(`fw=%q
doctl compute firewall add-rules "$fw" \
  --outbound-rules "protocol:tcp,ports:443,address:0.0.0.0/0" \
  --outbound-rules "protocol:udp,ports:53,address:1.1.1.1" \
  --outbound-rules "protocol:tcp,ports:5432,address:10.10.0.0/16"`, id)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
	}, nil
}

func renderBashFWICMP(f core.Finding) (remediate.Snippet, error) {
	id := bashResName(f, "FW_ID")
	body := fmt.Sprintf(`fw=%q
doctl compute firewall remove-rules "$fw" --inbound-rules "protocol:icmp,address:0.0.0.0/0"
doctl compute firewall add-rules    "$fw" --inbound-rules "protocol:icmp,address:10.0.0.0/8"`, id)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: false, Content: body,
	}, nil
}

func renderBashFWEmptyTag(f core.Finding) (remediate.Snippet, error) {
	id := bashResName(f, "FW_ID")
	body := fmt.Sprintf(`fw=%q
tags="$(doctl compute firewall get "$fw" -o json | jq -r '.[0].inbound_rules[].sources.tags // [] | .[]' | sort -u)"
for t in $tags; do
  count="$(doctl compute droplet list --tag-name "$t" --format ID --no-header | wc -l | tr -d ' ')"
  printf '%%s  → %%s droplet(s)\n' "$t" "$count"
done`, id)
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
		Notes: "Any tag with 0 droplets is a stale rule.",
	}, nil
}

func renderBashVPCPeering(f core.Finding) (remediate.Snippet, error) {
	id := bashResName(f, "PEERING_ID")
	body := fmt.Sprintf(`doctl vpcs peerings delete %s --force`, id)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		Notes: "For cross-region connectivity terminate WireGuard / IPsec on a droplet in each VPC.",
	}, nil
}

func renderBashReservedIP(f core.Finding) (remediate.Snippet, error) {
	ip := bashResName(f, "RESERVED_IP")
	body := fmt.Sprintf(`ip=%q
doctl compute reserved-ip delete "$ip" --force
doctl compute reserved-ip create --region nyc3`, ip)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
	}, nil
}

func renderBashLBTLSPassthrough(f core.Finding) (remediate.Snippet, error) {
	id := bashResName(f, "LB_ID")
	body := fmt.Sprintf(`lb=%q
# Pull current spec.
doctl compute load-balancer get "$lb" --format ForwardingRules,TlsPassthrough

# For non-trivial spec mutations, use TF: 'doctl compute load-balancer update'
# replaces the entire spec which is error-prone via shell flags.`, id)
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
	}, nil
}

func renderBashLBStickyCookie(_ core.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"LB sticky-cookie flags",
		"https://docs.digitalocean.com/products/networking/load-balancers/",
		"`curl -sI https://<lb-host>/` to read Set-Cookie flags; move stickiness to app cookie if flags are insufficient")
}

func renderBashLBProxyProtocol(f core.Finding) (remediate.Snippet, error) {
	id := bashResName(f, "LB_ID")
	body := fmt.Sprintf(`doctl compute load-balancer get %s --format EnableProxyProtocol`, id)
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
		Notes: "If true, ensure backend nginx has real_ip_header proxy_protocol + set_real_ip_from <LB CIDR>.",
	}, nil
}

func renderBashLBSSLCipher(_ core.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"LB TLS cipher / protocol audit",
		"https://www.ssllabs.com/ssltest/",
		"Run `testssl.sh <lb-host>` and capture protocol + cipher report")
}
