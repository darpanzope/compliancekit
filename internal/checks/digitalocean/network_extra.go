package digitalocean

import (
	"context"
	"fmt"
	"strings"

	"github.com/digitalocean/godo"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.19 phase 7 — networking depth: firewall rule dedup + ICMP +
// outbound restriction; VPC peering cross-region; reserved-IP region
// hygiene; LB TLS passthrough mismatch; LB cookie/proxy-protocol/
// cipher manual verifications.

func newNetFinding(check core.Check, r core.Resource) core.Finding {
	return core.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Resource: r.Ref(),
		Tags:     check.Tags,
	}
}

func netManualVerify(check core.Check, r core.Resource, control, hint string) core.Finding {
	f := newNetFinding(check, r)
	f.Status = core.StatusError
	f.Message = fmt.Sprintf("%s %q: %s — DO API does not surface this; verify via %s",
		r.Type, r.Name, control, hint)
	return f
}

// ----- 1. duplicate inbound firewall rules ----------------------------

var CheckFWInboundDuplicates = core.Check{
	ID:           "do-fw-inbound-rules-duplicated",
	Title:        "Firewall must not have duplicate inbound rules",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "firewalls",
	ResourceType: docol.FirewallType,
	Description: "Duplicate rules add no security but inflate the rule " +
		"set. DO firewalls cap at 50 rules per firewall — duplicates " +
		"eat headroom. Common cause: scripted rule additions without " +
		"a presence check.",
	Remediation: "Audit + dedupe: `doctl compute firewall get <id>` " +
		"shows the full rule list. Remove duplicates with " +
		"`doctl compute firewall remove-rules`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC8.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"firewalls", "hygiene"},
	Scanner: "firewalls.InboundDuplicates",
}

// ruleSignature collapses a single firewall rule into a comparable
// string key. Matching signatures across two rules == duplicate.
func ruleSignature(r godo.InboundRule) string {
	srcs := []string{}
	if r.Sources != nil {
		srcs = append(srcs, r.Sources.Addresses...)
		srcs = append(srcs, r.Sources.Tags...)
		for _, d := range r.Sources.DropletIDs {
			srcs = append(srcs, fmt.Sprintf("d:%d", d))
		}
	}
	return strings.Join([]string{r.Protocol, r.PortRange, strings.Join(srcs, ",")}, "|")
}

func FWInboundDuplicates(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, fw := range g.ByType(docol.FirewallType) {
		rules, _ := fw.Attributes["inbound_rules"].([]godo.InboundRule)
		seen := map[string]int{}
		for _, r := range rules {
			seen[ruleSignature(r)]++
		}
		dupes := 0
		for _, n := range seen {
			if n > 1 {
				dupes += n - 1
			}
		}
		f := newNetFinding(CheckFWInboundDuplicates, fw)
		if dupes == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("firewall %q: %d unique inbound rules", fw.Name, len(rules))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("firewall %q: %d duplicate inbound rule(s)", fw.Name, dupes)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 2. outbound restrictions ---------------------------------------

var CheckFWOutboundUnrestricted = core.Check{
	ID:           "do-fw-outbound-unrestricted",
	Title:        "Firewalls should restrict outbound traffic",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "firewalls",
	ResourceType: docol.FirewallType,
	Description: "Empty outbound_rules means default-allow-all egress. " +
		"Modern compromise patterns rely on outbound exfiltration; " +
		"restricting egress (allow-list to known sinks) limits blast " +
		"radius. SOC2 CC6.6, ISO A.8.20, CIS 13.4 expect egress " +
		"controls.",
	Remediation: "Define outbound rules in the firewall spec; allow " +
		"only the destinations the workload needs (DB IPs, API " +
		"endpoints, package mirrors). Anything else gets dropped.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"13.4"},
	},
	Tags:    []string{"firewalls", "egress"},
	Scanner: "firewalls.OutboundUnrestricted",
}

func FWOutboundUnrestricted(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, fw := range g.ByType(docol.FirewallType) {
		rules, _ := fw.Attributes["outbound_rules"].([]godo.OutboundRule)
		f := newNetFinding(CheckFWOutboundUnrestricted, fw)
		if len(rules) == 0 {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("firewall %q: no outbound rules (default allow-all)", fw.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("firewall %q: %d outbound rule(s) declared", fw.Name, len(rules))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 3. ICMP from any -----------------------------------------------

var CheckFWICMPFromAny = core.Check{
	ID:           "do-fw-icmp-from-any",
	Title:        "ICMP from 0.0.0.0/0 leaks host enumeration",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "firewalls",
	ResourceType: docol.FirewallType,
	Description: "Allowing ICMP (ping) from the internet lets attackers " +
		"enumerate live droplets at zero cost. Restrict to known " +
		"monitoring sources or block entirely.",
	Remediation: "Remove the wide ICMP rule + replace with a tight one: " +
		"`doctl compute firewall add-rules <id> " +
		"--inbound-rules \"protocol:icmp,address:10.0.0.0/8\"`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"firewalls", "icmp", "enumeration"},
	Scanner: "firewalls.ICMPFromAny",
}

func FWICMPFromAny(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, fw := range g.ByType(docol.FirewallType) {
		rules, _ := fw.Attributes["inbound_rules"].([]godo.InboundRule)
		open := false
		for _, r := range rules {
			if !strings.EqualFold(r.Protocol, "icmp") || r.Sources == nil {
				continue
			}
			for _, a := range r.Sources.Addresses {
				if a == "0.0.0.0/0" || a == "::/0" {
					open = true
					break
				}
			}
			if open {
				break
			}
		}
		f := newNetFinding(CheckFWICMPFromAny, fw)
		if open {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("firewall %q: ICMP allowed from 0.0.0.0/0", fw.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("firewall %q: ICMP restricted", fw.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 4. manual: empty tag sources ----------------------------------

var CheckFWEmptyTagSource = core.Check{
	ID:           "do-fw-empty-tag-source",
	Title:        "Firewall tag sources should resolve to ≥1 droplet",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "firewalls",
	ResourceType: docol.FirewallType,
	Description: "A rule sourcing 'tag:bastion' resolves at runtime to " +
		"all droplets carrying that tag. If 0 droplets do, the rule " +
		"silently allows nothing — usually a typo. godo doesn't " +
		"surface tag resolution at firewall-list time; verify manually.",
	Remediation: "List the rules: `doctl compute firewall get <id>`. For " +
		"each tag source, run `doctl compute droplet list " +
		"--tag-name <tag>` and confirm ≥1 droplet.",
	Frameworks: map[string][]string{
		"soc2":     {"CC8.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"firewalls", "tags", "manual-verify"},
	Scanner: "firewalls.EmptyTagSource",
}

func FWEmptyTagSource(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, fw := range g.ByType(docol.FirewallType) {
		rules, _ := fw.Attributes["inbound_rules"].([]godo.InboundRule)
		hasTagSource := false
		for _, r := range rules {
			if r.Sources != nil && len(r.Sources.Tags) > 0 {
				hasTagSource = true
				break
			}
		}
		if !hasTagSource {
			continue
		}
		findings = append(findings,
			netManualVerify(CheckFWEmptyTagSource, fw,
				"tag sources resolve to ≥1 droplet",
				"`doctl compute droplet list --tag-name <tag>` per tag"))
	}
	return findings, nil
}

// ----- 5. VPC peering cross-region -----------------------------------

var CheckVPCPeeringCrossRegion = core.Check{
	ID:           "do-vpc-peering-cross-region",
	Title:        "VPC peering spans must be intra-region (DO does not support cross-region peering)",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "networking",
	ResourceType: docol.VPCPeeringType,
	Description: "DO does not support VPC peering across regions. Any " +
		"peering registered with VPCs in different regions is a stale " +
		"or impossible config — DO API will reject the bind, but the " +
		"peering record may persist. Validate.",
	Remediation: "Drop the cross-region peering: `doctl vpcs peerings " +
		"delete <id>`. For cross-region connectivity use a VPN tunnel " +
		"between droplets in each VPC.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"12.1"},
	},
	Tags:    []string{"networking", "vpc", "peering"},
	Scanner: "networking.VPCPeeringCrossRegion",
}

func VPCPeeringCrossRegion(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	// Build region index over VPCs.
	regionByVPCID := map[string]string{}
	for _, v := range g.ByType(docol.VPCType) {
		uuid, _ := v.Attributes["uuid"].(string)
		region, _ := v.Attributes["region"].(string)
		if uuid != "" {
			regionByVPCID[uuid] = region
		}
	}
	for _, p := range g.ByType(docol.VPCPeeringType) {
		ids, _ := p.Attributes["vpc_ids"].([]string)
		regions := map[string]struct{}{}
		for _, id := range ids {
			if reg := regionByVPCID[id]; reg != "" {
				regions[reg] = struct{}{}
			}
		}
		f := newNetFinding(CheckVPCPeeringCrossRegion, p)
		if len(regions) > 1 {
			f.Status = core.StatusFail
			rs := make([]string, 0, len(regions))
			for r := range regions {
				rs = append(rs, r)
			}
			f.Message = fmt.Sprintf("vpc peering %q: spans regions %v", p.Name, rs)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("vpc peering %q: intra-region", p.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 6. reserved IP without region --------------------------------

var CheckReservedIPNoRegion = core.Check{
	ID:           "do-reserved-ip-no-region",
	Title:        "Reserved IPs must declare a region",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "networking",
	ResourceType: docol.ReservedIPType,
	Description: "Reserved IPs are region-locked; the API should always " +
		"return a region. A missing region usually indicates a stale " +
		"data-collection error or an in-migration reserved IP. Either " +
		"way: not a valid steady state.",
	Remediation: "Inspect: `doctl compute reserved-ip get <ip>`. If the " +
		"region is genuinely missing, delete + recreate via " +
		"`doctl compute reserved-ip create --region nyc3`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC8.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"networking", "reserved-ip"},
	Scanner: "networking.ReservedIPNoRegion",
}

func ReservedIPNoRegion(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, ip := range g.ByType(docol.ReservedIPType) {
		f := newNetFinding(CheckReservedIPNoRegion, ip)
		if ip.Region == "" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("reserved-ip %q: no region declared", ip.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("reserved-ip %q: region=%s", ip.Name, ip.Region)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 7. LB TLS passthrough with no HTTPS listener -----------------

var CheckLBTLSPassthroughWithoutHTTPS = core.Check{
	ID:           "do-lb-tls-passthrough-misconfigured",
	Title:        "TLS passthrough must pair with an HTTPS-aware backend",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "load_balancers",
	ResourceType: docol.LoadBalancerType,
	Description: "tls_passthrough=true means the LB does not terminate " +
		"TLS — the backend must speak TLS on the entry port. If the " +
		"backend speaks plain HTTP, every connection will fail. " +
		"Symptom: 502 / handshake errors at the LB.",
	Remediation: "Either: (1) flip tls_passthrough=false + add a managed " +
		"cert at the LB, OR (2) configure backend droplets to speak " +
		"TLS on the entry port (typically 443).",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7", "A1.2"},
		"iso27001": {"A.8.20", "A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"load_balancers", "tls", "configuration"},
	Scanner: "load_balancers.TLSPassthroughMisconfigured",
}

func LBTLSPassthroughWithoutHTTPS(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, lb := range g.ByType(docol.LoadBalancerType) {
		rules, _ := lb.Attributes["forwarding_rules"].([]map[string]any)
		anyPassthroughHTTP := false
		for _, r := range rules {
			passthrough, _ := r["tls_passthrough"].(bool)
			entry, _ := r["entry_protocol"].(string)
			target, _ := r["target_protocol"].(string)
			if passthrough && strings.EqualFold(entry, "https") && strings.EqualFold(target, "http") {
				anyPassthroughHTTP = true
				break
			}
		}
		f := newNetFinding(CheckLBTLSPassthroughWithoutHTTPS, lb)
		if anyPassthroughHTTP {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("lb %q: tls_passthrough HTTPS→HTTP rule (backend can't decrypt)", lb.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("lb %q: forwarding rules consistent", lb.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 8. manual: sticky cookie HttpOnly ----------------------------

var CheckLBStickyCookieHTTPOnly = core.Check{
	ID:           "do-lb-sticky-cookie-no-httponly",
	Title:        "Sticky-session cookies must be HTTPOnly",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "load_balancers",
	ResourceType: docol.LoadBalancerType,
	Description: "DO LB sticky sessions issue a cookie back to clients. " +
		"The DO API doesn't surface the cookie's flags (HttpOnly, " +
		"Secure, SameSite) — operators must verify via curl against " +
		"the LB. Per OWASP, the affinity cookie should be HttpOnly + " +
		"Secure + SameSite=Lax.",
	Remediation: "DO LB cookie flags are not configurable; if the " +
		"defaults don't meet your policy, terminate stickiness at the " +
		"application + use a non-LB cookie under your control.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.5"},
		"cis-v8":   {"3.3"},
	},
	Tags:    []string{"load_balancers", "sticky", "manual-verify"},
	Scanner: "load_balancers.StickyCookieHTTPOnly",
}

func LBStickyCookieHTTPOnly(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, lb := range g.ByType(docol.LoadBalancerType) {
		findings = append(findings,
			netManualVerify(CheckLBStickyCookieHTTPOnly, lb,
				"sticky cookie HttpOnly + Secure flags",
				"`curl -sI https://"+lb.Name+"/` → check Set-Cookie flags"))
	}
	return findings, nil
}

// ----- 9. manual: proxy protocol -----------------------------------

var CheckLBProxyProtocol = core.Check{
	ID:           "do-lb-proxy-protocol-mismatch",
	Title:        "PROXY-protocol must match backend support",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "load_balancers",
	ResourceType: docol.LoadBalancerType,
	Description: "When the LB sends PROXY-protocol headers but the " +
		"backend (nginx, etc.) doesn't decode them, every request " +
		"fails parsing. The DO API exposes the LB's proxy_protocol " +
		"setting, but not the backend's — verify alignment manually.",
	Remediation: "If LB has proxy_protocol=true, backend nginx needs " +
		"'real_ip_header proxy_protocol' + 'set_real_ip_from <LB CIDR>'. " +
		"If LB has proxy_protocol=false, backends see the LB's IP — " +
		"X-Forwarded-For carries the client IP.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.15"},
		"cis-v8":   {"8.5"},
	},
	Tags:    []string{"load_balancers", "proxy-protocol", "manual-verify"},
	Scanner: "load_balancers.ProxyProtocol",
}

func LBProxyProtocol(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, lb := range g.ByType(docol.LoadBalancerType) {
		findings = append(findings,
			netManualVerify(CheckLBProxyProtocol, lb,
				"PROXY-protocol alignment between LB + backend",
				"`doctl compute load-balancer get "+lb.Name+"` + backend nginx/HAProxy config"))
	}
	return findings, nil
}

// ----- 10. manual: SSL cipher floor -------------------------------

var CheckLBSSLCipherFloor = core.Check{
	ID:           "do-lb-ssl-cipher-floor",
	Title:        "LB-terminated TLS must drop legacy ciphers",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "load_balancers",
	ResourceType: docol.LoadBalancerType,
	Description: "DO LBs run a managed TLS terminator. Cipher / protocol " +
		"selection is platform-side, not customer-configurable. PCI " +
		"DSS 4.2 + SOC2 CC6.7 expect documented protocol/cipher " +
		"floors. Validate the LB's current capabilities via " +
		"testssl.sh or sslyze and record in the audit pack.",
	Remediation: "Run `testssl.sh https://<lb-host>` and capture the " +
		"protocol + cipher report. If unacceptable ciphers appear " +
		"(SSLv3, RC4, 3DES, NULL, EXPORT), open a DO support ticket. " +
		"Document in the audit pack.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"load_balancers", "tls", "ciphers", "manual-verify"},
	Scanner: "load_balancers.SSLCipherFloor",
}

func LBSSLCipherFloor(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, lb := range g.ByType(docol.LoadBalancerType) {
		findings = append(findings,
			netManualVerify(CheckLBSSLCipherFloor, lb,
				"TLS cipher + protocol floor",
				"`testssl.sh "+lb.Name+"` or https://www.ssllabs.com/ssltest/"))
	}
	return findings, nil
}

func init() {
	core.Register(CheckFWInboundDuplicates, FWInboundDuplicates)
	core.Register(CheckFWOutboundUnrestricted, FWOutboundUnrestricted)
	core.Register(CheckFWICMPFromAny, FWICMPFromAny)
	core.Register(CheckFWEmptyTagSource, FWEmptyTagSource)
	core.Register(CheckVPCPeeringCrossRegion, VPCPeeringCrossRegion)
	core.Register(CheckReservedIPNoRegion, ReservedIPNoRegion)
	core.Register(CheckLBTLSPassthroughWithoutHTTPS, LBTLSPassthroughWithoutHTTPS)
	core.Register(CheckLBStickyCookieHTTPOnly, LBStickyCookieHTTPOnly)
	core.Register(CheckLBProxyProtocol, LBProxyProtocol)
	core.Register(CheckLBSSLCipherFloor, LBSSLCipherFloor)
}
