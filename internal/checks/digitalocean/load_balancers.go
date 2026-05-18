package digitalocean

import (
	"context"
	"fmt"
	"strings"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// fwdRulesOf returns the forwarding-rules slice extracted from
// a load balancer resource. Returns an empty slice when missing
// or the wrong type.
func fwdRulesOf(lb compliancekit.Resource) []map[string]any {
	rules, _ := lb.Attributes["forwarding_rules"].([]map[string]any)
	return rules
}

// CheckLBRedirectHTTPToHTTPS requires the load balancer redirect
// http -> https when it terminates http on port 80.
var CheckLBRedirectHTTPToHTTPS = compliancekit.Check{
	ID:           "do-lb-redirect-http-to-https",
	Title:        "Load balancers serving HTTP must redirect to HTTPS",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "load_balancers",
	ResourceType: docol.LoadBalancerType,
	Description: "A load balancer that accepts cleartext HTTP on port 80 " +
		"and does not redirect to HTTPS sends every request, including " +
		"every auth cookie + bearer token, over the wire in plaintext " +
		"to any on-path observer. The redirect_http_to_https flag " +
		"makes the LB issue a 301 from port 80 to the equivalent " +
		"https URL.",
	Remediation: "Enable the redirect via the LB Edit screen, " +
		"'doctl compute load-balancer update <id> " +
		"--redirect-http-to-https', or set " +
		"redirect_http_to_https = true on the Terraform " +
		"digitalocean_loadbalancer resource.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7", "CC6.1"},
		"iso27001": {"A.8.20", "A.8.24"},
		"cis-v8":   {"3.10", "12.6"},
	},
	Tags:    []string{"lb", "encryption-in-transit", "tls"},
	Scanner: "lb.RedirectHTTPToHTTPS",
}

func LBRedirectHTTPToHTTPS(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, lb := range g.ByType(docol.LoadBalancerType) {
		f := compliancekit.Finding{
			CheckID:  CheckLBRedirectHTTPToHTTPS.ID,
			Severity: CheckLBRedirectHTTPToHTTPS.Severity,
			Resource: lb.Ref(),
			Tags:     CheckLBRedirectHTTPToHTTPS.Tags,
		}
		hasHTTP := false
		for _, r := range fwdRulesOf(lb) {
			if strings.EqualFold(asString(r["entry_protocol"]), "http") {
				hasHTTP = true
				break
			}
		}
		if !hasHTTP {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("lb %q: no http listener", lb.Name)
			findings = append(findings, f)
			continue
		}
		redirect, _ := lb.Attributes["redirect_http_to_https"].(bool)
		if redirect {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("lb %q: http -> https redirect enabled", lb.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("lb %q: http listener present but no https redirect", lb.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckLBHasHTTPS requires the load balancer terminate at least
// one HTTPS listener. An HTTP-only LB is, in 2026, almost always
// a misconfiguration.
var CheckLBHasHTTPS = compliancekit.Check{
	ID:           "do-lb-no-https-listener",
	Title:        "Load balancers must serve at least one HTTPS listener",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "load_balancers",
	ResourceType: docol.LoadBalancerType,
	Description: "A load balancer with no HTTPS forwarding rule is " +
		"either an internal-only LB on a private VPC (rare) or, far " +
		"more commonly, a public LB that forgot to terminate TLS. " +
		"Either way, the modern baseline is at least one entry on " +
		"port 443 with a certificate.",
	Remediation: "Provision a managed cert + add an https forwarding rule: " +
		"'doctl compute certificate create --type lets_encrypt " +
		"--domains example.com,www.example.com' then attach the " +
		"resulting cert ID to a new https forwarding rule on port 443.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7", "CC6.1"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"lb", "encryption-in-transit", "tls"},
	Scanner: "lb.HasHTTPS",
}

func LBHasHTTPS(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, lb := range g.ByType(docol.LoadBalancerType) {
		f := compliancekit.Finding{
			CheckID:  CheckLBHasHTTPS.ID,
			Severity: CheckLBHasHTTPS.Severity,
			Resource: lb.Ref(),
			Tags:     CheckLBHasHTTPS.Tags,
		}
		hasHTTPS := false
		for _, r := range fwdRulesOf(lb) {
			proto := strings.ToLower(asString(r["entry_protocol"]))
			if proto == "https" || proto == "https2" || proto == "http2" {
				hasHTTPS = true
				break
			}
		}
		if hasHTTPS {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("lb %q: https listener present", lb.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("lb %q: no https listener", lb.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckLBHealthCheckProtocol requires the health check use HTTPS
// (or TCP for non-http LBs). HTTP health checks against an HTTPS
// LB are a common misconfiguration that silently degrades during
// cert rotation.
var CheckLBHealthCheckProtocol = compliancekit.Check{
	ID:           "do-lb-health-check-cleartext",
	Title:        "Load balancer health checks should not use cleartext HTTP",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "load_balancers",
	ResourceType: docol.LoadBalancerType,
	Description: "When the LB terminates HTTPS to its targets, the health " +
		"check should also use HTTPS (or TCP). An HTTP health check " +
		"against an HTTPS-only backend hits a TLS-redirect or 400, " +
		"flapping the LB membership during normal operation and " +
		"masking real outages.",
	Remediation: "Update the health check: 'doctl compute load-balancer " +
		"update <id> --health-check protocol:https,port:443,path:/health'. " +
		"If the backend is plain HTTP behind a TLS-terminating LB, " +
		"http health check on the backend port is correct.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"lb", "healthcheck"},
	Scanner: "lb.HealthCheckProtocol",
}

func LBHealthCheckProtocol(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, lb := range g.ByType(docol.LoadBalancerType) {
		hc, _ := lb.Attributes["health_check"].(map[string]any)
		hcProto := strings.ToLower(asString(hc["protocol"]))

		// If the LB has no HTTPS listener, an HTTP health check is fine.
		hasHTTPSEntry := false
		for _, r := range fwdRulesOf(lb) {
			proto := strings.ToLower(asString(r["entry_protocol"]))
			if proto == "https" || proto == "https2" || proto == "http2" {
				hasHTTPSEntry = true
				break
			}
		}

		f := compliancekit.Finding{
			CheckID:  CheckLBHealthCheckProtocol.ID,
			Severity: CheckLBHealthCheckProtocol.Severity,
			Resource: lb.Ref(),
			Tags:     CheckLBHealthCheckProtocol.Tags,
		}
		switch {
		case !hasHTTPSEntry:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("lb %q: no https listener, healthcheck protocol not constrained", lb.Name)
		case hcProto == "http":
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("lb %q: https listener with http healthcheck (use https or tcp)", lb.Name)
		default:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("lb %q: healthcheck protocol=%q", lb.Name, hcProto)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckLBInVPC requires every LB sit inside a VPC.
var CheckLBInVPC = compliancekit.Check{
	ID:           "do-lb-no-vpc",
	Title:        "Load balancers must belong to a VPC",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "load_balancers",
	ResourceType: docol.LoadBalancerType,
	Description: "Load balancers created before the DO VPC GA may sit " +
		"outside any VPC, exposing the backend droplets via the " +
		"region-wide shared private network. Modern LBs are VPC-bound; " +
		"a missing vpc_uuid is almost certainly a legacy resource.",
	Remediation: "DO does not support changing a load balancer's VPC " +
		"in place. Recreate the LB inside the target VPC and re-point " +
		"DNS at the new floating IP. Use Terraform to make the cutover " +
		"atomic.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"12.2", "12.4"},
	},
	Tags:    []string{"lb", "network", "segmentation"},
	Scanner: "lb.InVPC",
}

func LBInVPC(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, lb := range g.ByType(docol.LoadBalancerType) {
		vpc, _ := lb.Attributes["vpc_uuid"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckLBInVPC.ID,
			Severity: CheckLBInVPC.Severity,
			Resource: lb.Ref(),
			Tags:     CheckLBInVPC.Tags,
		}
		if vpc != "" {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("lb %q: in VPC %s", lb.Name, vpc)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("lb %q: no VPC association", lb.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckLBOrphan flags LBs with no attached droplets AND no droplet
// tag selector. Empty LBs answer 503 to everything; they should
// be deleted or attached.
var CheckLBOrphan = compliancekit.Check{
	ID:           "do-lb-orphan",
	Title:        "Load balancers should have at least one backend",
	Severity:     compliancekit.SeverityLow,
	Provider:     "digitalocean",
	Service:      "load_balancers",
	ResourceType: docol.LoadBalancerType,
	Description: "A load balancer with zero attached droplets and no " +
		"droplet-tag selector responds 503 Service Unavailable to " +
		"every request. It bills as if it were serving, shows up in " +
		"DNS and TLS audit trails, and confuses incident response. " +
		"Either attach backends or delete.",
	Remediation: "Inspect: 'doctl compute load-balancer get <id> --format " +
		"Name,DropletIDs,Tag'. If the LB is legitimately retired, " +
		"'doctl compute load-balancer delete <id>'. Otherwise attach " +
		"the backend droplets or the matching tag.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.4"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"lb", "hygiene"},
	Scanner: "lb.Orphan",
}

func LBOrphan(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, lb := range g.ByType(docol.LoadBalancerType) {
		ids, _ := lb.Attributes["droplet_ids"].([]int)
		tag, _ := lb.Attributes["droplet_tag"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckLBOrphan.ID,
			Severity: CheckLBOrphan.Severity,
			Resource: lb.Ref(),
			Tags:     CheckLBOrphan.Tags,
		}
		if len(ids) == 0 && tag == "" {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("lb %q: no droplets and no tag selector", lb.Name)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("lb %q: %d droplet(s), tag=%q", lb.Name, len(ids), tag)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// asString returns the value if string, "" otherwise. Helper for
// extracting fields from map[string]any attributes the LB
// forwarding-rules slice stores.
func asString(v any) string {
	s, _ := v.(string)
	return s
}

func init() {
	compliancekit.Register(CheckLBRedirectHTTPToHTTPS, LBRedirectHTTPToHTTPS)
	compliancekit.Register(CheckLBHasHTTPS, LBHasHTTPS)
	compliancekit.Register(CheckLBHealthCheckProtocol, LBHealthCheckProtocol)
	compliancekit.Register(CheckLBInVPC, LBInVPC)
	compliancekit.Register(CheckLBOrphan, LBOrphan)
}
