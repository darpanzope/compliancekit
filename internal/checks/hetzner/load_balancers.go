package hetzner

import (
	"context"
	"fmt"

	hetznercol "github.com/darpanzope/compliancekit/internal/collectors/hetzner"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func servicesOf(lb compliancekit.Resource) []map[string]any {
	s, _ := lb.Attributes["services"].([]map[string]any)
	return s
}

// CheckLBHTTPSListener requires a Hetzner LB serve at least one
// HTTPS service. An LB without an HTTPS listener serves traffic
// in plaintext — almost always a misconfiguration.
var CheckLBHTTPSListener = compliancekit.Check{
	ID:           "hetzner-lb-no-https-listener",
	Title:        "Hetzner load balancers should serve at least one HTTPS listener",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "hetzner",
	Service:      "load_balancers",
	ResourceType: hetznercol.LoadBalancerType,
	Description: "A Hetzner Cloud Load Balancer without an HTTPS service " +
		"serves every request in cleartext to any on-path observer. " +
		"At minimum, a public LB should have an `https` service with " +
		"at least one Certificate attached.",
	Remediation: "Add an HTTPS service via the Cloud Console or " +
		"`hcloud load-balancer add-service <name> --protocol https " +
		"--listen-port 443 --certificates <cert-id>`. Hetzner managed " +
		"certs are free via the Cloud Console > Certificates page.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"lb", "tls", "encryption-in-transit"},
	Scanner: "lb.HTTPSListener",
}

func LBHTTPSListener(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, lb := range g.ByType(hetznercol.LoadBalancerType) {
		f := compliancekit.Finding{
			CheckID:  CheckLBHTTPSListener.ID,
			Severity: CheckLBHTTPSListener.Severity,
			Resource: lb.Ref(),
			Tags:     CheckLBHTTPSListener.Tags,
		}
		hasHTTPS := false
		for _, s := range servicesOf(lb) {
			if asString(s["protocol"]) == "https" {
				hasHTTPS = true
				break
			}
		}
		if hasHTTPS {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("lb %q: https listener present", lb.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("lb %q: no https service configured", lb.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckLBHTTPRedirect requires that any HTTP service on a Hetzner
// LB is configured to redirect to HTTPS. Hetzner exposes
// `redirect_http: bool` on the HTTP sub-config; without it, a
// client request to the http listener gets served back in clear.
var CheckLBHTTPRedirect = compliancekit.Check{
	ID:           "hetzner-lb-http-not-redirected",
	Title:        "Hetzner LB HTTP services must redirect to HTTPS",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "hetzner",
	Service:      "load_balancers",
	ResourceType: hetznercol.LoadBalancerType,
	Description: "A Hetzner LB with an HTTP service that does not set " +
		"redirect_http=true accepts cleartext requests and serves the " +
		"response back in cleartext. Modern hardening pattern is to " +
		"accept HTTP only to 301-redirect to HTTPS; never to actually " +
		"serve content over HTTP.",
	Remediation: "Set redirect_http on the http service: 'hcloud " +
		"load-balancer update-service <lb> --listen-port 80 " +
		"--http-redirect-http=true'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"lb", "tls", "encryption-in-transit"},
	Scanner: "lb.HTTPRedirect",
}

func LBHTTPRedirect(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, lb := range g.ByType(hetznercol.LoadBalancerType) {
		f := compliancekit.Finding{
			CheckID:  CheckLBHTTPRedirect.ID,
			Severity: CheckLBHTTPRedirect.Severity,
			Resource: lb.Ref(),
			Tags:     CheckLBHTTPRedirect.Tags,
		}
		// Find the http service (if any) and check its redirect.
		var httpService map[string]any
		for _, s := range servicesOf(lb) {
			if asString(s["protocol"]) == "http" {
				httpService = s
				break
			}
		}
		if httpService == nil {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("lb %q: no http listener", lb.Name)
			findings = append(findings, f)
			continue
		}
		redirect, _ := httpService["redirect_http"].(bool)
		if redirect {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("lb %q: http -> https redirect enabled", lb.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("lb %q: http listener does NOT redirect to https", lb.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckLBHTTPSListener, LBHTTPSListener)
	compliancekit.Register(CheckLBHTTPRedirect, LBHTTPRedirect)
}
