package digitalocean

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.19 phase 3 — DNS depth: DMARC policy strictness, subdomain
// policy, percentage rollout, aggregate + forensic reporting,
// SPF strict-fail, SPF redirect avoidance, DKIM selector presence,
// CAA iodef contact, and registrar-side DNSSEC verification.
//
// All 10 checks attach findings to the DO managed-DNS zone resource
// (digitalocean.domain). Real-data checks parse the record bodies
// the v0.19 phase 3 collector extension surfaces (spf_records,
// dmarc_records, dkim_selectors, ns_records). The DNSSEC check is
// manual-verify because DigitalOcean does not currently support DS
// records on managed zones — DNSSEC has to be enabled at the
// registrar.

// ----- shared helpers ---------------------------------------------------

func newDomainFinding(check core.Check, domain core.Resource) core.Finding {
	return core.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Resource: domain.Ref(),
		Tags:     check.Tags,
	}
}

// parseDMARC parses a DMARC TXT body into a tag→value map. DMARC tags
// are semicolon-separated key=value pairs after the leading "v=DMARC1;".
// Returns an empty map for malformed input.
func parseDMARC(body string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(body, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:eq]))
		val := strings.TrimSpace(part[eq+1:])
		out[key] = val
	}
	return out
}

// firstDMARC returns the first non-empty DMARC record body for a
// domain, or "" if none.
func firstDMARC(domain core.Resource) string {
	recs, _ := domain.Attributes["dmarc_records"].([]string)
	for _, r := range recs {
		if r != "" {
			return r
		}
	}
	return ""
}

// firstSPF returns the first non-empty SPF record body for a domain.
func firstSPF(domain core.Resource) string {
	recs, _ := domain.Attributes["spf_records"].([]string)
	for _, r := range recs {
		if r != "" {
			return r
		}
	}
	return ""
}

// ----- 1. DMARC policy strict (p= quarantine|reject) --------------------

var CheckDomainDMARCPolicyStrict = core.Check{
	ID:           "do-domain-dmarc-policy-not-strict",
	Title:        "DMARC policy must be quarantine or reject",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "domains",
	ResourceType: docol.DomainType,
	Description: "A DMARC record with 'p=none' is a monitoring posture — " +
		"receivers report failures but do nothing with them. Production " +
		"domains should advance to 'p=quarantine' (mail to junk) or " +
		"'p=reject' (drop) once monitoring shows legitimate senders are " +
		"DKIM/SPF-aligned. SOC2 CC6.7 + ISO A.8.20 + DMARC.org all " +
		"recommend an enforcement policy.",
	Remediation: "Update the _dmarc TXT record. Phase: start with " +
		"'p=quarantine; pct=10', monitor aggregate reports for 2 weeks, " +
		"raise pct in 25% steps. Final state: 'p=reject; pct=100'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7", "CC7.2"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"9.4"},
	},
	Tags:    []string{"domains", "dmarc", "email-auth"},
	Scanner: "domains.DMARCPolicyStrict",
}

func DomainDMARCPolicyStrict(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(docol.DomainType) {
		body := firstDMARC(d)
		if body == "" {
			continue // do-domain-no-dmarc covers absence
		}
		f := newDomainFinding(CheckDomainDMARCPolicyStrict, d)
		tags := parseDMARC(body)
		switch strings.ToLower(tags["p"]) {
		case "quarantine", "reject":
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("domain %q: DMARC p=%s", d.Name, tags["p"])
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("domain %q: DMARC p=%q (not enforced)", d.Name, tags["p"])
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 2. DMARC subdomain policy --------------------------------------

var CheckDomainDMARCSubdomainPolicy = core.Check{
	ID:           "do-domain-dmarc-subdomain-policy",
	Title:        "DMARC sp= (subdomain policy) must be set",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "domains",
	ResourceType: docol.DomainType,
	Description: "Without an explicit 'sp=' tag, subdomains inherit the " +
		"parent's 'p=' — but only when 'sp=' is unset. Some receivers " +
		"interpret missing sp= as 'unenforced'. Set sp= explicitly to " +
		"'quarantine' or 'reject' (typically the same as p=) so " +
		"subdomain spoofing is caught regardless of receiver " +
		"interpretation.",
	Remediation: "Append 'sp=reject;' to the _dmarc TXT record (or " +
		"'sp=quarantine' if you're not at p=reject yet).",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"9.4"},
	},
	Tags:    []string{"domains", "dmarc", "subdomain"},
	Scanner: "domains.DMARCSubdomainPolicy",
}

func DomainDMARCSubdomainPolicy(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(docol.DomainType) {
		body := firstDMARC(d)
		if body == "" {
			continue
		}
		tags := parseDMARC(body)
		f := newDomainFinding(CheckDomainDMARCSubdomainPolicy, d)
		switch strings.ToLower(tags["sp"]) {
		case "quarantine", "reject":
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("domain %q: DMARC sp=%s", d.Name, tags["sp"])
		case "none":
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("domain %q: DMARC sp=none (subdomains unprotected)", d.Name)
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("domain %q: DMARC sp= not set; subdomain policy unspecified", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 3. DMARC pct full -----------------------------------------------

var CheckDomainDMARCPctFull = core.Check{
	ID:           "do-domain-dmarc-pct-not-full",
	Title:        "DMARC pct= should be 100 once monitoring is complete",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "domains",
	ResourceType: docol.DomainType,
	Description: "DMARC 'pct=' controls the percentage of messages " +
		"subjected to the policy. During rollout, operators may stage " +
		"pct=10 → pct=50 → pct=100. A production domain that's been " +
		"on enforcement >30 days should be at pct=100 (or omit pct, " +
		"which defaults to 100). Staying at lower pct indefinitely " +
		"is a half-finished rollout.",
	Remediation: "Raise pct stepwise as monitoring confirms no " +
		"legitimate senders are caught. Target: pct=100 or omit the " +
		"tag entirely.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"9.4"},
	},
	Tags:    []string{"domains", "dmarc", "rollout"},
	Scanner: "domains.DMARCPctFull",
}

func DomainDMARCPctFull(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(docol.DomainType) {
		body := firstDMARC(d)
		if body == "" {
			continue
		}
		tags := parseDMARC(body)
		raw, ok := tags["pct"]
		f := newDomainFinding(CheckDomainDMARCPctFull, d)
		if !ok {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("domain %q: DMARC pct omitted (defaults to 100)", d.Name)
			findings = append(findings, f)
			continue
		}
		pct, err := strconv.Atoi(raw)
		switch {
		case err != nil:
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("domain %q: DMARC pct=%q is not an integer", d.Name, raw)
		case pct == 100:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("domain %q: DMARC pct=100", d.Name)
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("domain %q: DMARC pct=%d (rollout incomplete)", d.Name, pct)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 4. DMARC rua present --------------------------------------------

var CheckDomainDMARCRUAPresent = core.Check{
	ID:           "do-domain-dmarc-no-rua",
	Title:        "DMARC rua= (aggregate reporting) must be configured",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "domains",
	ResourceType: docol.DomainType,
	Description: "Without rua= a domain receives no aggregate DMARC " +
		"reports — every receiver evaluates the policy in silence. " +
		"Aggregate reports are the only feedback loop for catching " +
		"misconfigured senders BEFORE enforcement starts dropping " +
		"legitimate mail.",
	Remediation: "Append 'rua=mailto:dmarc-reports@yourdomain.com' to " +
		"the _dmarc record. Common consumers: dmarcian, Postmark " +
		"DMARC, Valimail, in-house parser into ELK.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"9.4"},
	},
	Tags:    []string{"domains", "dmarc", "reporting"},
	Scanner: "domains.DMARCRUAPresent",
}

func DomainDMARCRUAPresent(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(docol.DomainType) {
		body := firstDMARC(d)
		if body == "" {
			continue
		}
		tags := parseDMARC(body)
		f := newDomainFinding(CheckDomainDMARCRUAPresent, d)
		if rua := strings.TrimSpace(tags["rua"]); rua != "" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("domain %q: DMARC rua=%s", d.Name, rua)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("domain %q: DMARC has no rua= reporting URI", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 5. DMARC ruf present (forensic reports) -------------------------

var CheckDomainDMARCRUFPresent = core.Check{
	ID:           "do-domain-dmarc-no-ruf",
	Title:        "DMARC ruf= (forensic reporting) should be configured",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "domains",
	ResourceType: docol.DomainType,
	Description: "ruf= asks receivers to forward forensic copies of " +
		"failing messages. Coverage is patchy (Gmail does not honor " +
		"ruf), but where it works it provides per-incident detail " +
		"aggregate reports lack. Severity is low — ruf is best-effort, " +
		"not a hard requirement.",
	Remediation: "Append 'ruf=mailto:dmarc-forensics@yourdomain.com' to " +
		"the _dmarc record. Use a dedicated mailbox; forensic reports " +
		"can include PII from message bodies.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"9.4"},
	},
	Tags:    []string{"domains", "dmarc", "reporting", "best-effort"},
	Scanner: "domains.DMARCRUFPresent",
}

func DomainDMARCRUFPresent(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(docol.DomainType) {
		body := firstDMARC(d)
		if body == "" {
			continue
		}
		tags := parseDMARC(body)
		f := newDomainFinding(CheckDomainDMARCRUFPresent, d)
		if ruf := strings.TrimSpace(tags["ruf"]); ruf != "" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("domain %q: DMARC ruf=%s", d.Name, ruf)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("domain %q: DMARC has no ruf= forensic URI", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 6. SPF qualifier strict (-all) ----------------------------------

var CheckDomainSPFStrictAll = core.Check{
	ID:           "do-domain-spf-not-strict-fail",
	Title:        "SPF must end in -all (hard fail), not ~all or ?all",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "domains",
	ResourceType: docol.DomainType,
	Description: "The terminating qualifier in SPF determines what " +
		"happens to messages NOT matched by any prior mechanism. " +
		"'-all' is hard fail (drop); '~all' is soft fail (mark as " +
		"suspicious); '?all' is neutral. Production domains should " +
		"use '-all' once SPF coverage is verified — anything weaker " +
		"undermines downstream DMARC enforcement.",
	Remediation: "Change the trailing qualifier in the root TXT record " +
		"from '~all'/'?all'/'+all' to '-all'. Verify with the DMARC " +
		"aggregate reports first to confirm no legitimate senders " +
		"will be hard-failed.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"9.4"},
	},
	Tags:    []string{"domains", "spf", "email-auth"},
	Scanner: "domains.SPFStrictAll",
}

func DomainSPFStrictAll(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(docol.DomainType) {
		body := firstSPF(d)
		if body == "" {
			continue
		}
		f := newDomainFinding(CheckDomainSPFStrictAll, d)
		lower := strings.ToLower(body)
		switch {
		case strings.HasSuffix(strings.TrimSpace(lower), "-all"):
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("domain %q: SPF ends in -all", d.Name)
		case strings.Contains(lower, "~all"):
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("domain %q: SPF ends in ~all (soft fail)", d.Name)
		case strings.Contains(lower, "?all"):
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("domain %q: SPF ends in ?all (neutral)", d.Name)
		case strings.Contains(lower, "+all"):
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("domain %q: SPF ends in +all (pass-all — open relay)", d.Name)
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("domain %q: SPF has no terminating all qualifier", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 7. SPF no redirect= ---------------------------------------------

var CheckDomainSPFNoRedirect = core.Check{
	ID:           "do-domain-spf-uses-redirect",
	Title:        "SPF should not use redirect= for primary policy",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "domains",
	ResourceType: docol.DomainType,
	Description: "redirect= delegates the entire SPF decision to another " +
		"domain. This silently inherits whatever that domain publishes — " +
		"a change at the redirect target changes your SPF posture " +
		"without your knowledge. Per RFC 7208 §6.1 redirect= is " +
		"discouraged; prefer 'include:<domain>' which adds rules " +
		"without giving up the terminating all qualifier.",
	Remediation: "Replace 'redirect=<other>.com' with " +
		"'include:<other>.com -all'. The include mechanism layers " +
		"the other domain's allowed senders into your policy without " +
		"surrendering control of the terminator.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"9.4"},
	},
	Tags:    []string{"domains", "spf", "best-practice"},
	Scanner: "domains.SPFNoRedirect",
}

func DomainSPFNoRedirect(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(docol.DomainType) {
		body := firstSPF(d)
		if body == "" {
			continue
		}
		f := newDomainFinding(CheckDomainSPFNoRedirect, d)
		if strings.Contains(strings.ToLower(body), "redirect=") {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("domain %q: SPF uses redirect= (prefer include:)", d.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("domain %q: SPF does not use redirect=", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 8. DKIM selector present ----------------------------------------

var CheckDomainDKIMSelectorPresent = core.Check{
	ID:           "do-domain-dkim-no-selector",
	Title:        "DKIM selector record(s) must be present",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "domains",
	ResourceType: docol.DomainType,
	Description: "DKIM signs outgoing mail with a public key published " +
		"at <selector>._domainkey.<domain>. Without at least one DKIM " +
		"selector, DMARC 'pass' relies on SPF alignment alone — and " +
		"any mail forwarded through an intermediary breaks the SPF " +
		"chain. DKIM survives forwarding; SPF generally does not.",
	Remediation: "Issue a key pair (typically RSA-2048) and publish the " +
		"public key as a TXT record at '<selector>._domainkey'. " +
		"Common selectors: 'google' (Google Workspace), 'k1' (Mailgun), " +
		"'pm' (Postmark), '<custom>' if rolling your own MTA. Rotate " +
		"selectors annually with overlapping validity.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"9.4"},
	},
	Tags:    []string{"domains", "dkim", "email-auth"},
	Scanner: "domains.DKIMSelectorPresent",
}

func DomainDKIMSelectorPresent(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(docol.DomainType) {
		hasMX, _ := d.Attributes["has_mx"].(bool)
		if !hasMX {
			continue // no MX = no mail handling at this zone; DKIM optional
		}
		selectors, _ := d.Attributes["dkim_selectors"].([]string)
		f := newDomainFinding(CheckDomainDKIMSelectorPresent, d)
		if len(selectors) > 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("domain %q: %d DKIM selector(s)", d.Name, len(selectors))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("domain %q: MX present but no DKIM selectors found", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 9. CAA iodef contact --------------------------------------------

var CheckDomainCAAIodef = core.Check{
	ID:           "do-domain-caa-no-iodef",
	Title:        "CAA records should declare an iodef= contact",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "domains",
	ResourceType: docol.DomainType,
	Description: "RFC 8659 'iodef' tag in a CAA record gives CAs a " +
		"mailto:/URL to use when they reject an issuance request. " +
		"Without iodef, CA-side rejections (e.g. domain validation " +
		"failures from rogue Let's Encrypt requests) are invisible " +
		"to the operator. The tag adds zero attack surface; missing " +
		"it is hygiene.",
	Remediation: "Add a CAA record: '0 iodef \"mailto:secops@example.com\"' " +
		"alongside the existing 'issue \"letsencrypt.org\"' records.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"7.3"},
	},
	Tags:    []string{"domains", "caa", "tls", "reporting"},
	Scanner: "domains.CAAIodef",
}

func DomainCAAIodef(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(docol.DomainType) {
		caas, _ := d.Attributes["caa_records"].([]string)
		if len(caas) == 0 {
			continue // do-domain-no-caa covers absence
		}
		hasIodef := false
		for _, r := range caas {
			if strings.Contains(strings.ToLower(r), "iodef") {
				hasIodef = true
				break
			}
		}
		f := newDomainFinding(CheckDomainCAAIodef, d)
		if hasIodef {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("domain %q: CAA has iodef contact", d.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("domain %q: CAA has %d records but no iodef= contact", d.Name, len(caas))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 10. DNSSEC via registrar (manual-verify) ------------------------

var CheckDomainDNSSECViaRegistrar = core.Check{
	ID:           "do-domain-dnssec-via-registrar",
	Title:        "DNSSEC must be enabled at the registrar (DO does not manage DS records)",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "domains",
	ResourceType: docol.DomainType,
	Description: "DigitalOcean managed DNS does NOT serve signed zones — " +
		"DS records and zone signing happen at the registrar level. " +
		"This is a hard limitation, not a misconfiguration. SOC2 CC6.7 " +
		"and ISO A.8.20 require DNSSEC where the operating environment " +
		"supports it; for DO this means verifying DS records at the " +
		"registrar AND keeping the chain-of-trust intact when DO's " +
		"nameservers change. This finding records the gap so the " +
		"auditor can capture registrar-side evidence.",
	Remediation: "At the registrar (Namecheap / Gandi / Cloudflare etc.): " +
		"enable DNSSEC for the domain, generate / accept the DS record. " +
		"Verify chain-of-trust via 'dig +dnssec example.com' (must see " +
		"AD flag) or https://dnssec-analyzer.verisignlabs.com. Capture " +
		"a screenshot of the registrar DNSSEC status for the audit pack.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"9.4"},
	},
	Tags:    []string{"domains", "dnssec", "unsupported", "manual-verify"},
	Scanner: "domains.DNSSECViaRegistrar",
}

func DomainDNSSECViaRegistrar(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(docol.DomainType) {
		f := newDomainFinding(CheckDomainDNSSECViaRegistrar, d)
		f.Status = core.StatusError
		f.Message = fmt.Sprintf("domain %q: DO managed DNS does not serve signed zones — verify DS records at registrar (dig +dnssec %s ; check AD flag)",
			d.Name, d.Name)
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckDomainDMARCPolicyStrict, DomainDMARCPolicyStrict)
	core.Register(CheckDomainDMARCSubdomainPolicy, DomainDMARCSubdomainPolicy)
	core.Register(CheckDomainDMARCPctFull, DomainDMARCPctFull)
	core.Register(CheckDomainDMARCRUAPresent, DomainDMARCRUAPresent)
	core.Register(CheckDomainDMARCRUFPresent, DomainDMARCRUFPresent)
	core.Register(CheckDomainSPFStrictAll, DomainSPFStrictAll)
	core.Register(CheckDomainSPFNoRedirect, DomainSPFNoRedirect)
	core.Register(CheckDomainDKIMSelectorPresent, DomainDKIMSelectorPresent)
	core.Register(CheckDomainCAAIodef, DomainCAAIodef)
	core.Register(CheckDomainDNSSECViaRegistrar, DomainDNSSECViaRegistrar)
}
