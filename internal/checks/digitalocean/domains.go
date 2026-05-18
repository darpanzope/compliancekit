package digitalocean

import (
	"context"
	"fmt"
	"strings"
	"time"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

const certExpiryThresholdDays = 30

// CheckDomainCAA requires every managed DNS zone publish a CAA
// record. CAA tells the public CA ecosystem which authorities are
// allowed to issue certificates for the zone, which blocks
// rogue-CA issuance even after a credential leak.
var CheckDomainCAA = compliancekit.Check{
	ID:           "do-domain-no-caa",
	Title:        "Managed domains should publish a CAA record",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "domains",
	ResourceType: docol.DomainType,
	Description: "A CAA (Certification Authority Authorization) record " +
		"declares which public CAs may issue certificates for the " +
		"domain. Without it, any CA in the public trust store can " +
		"issue a cert against a successful HTTP/DNS challenge, which " +
		"a compromised DNS account or an MITM during validation can " +
		"abuse. CAA is the cheapest single mitigation against rogue " +
		"issuance.",
	Remediation: "Publish a CAA record naming your CAs of record. For " +
		"DO Managed Certs (which use Let's Encrypt): 'doctl compute " +
		"domain records create <domain> --record-type CAA " +
		"--record-name @ --record-flags 0 --record-tag issue " +
		"--record-data letsencrypt.org'. Add additional CAs as needed.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"dns", "tls", "ca-hygiene"},
	Scanner: "domains.CAA",
}

func DomainCAA(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, d := range g.ByType(docol.DomainType) {
		has, _ := d.Attributes["has_caa"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckDomainCAA.ID,
			Severity: CheckDomainCAA.Severity,
			Resource: d.Ref(),
			Tags:     CheckDomainCAA.Tags,
		}
		if has {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("domain %q: CAA published", d.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("domain %q: no CAA record", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckDomainSPF flags root-level domains that send email (have an
// MX record) but don't publish an SPF policy. SPF lets receivers
// reject spoofed messages claiming to come from the domain.
var CheckDomainSPF = compliancekit.Check{
	ID:           "do-domain-no-spf",
	Title:        "Mail-sending domains should publish SPF",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "domains",
	ResourceType: docol.DomainType,
	Description: "A domain with an MX record but no SPF (a TXT record " +
		"on the apex starting 'v=spf1') is trivially spoofable -- the " +
		"receiver has no policy to consult and any sender claiming to " +
		"be the domain gets a fair hearing. SPF is the minimum email " +
		"sender-policy a domain can publish; DMARC + DKIM stack on " +
		"top.",
	Remediation: "Add a TXT record on the apex publishing your SPF " +
		"policy. Minimum: 'v=spf1 -all' to declare 'no mail from this " +
		"domain.' If you send mail, list your senders: 'v=spf1 " +
		"include:_spf.mx.example.com -all'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7", "CC6.1"},
		"iso27001": {"A.5.14"},
		"cis-v8":   {"9.1", "9.2"},
	},
	Tags:    []string{"dns", "email-auth", "spoofing"},
	Scanner: "domains.SPF",
}

func DomainSPF(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, d := range g.ByType(docol.DomainType) {
		hasMX, _ := d.Attributes["has_mx"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckDomainSPF.ID,
			Severity: CheckDomainSPF.Severity,
			Resource: d.Ref(),
			Tags:     CheckDomainSPF.Tags,
		}
		if !hasMX {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("domain %q: no MX, SPF not required", d.Name)
			findings = append(findings, f)
			continue
		}
		hasSPF, _ := d.Attributes["has_spf"].(bool)
		if hasSPF {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("domain %q: SPF published", d.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("domain %q: MX present but no SPF policy", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckDomainDMARC requires mail-sending domains publish DMARC.
var CheckDomainDMARC = compliancekit.Check{
	ID:           "do-domain-no-dmarc",
	Title:        "Mail-sending domains should publish DMARC",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "domains",
	ResourceType: docol.DomainType,
	Description: "A domain with MX but no DMARC (TXT record on " +
		"_dmarc.<domain>) tells receivers 'I have no opinion about " +
		"what to do with mail that fails authentication.' Combined " +
		"with SPF + DKIM, DMARC publishes the reject/quarantine " +
		"policy that closes the spoofing loop.",
	Remediation: "Add a TXT record on _dmarc.<domain>. Start in " +
		"reporting-only mode: 'v=DMARC1; p=none; " +
		"rua=mailto:dmarc@example.com'. Once you see clean reports " +
		"for two weeks, harden to 'p=quarantine' then 'p=reject'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.5.14"},
		"cis-v8":   {"9.1", "9.2"},
	},
	Tags:    []string{"dns", "email-auth", "spoofing"},
	Scanner: "domains.DMARC",
}

func DomainDMARC(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, d := range g.ByType(docol.DomainType) {
		hasMX, _ := d.Attributes["has_mx"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckDomainDMARC.ID,
			Severity: CheckDomainDMARC.Severity,
			Resource: d.Ref(),
			Tags:     CheckDomainDMARC.Tags,
		}
		if !hasMX {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("domain %q: no MX, DMARC not required", d.Name)
			findings = append(findings, f)
			continue
		}
		has, _ := d.Attributes["has_dmarc"].(bool)
		if has {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("domain %q: DMARC published", d.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("domain %q: MX present but no DMARC policy", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckDomainCAANotWildcard flags CAA records that allow ANY
// authority via the wildcard "issue" tag with no value. Better
// than no CAA, but a tightened CAA list is the right baseline.
var CheckDomainCAANotWildcard = compliancekit.Check{
	ID:           "do-domain-caa-wildcard",
	Title:        "CAA records should name specific CAs, not allow any",
	Severity:     compliancekit.SeverityLow,
	Provider:     "digitalocean",
	Service:      "domains",
	ResourceType: docol.DomainType,
	Description: "A CAA record with a literal ';' or empty value " +
		"effectively says 'any CA may issue.' This is better than no " +
		"CAA at all (CAA-aware receivers honor the syntax) but " +
		"defeats the point of CAA. Name your CAs explicitly: " +
		"letsencrypt.org for managed certs, digicert.com / sectigo.com " +
		"for purchased certs.",
	Remediation: "Replace the wildcard CAA entry with explicit issuers. " +
		"Audit existing records: 'doctl compute domain records list " +
		"<domain> --format Type,Name,Data | grep CAA'. Remove the " +
		"wildcard, add explicit issue/issuewild entries for the CAs " +
		"you actually use.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"dns", "tls", "ca-hygiene"},
	Scanner: "domains.CAANotWildcard",
}

func DomainCAANotWildcard(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, d := range g.ByType(docol.DomainType) {
		has, _ := d.Attributes["has_caa"].(bool)
		if !has {
			// no-CAA case is covered by CheckDomainCAA; skip to
			// avoid duplicate findings on the same root cause.
			continue
		}
		records, _ := d.Attributes["caa_records"].([]string)
		f := compliancekit.Finding{
			CheckID:  CheckDomainCAANotWildcard.ID,
			Severity: CheckDomainCAANotWildcard.Severity,
			Resource: d.Ref(),
			Tags:     CheckDomainCAANotWildcard.Tags,
		}
		wildcard := false
		for _, r := range records {
			trimmed := strings.TrimSpace(r)
			if trimmed == "" || trimmed == ";" || strings.HasSuffix(trimmed, "\"\"") {
				wildcard = true
				break
			}
		}
		if wildcard {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("domain %q: CAA includes wildcard entry", d.Name)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("domain %q: CAA names %d issuer(s)", d.Name, len(records))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckCertificateExpiry flags certs that expire in less than
// certExpiryThresholdDays. Buying buffer to renew + propagate
// matters; 30 days is the industry standard.
var CheckCertificateExpiry = compliancekit.Check{
	ID:           "do-certificate-near-expiry",
	Title:        "Certificates should not expire within 30 days",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "certificates",
	ResourceType: docol.CertificateType,
	Description: "A cert that expires in less than 30 days is in the " +
		"renewal-or-outage window. DO managed certs auto-renew but " +
		"the renewal needs DNS / file-system access that might be " +
		"broken; uploaded certs need a human to refresh. 30 days is " +
		"the industry-standard cushion that gives an incident " +
		"response team time to find the problem.",
	Remediation: "Managed certs (type=lets_encrypt): verify the cert's " +
		"DNS challenge can still resolve and reach DO. " +
		"Uploaded certs: rotate. 'doctl compute certificate create " +
		"--type lets_encrypt --domains <names>' creates a new " +
		"managed cert ready to swap into LB forwarding rules.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"tls", "expiry"},
	Scanner: "certificates.Expiry",
}

func CertificateExpiry(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	now := time.Now().UTC()
	threshold := now.Add(certExpiryThresholdDays * 24 * time.Hour)
	for _, ct := range g.ByType(docol.CertificateType) {
		notAfter, _ := ct.Attributes["not_after"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckCertificateExpiry.ID,
			Severity: CheckCertificateExpiry.Severity,
			Resource: ct.Ref(),
			Tags:     CheckCertificateExpiry.Tags,
		}
		t, err := time.Parse(time.RFC3339, notAfter)
		if err != nil {
			f.Status = compliancekit.StatusSkip
			f.Message = fmt.Sprintf("cert %q: unparsable not_after=%q", ct.Name, notAfter)
		} else {
			days := int(t.Sub(now).Hours() / 24)
			switch {
			case t.Before(now):
				f.Status = compliancekit.StatusFail
				f.Message = fmt.Sprintf("cert %q: EXPIRED %d day(s) ago", ct.Name, -days)
			case t.Before(threshold):
				f.Status = compliancekit.StatusFail
				f.Message = fmt.Sprintf("cert %q: expires in %d day(s) (< %d threshold)", ct.Name, days, certExpiryThresholdDays)
			default:
				f.Status = compliancekit.StatusPass
				f.Message = fmt.Sprintf("cert %q: expires in %d day(s)", ct.Name, days)
			}
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckCertificateLetsEncrypt prefers managed Let's Encrypt certs
// over uploaded ones for any LB-attached usage. Managed certs
// renew automatically; uploaded certs are a human responsibility.
var CheckCertificateLetsEncrypt = compliancekit.Check{
	ID:           "do-certificate-uploaded-not-managed",
	Title:        "Uploaded certificates should be reviewed for migration to managed",
	Severity:     compliancekit.SeverityLow,
	Provider:     "digitalocean",
	Service:      "certificates",
	ResourceType: docol.CertificateType,
	Description: "Custom (uploaded) certificates require a human-driven " +
		"renewal cycle. DO's managed certs (Let's Encrypt) auto-renew " +
		"every 90 days with zero operator involvement. For LB-attached " +
		"certs without an EV / wildcard requirement, managed is the " +
		"strictly safer default -- one fewer thing to fall off the " +
		"on-call backlog.",
	Remediation: "If the cert protects domains DO can DNS-challenge, " +
		"create a managed equivalent and swap: 'doctl compute " +
		"certificate create --type lets_encrypt --domains <names>'. " +
		"For wildcard or EV certs that require purchased provenance, " +
		"document the manual-rotation procedure and assign an owner.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"tls", "managed-cert", "renewal"},
	Scanner: "certificates.Type",
}

func CertificateLetsEncrypt(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, ct := range g.ByType(docol.CertificateType) {
		typ, _ := ct.Attributes["type"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckCertificateLetsEncrypt.ID,
			Severity: CheckCertificateLetsEncrypt.Severity,
			Resource: ct.Ref(),
			Tags:     CheckCertificateLetsEncrypt.Tags,
		}
		if typ == "lets_encrypt" {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("cert %q: managed (lets_encrypt)", ct.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("cert %q: type=%q (custom/uploaded; not auto-renewed)", ct.Name, typ)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckDomainCAA, DomainCAA)
	compliancekit.Register(CheckDomainSPF, DomainSPF)
	compliancekit.Register(CheckDomainDMARC, DomainDMARC)
	compliancekit.Register(CheckDomainCAANotWildcard, DomainCAANotWildcard)
	compliancekit.Register(CheckCertificateExpiry, CertificateExpiry)
	compliancekit.Register(CheckCertificateLetsEncrypt, CertificateLetsEncrypt)
}
