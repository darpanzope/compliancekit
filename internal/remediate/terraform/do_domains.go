package terraform

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 3 — Terraform strategies for the 10 DNS-depth checks.
//
// DNS records under DO go through `digitalocean_record`. The provider
// has no special handling for DMARC/SPF/DKIM — they're all TXT records
// with the right Name + Data. CAA gets its own type. DNSSEC is
// registrar-side and has no DO TF surface; that strategy emits a
// manual stub pointing the operator at their registrar.

func init() {
	register("tf-do-domain-dmarc-policy-strict",
		[]string{"do-domain-dmarc-policy-not-strict"}, renderTFDMARCPolicy)
	register("tf-do-domain-dmarc-subdomain-policy",
		[]string{"do-domain-dmarc-subdomain-policy"}, renderTFDMARCSubdomain)
	register("tf-do-domain-dmarc-pct-full",
		[]string{"do-domain-dmarc-pct-not-full"}, renderTFDMARCPct)
	register("tf-do-domain-dmarc-rua",
		[]string{"do-domain-dmarc-no-rua"}, renderTFDMARCRUA)
	register("tf-do-domain-dmarc-ruf",
		[]string{"do-domain-dmarc-no-ruf"}, renderTFDMARCRUF)
	register("tf-do-domain-spf-strict-all",
		[]string{"do-domain-spf-not-strict-fail"}, renderTFSPFStrict)
	register("tf-do-domain-spf-no-redirect",
		[]string{"do-domain-spf-uses-redirect"}, renderTFSPFNoRedirect)
	register("tf-do-domain-dkim-selector",
		[]string{"do-domain-dkim-no-selector"}, renderTFDKIMSelector)
	register("tf-do-domain-caa-iodef",
		[]string{"do-domain-caa-no-iodef"}, renderTFCAAIodef)
	register("tf-do-domain-dnssec-registrar",
		[]string{"do-domain-dnssec-via-registrar"}, renderTFDNSSECRegistrar)
}

func tfRecord(domain, recName, recType, data string) string {
	return fmt.Sprintf(`resource "digitalocean_record" %q {
  domain = %q
  type   = %q
  name   = %q
  value  = %q
  ttl    = 3600
}
`, tfIdent(recName+"-"+recType), domain, recType, recName, data)
}

func renderTFDMARCPolicy(f core.Finding) (remediate.Snippet, error) {
	domain := tfNameOrFallback(f, "DOMAIN")
	body := tfRecord(domain, "_dmarc", "TXT",
		"v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@"+domain+"; ruf=mailto:dmarc-forensics@"+domain)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`dig +short TXT _dmarc.%s`, domain),
		Notes:     "Stage p=quarantine first if rolling out from p=none; flip to p=reject once aggregate reports show no legit-sender failures for ≥2 weeks.",
		Refs:      []string{"https://datatracker.ietf.org/doc/html/rfc7489"},
	}, nil
}

func renderTFDMARCSubdomain(f core.Finding) (remediate.Snippet, error) {
	// Same record; the rendered body includes sp=. Reuse the parent.
	return renderTFDMARCPolicy(f)
}

func renderTFDMARCPct(f core.Finding) (remediate.Snippet, error) {
	return renderTFDMARCPolicy(f)
}

func renderTFDMARCRUA(f core.Finding) (remediate.Snippet, error) {
	return renderTFDMARCPolicy(f)
}

func renderTFDMARCRUF(f core.Finding) (remediate.Snippet, error) {
	return renderTFDMARCPolicy(f)
}

func renderTFSPFStrict(f core.Finding) (remediate.Snippet, error) {
	domain := tfNameOrFallback(f, "DOMAIN")
	body := tfRecord(domain, "@", "TXT",
		"v=spf1 include:_spf.google.com include:mailgun.org -all")
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`dig +short TXT %s | grep spf1`, domain),
		Notes:     "Adjust include: list to match your actual senders. Verify aggregate DMARC reports show no legit-sender failures BEFORE moving from ~all → -all in production.",
		Refs:      []string{"https://datatracker.ietf.org/doc/html/rfc7208"},
	}, nil
}

func renderTFSPFNoRedirect(f core.Finding) (remediate.Snippet, error) {
	return renderTFSPFStrict(f)
}

func renderTFDKIMSelector(f core.Finding) (remediate.Snippet, error) {
	domain := tfNameOrFallback(f, "DOMAIN")
	body := tfRecord(domain, "primary._domainkey", "TXT",
		"v=DKIM1; k=rsa; p=YOUR_BASE64_PUBLIC_KEY_HERE")
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`dig +short TXT primary._domainkey.%s`, domain),
		Notes:     "Generate the key pair (opendkim-genkey -s primary -d " + domain + "), publish the public key here, configure the MTA to sign with the private key.",
		Refs:      []string{"https://datatracker.ietf.org/doc/html/rfc6376"},
	}, nil
}

func renderTFCAAIodef(f core.Finding) (remediate.Snippet, error) {
	domain := tfNameOrFallback(f, "DOMAIN")
	body := fmt.Sprintf(`resource "digitalocean_record" %q {
  domain = %q
  type   = "CAA"
  name   = "@"
  value  = "mailto:secops@%s"
  flags  = 0
  tag    = "iodef"
  ttl    = 3600
}
`, tfIdent(domain+"-caa-iodef"), domain, domain)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`dig +short CAA %s`, domain),
		Notes:     "Adds the iodef contact alongside any existing 'issue \"letsencrypt.org\"' CAA records.",
		Refs:      []string{"https://datatracker.ietf.org/doc/html/rfc8659"},
	}, nil
}

func renderTFDNSSECRegistrar(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"DigitalOcean managed DNS does not serve signed zones; DNSSEC is a registrar-side control",
		"https://dnssec-analyzer.verisignlabs.com",
		"At the registrar (Namecheap / Gandi / Cloudflare etc.): enable DNSSEC, accept the DS record, then verify with 'dig +dnssec' (look for AD flag)")
}

// v0.19 phase 9 — legacy backfill for v0.9-vintage domain checks.
var legacyDomainTFEntries = map[string]legacyTFEntry{
	"do-domain-caa-wildcard": {risk: remediate.RiskReview,
		content: "# Replace wildcard CAA with explicit issuer records.\nresource \"digitalocean_record\" \"caa_letsencrypt\" {\n  domain = \"example.com\"\n  type   = \"CAA\"\n  name   = \"@\"\n  flags  = 0\n  tag    = \"issue\"\n  value  = \"letsencrypt.org\"\n}\n"},
	"do-domain-no-dmarc": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_record\" \"dmarc\" {\n  domain = \"example.com\"\n  type   = \"TXT\"\n  name   = \"_dmarc\"\n  value  = \"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com\"\n}\n"},
	"do-domain-no-spf": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_record\" \"spf\" {\n  domain = \"example.com\"\n  type   = \"TXT\"\n  name   = \"@\"\n  value  = \"v=spf1 include:_spf.google.com -all\"\n}\n"},
}

func init() { registerLegacyTF(legacyDomainTFEntries) }
