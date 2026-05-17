package doctl

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 3 — doctl strategies for the 10 DNS-depth checks.
// All record manipulations go through `doctl compute domain records create`
// / `update`. DNSSEC is registrar-side; that strategy renders a manual
// stub.

func init() {
	register("doctl-do-domain-dmarc-policy-strict",
		[]string{"do-domain-dmarc-policy-not-strict"}, renderDoctlDMARCPolicy)
	register("doctl-do-domain-dmarc-subdomain-policy",
		[]string{"do-domain-dmarc-subdomain-policy"}, renderDoctlDMARCSubdomain)
	register("doctl-do-domain-dmarc-pct-full",
		[]string{"do-domain-dmarc-pct-not-full"}, renderDoctlDMARCPct)
	register("doctl-do-domain-dmarc-rua",
		[]string{"do-domain-dmarc-no-rua"}, renderDoctlDMARCRUA)
	register("doctl-do-domain-dmarc-ruf",
		[]string{"do-domain-dmarc-no-ruf"}, renderDoctlDMARCRUF)
	register("doctl-do-domain-spf-strict-all",
		[]string{"do-domain-spf-not-strict-fail"}, renderDoctlSPFStrict)
	register("doctl-do-domain-spf-no-redirect",
		[]string{"do-domain-spf-uses-redirect"}, renderDoctlSPFNoRedirect)
	register("doctl-do-domain-dkim-selector",
		[]string{"do-domain-dkim-no-selector"}, renderDoctlDKIMSelector)
	register("doctl-do-domain-caa-iodef",
		[]string{"do-domain-caa-no-iodef"}, renderDoctlCAAIodef)
	register("doctl-do-domain-dnssec-registrar",
		[]string{"do-domain-dnssec-via-registrar"}, renderDoctlDNSSECRegistrar)
}

func doctlDomain(f core.Finding) string {
	if f.Resource.Name != "" {
		return f.Resource.Name
	}
	return "DOMAIN"
}

func renderDoctlDMARCPolicy(f core.Finding) (remediate.Snippet, error) {
	d := doctlDomain(f)
	body := fmt.Sprintf(`# DMARC: enforce + report. Phase rollout via pct=10 → 50 → 100.
# If the _dmarc record already exists, find its ID first:
#   doctl compute domain records list %s --format ID,Type,Name,Data | grep _dmarc
# Then 'doctl compute domain records update %s --record-id <ID> --record-data <NEW>'.

doctl compute domain records create %s \
  --record-type TXT \
  --record-name _dmarc \
  --record-data "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@%s; ruf=mailto:dmarc-forensics@%s" \
  --record-ttl 3600`, d, d, d, d, d)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		VerifyCmd: fmt.Sprintf(`dig +short TXT _dmarc.%s`, d),
		Notes:     "Create is not idempotent — duplicate _dmarc records produce undefined behavior. Use update if record already exists.",
	}, nil
}

func renderDoctlDMARCSubdomain(f core.Finding) (remediate.Snippet, error) {
	return renderDoctlDMARCPolicy(f)
}
func renderDoctlDMARCPct(f core.Finding) (remediate.Snippet, error) { return renderDoctlDMARCPolicy(f) }
func renderDoctlDMARCRUA(f core.Finding) (remediate.Snippet, error) { return renderDoctlDMARCPolicy(f) }
func renderDoctlDMARCRUF(f core.Finding) (remediate.Snippet, error) { return renderDoctlDMARCPolicy(f) }

func renderDoctlSPFStrict(f core.Finding) (remediate.Snippet, error) {
	d := doctlDomain(f)
	body := fmt.Sprintf(`# Tighten the SPF terminator to -all. Update the existing root TXT record.
doctl compute domain records list %s --format ID,Type,Name,Data | grep 'spf1'

# Then (replace ID + sender includes with your real ones):
doctl compute domain records update %s --record-id RECORD_ID \
  --record-data "v=spf1 include:_spf.google.com include:mailgun.org -all"`, d, d)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		VerifyCmd: fmt.Sprintf(`dig +short TXT %s | grep spf1`, d),
		Notes:     "Verify DMARC aggregate reports show no legitimate-sender failures BEFORE moving the terminator to -all.",
	}, nil
}

func renderDoctlSPFNoRedirect(f core.Finding) (remediate.Snippet, error) {
	return renderDoctlSPFStrict(f)
}

func renderDoctlDKIMSelector(f core.Finding) (remediate.Snippet, error) {
	d := doctlDomain(f)
	body := fmt.Sprintf(`# Publish a DKIM selector. Key generation example (opendkim-genkey):
#   opendkim-genkey -s primary -d %s
#   # produces primary.private (signer) + primary.txt (publish below)

doctl compute domain records create %s \
  --record-type TXT \
  --record-name primary._domainkey \
  --record-data "v=DKIM1; k=rsa; p=YOUR_BASE64_PUBLIC_KEY_HERE" \
  --record-ttl 3600`, d, d)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		VerifyCmd: fmt.Sprintf(`dig +short TXT primary._domainkey.%s`, d),
		Notes:     "Configure the MTA (postfix/sendgrid/etc.) to sign with the matching private key. Rotate selectors annually with overlap.",
	}, nil
}

func renderDoctlCAAIodef(f core.Finding) (remediate.Snippet, error) {
	d := doctlDomain(f)
	body := fmt.Sprintf(`doctl compute domain records create %s \
  --record-type CAA \
  --record-name @ \
  --record-data "0 iodef \"mailto:secops@%s\"" \
  --record-ttl 3600`, d, d)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: false, Content: body,
		VerifyCmd: fmt.Sprintf(`dig +short CAA %s`, d),
		Notes:     "Adds iodef alongside any existing CAA records. Confirm there's only one iodef= per domain after creation.",
	}, nil
}

func renderDoctlDNSSECRegistrar(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"DNSSEC for DO-managed zones",
		"https://dnssec-analyzer.verisignlabs.com",
		"At the registrar: enable DNSSEC, accept the DS record, then 'dig +dnssec <domain>' — look for AD flag")
}

// v0.19 phase 9 — legacy backfill for v0.9-vintage domain checks.
var legacyDomainDoctlEntries = map[string]legacyDoctlEntry{
	"do-domain-caa-wildcard": {risk: remediate.RiskReview,
		content: "doctl compute domain records list DOMAIN | grep CAA\n# Remove wildcard + add explicit:\ndoctl compute domain records create DOMAIN --record-type CAA --record-name @ --record-data '0 issue \"letsencrypt.org\"'"},
	"do-domain-no-caa": {risk: remediate.RiskSafe,
		content: "doctl compute domain records create DOMAIN --record-type CAA --record-name @ --record-data '0 issue \"letsencrypt.org\"'"},
	"do-domain-no-dmarc": {risk: remediate.RiskReview,
		content: "doctl compute domain records create DOMAIN --record-type TXT --record-name _dmarc --record-data \"v=DMARC1; p=quarantine; rua=mailto:dmarc@DOMAIN\""},
	"do-domain-no-spf": {risk: remediate.RiskReview,
		content: "doctl compute domain records create DOMAIN --record-type TXT --record-name @ --record-data \"v=spf1 include:_spf.google.com -all\""},
}

func init() { registerLegacyDoctl(legacyDomainDoctlEntries) }
