package bash

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 3 — bash strategies for the 10 DNS-depth checks.
// Same record-create flow as doctl, wrapped in a script with verify
// + rollback hooks.

func init() {
	register("bash-do-domain-dmarc-policy-strict",
		[]string{"do-domain-dmarc-policy-not-strict"}, renderBashDMARCPolicy)
	register("bash-do-domain-dmarc-subdomain-policy",
		[]string{"do-domain-dmarc-subdomain-policy"}, renderBashDMARCSubdomain)
	register("bash-do-domain-dmarc-pct-full",
		[]string{"do-domain-dmarc-pct-not-full"}, renderBashDMARCPct)
	register("bash-do-domain-dmarc-rua",
		[]string{"do-domain-dmarc-no-rua"}, renderBashDMARCRUA)
	register("bash-do-domain-dmarc-ruf",
		[]string{"do-domain-dmarc-no-ruf"}, renderBashDMARCRUF)
	register("bash-do-domain-spf-strict-all",
		[]string{"do-domain-spf-not-strict-fail"}, renderBashSPFStrict)
	register("bash-do-domain-spf-no-redirect",
		[]string{"do-domain-spf-uses-redirect"}, renderBashSPFNoRedirect)
	register("bash-do-domain-dkim-selector",
		[]string{"do-domain-dkim-no-selector"}, renderBashDKIMSelector)
	register("bash-do-domain-caa-iodef",
		[]string{"do-domain-caa-no-iodef"}, renderBashCAAIodef)
	register("bash-do-domain-dnssec-registrar",
		[]string{"do-domain-dnssec-via-registrar"}, renderBashDNSSECRegistrar)
}

func bashDomain(f core.Finding) string {
	if f.Resource.Name != "" {
		return f.Resource.Name
	}
	return "DOMAIN"
}

func renderBashDMARCPolicy(f core.Finding) (remediate.Snippet, error) {
	d := bashDomain(f)
	body := fmt.Sprintf(`# Idempotent _dmarc upsert: delete any existing _dmarc TXT, then create the strict record.
domain=%q
rua="mailto:dmarc-reports@${domain}"
ruf="mailto:dmarc-forensics@${domain}"

existing="$(doctl compute domain records list "$domain" -o json \
  | jq -r '.[] | select(.type=="TXT" and .name=="_dmarc") | .id')"
for id in $existing; do
  doctl compute domain records delete "$domain" "$id" --force
done

doctl compute domain records create "$domain" \
  --record-type TXT --record-name _dmarc \
  --record-data "v=DMARC1; p=reject; sp=reject; pct=100; rua=${rua}; ruf=${ruf}" \
  --record-ttl 3600`, d)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`dig +short TXT _dmarc.%s`, d),
	}, nil
}

func renderBashDMARCSubdomain(f core.Finding) (remediate.Snippet, error) {
	return renderBashDMARCPolicy(f)
}
func renderBashDMARCPct(f core.Finding) (remediate.Snippet, error) { return renderBashDMARCPolicy(f) }
func renderBashDMARCRUA(f core.Finding) (remediate.Snippet, error) { return renderBashDMARCPolicy(f) }
func renderBashDMARCRUF(f core.Finding) (remediate.Snippet, error) { return renderBashDMARCPolicy(f) }

func renderBashSPFStrict(f core.Finding) (remediate.Snippet, error) {
	d := bashDomain(f)
	body := fmt.Sprintf(`# Find + update the root SPF TXT record terminator from ~all/?all to -all.
domain=%q
rec_id="$(doctl compute domain records list "$domain" -o json \
  | jq -r '.[] | select(.type=="TXT" and (.name=="@" or .name=="" or .name=="'"$domain"'") and (.data | test("v=spf1"))) | .id' | head -1)"
if [ -z "$rec_id" ]; then
  printf 'no SPF record found for %%s\n' "$domain" >&2
  exit 1
fi
data="$(doctl compute domain records get "$domain" "$rec_id" -o json | jq -r .[0].data)"
new="$(printf '%%s' "$data" | sed -E 's/[~?+]all$/-all/; s/[~?+]all([[:space:]])/-all\1/g')"
doctl compute domain records update "$domain" --record-id "$rec_id" --record-data "$new"`, d)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`dig +short TXT %s | grep spf1`, d),
		Notes:     "Verify DMARC aggregate reports show no legitimate-sender failures BEFORE running.",
	}, nil
}

func renderBashSPFNoRedirect(f core.Finding) (remediate.Snippet, error) {
	d := bashDomain(f)
	body := fmt.Sprintf(`# redirect= → include: rewrite. Manual review of the resulting SPF is REQUIRED
# because include: doesn't carry the terminating qualifier.
domain=%q
echo "Current SPF:"
doctl compute domain records list "$domain" --format ID,Type,Name,Data | grep spf1
echo
echo "Rewrite plan: replace 'redirect=<other>' with 'include:<other>' and add '-all' terminator."`, d)
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
		Notes: "redirect= migration requires understanding the target domain's policy. Don't auto-rewrite.",
	}, nil
}

func renderBashDKIMSelector(f core.Finding) (remediate.Snippet, error) {
	d := bashDomain(f)
	body := fmt.Sprintf(`# Generate + publish a DKIM key pair.
domain=%q
selector="primary"

# 1. Generate key pair (writes ${selector}.private + ${selector}.txt).
opendkim-genkey -s "$selector" -d "$domain" -b 2048

# 2. Extract the public-key body (drop "selector._domainkey IN TXT (" + close paren + quotes).
pubkey="$(awk -F'"' '/p=/ {p=""; for (i=2;i<=NF;i+=2) p=p $i; print p}' "${selector}.txt")"

# 3. Publish via doctl.
doctl compute domain records create "$domain" \
  --record-type TXT \
  --record-name "${selector}._domainkey" \
  --record-data "v=DKIM1; k=rsa; p=${pubkey}" \
  --record-ttl 3600

# 4. Configure the MTA (postfix/opendkim/SendGrid/Mailgun) with the matching ${selector}.private.`, d)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		VerifyCmd: fmt.Sprintf(`dig +short TXT primary._domainkey.%s`, d),
		Notes:     "Requires opendkim-tools. Move ${selector}.private to the MTA + chmod 600 + chown to the MTA user.",
	}, nil
}

func renderBashCAAIodef(f core.Finding) (remediate.Snippet, error) {
	d := bashDomain(f)
	body := fmt.Sprintf(`domain=%q
doctl compute domain records create "$domain" \
  --record-type CAA \
  --record-name @ \
  --record-data "0 iodef \"mailto:secops@${domain}\"" \
  --record-ttl 3600`, d)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: false, Content: body,
		VerifyCmd: fmt.Sprintf(`dig +short CAA %s`, d),
	}, nil
}

func renderBashDNSSECRegistrar(_ core.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"DNSSEC for DO-managed zones",
		"https://dnssec-analyzer.verisignlabs.com",
		"At the registrar: enable DNSSEC, accept the DS record, then 'dig +dnssec <domain>' to confirm the AD flag is set")
}

// v0.19 phase 9 — legacy backfill for v0.9-vintage domain checks.
var legacyDomainBashEntries = map[string]legacyBashEntry{
	"do-domain-caa-wildcard": {risk: remediate.RiskReview, body: "domain=DOMAIN\ndoctl compute domain records list \"$domain\" --format ID,Type,Data | grep CAA\n# Manual: remove wildcard ID + add explicit."},
	"do-domain-no-caa":       {risk: remediate.RiskSafe, body: "doctl compute domain records create DOMAIN --record-type CAA --record-name @ --record-data '0 issue \"letsencrypt.org\"'"},
	"do-domain-no-dmarc":     {risk: remediate.RiskReview, body: "doctl compute domain records create DOMAIN --record-type TXT --record-name _dmarc --record-data \"v=DMARC1; p=quarantine; rua=mailto:dmarc@DOMAIN\""},
	"do-domain-no-spf":       {risk: remediate.RiskReview, body: "doctl compute domain records create DOMAIN --record-type TXT --record-name @ --record-data \"v=spf1 include:_spf.google.com -all\""},
}

func init() { registerLegacyBash(legacyDomainBashEntries) }
