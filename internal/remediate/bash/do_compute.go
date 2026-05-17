package bash

import "github.com/darpanzope/compliancekit/internal/remediate"

// v0.19 phase 9 — legacy backfill for v0.9-vintage CDN, certificate,
// SSH-key, and volume checks.
var legacyComputeBashEntries = map[string]legacyBashEntry{
	"do-cdn-no-custom-cert":               {risk: remediate.RiskReview, body: "doctl compute certificate create --name app --type lets_encrypt --dns-names app.example.com\ndoctl compute cdn update CDN_ID --certificate-id CERT_ID"},
	"do-cdn-no-custom-domain":             {risk: remediate.RiskReview, body: "doctl compute cdn update CDN_ID --custom-domain app.example.com"},
	"do-certificate-near-expiry":          {risk: remediate.RiskReview, body: "doctl compute certificate list --format Name,Type,NotAfter\n# Reissue / renew near-expiry certs."},
	"do-certificate-uploaded-not-managed": {risk: remediate.RiskReview, body: "doctl compute certificate create --name managed --type lets_encrypt --dns-names app.example.com"},
	"do-ssh-key-too-many":                 {risk: remediate.RiskReview, body: "doctl compute ssh-key list --format ID,Name,FingerPrint\n# doctl compute ssh-key delete OLD_KEY_ID"},
	"do-ssh-key-weak-algorithm":           {risk: remediate.RiskReview, body: "ssh-keygen -t ed25519 -f ~/.ssh/do_ed25519\ndoctl compute ssh-key import new --public-key-file ~/.ssh/do_ed25519.pub\ndoctl compute ssh-key delete OLD_KEY_ID --force"},
	"do-volume-orphan":                    {risk: remediate.RiskReview, body: "doctl compute volume delete VOLUME_ID --force"},
	"do-volume-unformatted-orphan":        {risk: remediate.RiskReview, body: "doctl compute volume delete VOLUME_ID --force"},
}

func init() { registerLegacyBash(legacyComputeBashEntries) }
