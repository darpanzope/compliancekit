package doctl

import "github.com/darpanzope/compliancekit/internal/remediate"

// v0.19 phase 9 — legacy backfill for v0.9-vintage CDN, certificate,
// SSH-key, and volume checks.
var legacyComputeDoctlEntries = map[string]legacyDoctlEntry{
	"do-cdn-no-custom-cert": {risk: remediate.RiskReview,
		content: "doctl compute certificate create --name app --type lets_encrypt --dns-names app.example.com\ndoctl compute cdn update CDN_ID --certificate-id CERT_ID"},
	"do-cdn-no-custom-domain": {risk: remediate.RiskReview,
		content: "doctl compute cdn update CDN_ID --custom-domain app.example.com"},
	"do-certificate-uploaded-not-managed": {risk: remediate.RiskReview,
		content: "# Switch to a Let's Encrypt managed cert (auto-renews):\ndoctl compute certificate create --name app --type lets_encrypt --dns-names app.example.com\n# Then re-point LBs / apps + delete the uploaded one."},
	"do-ssh-key-too-many": {risk: remediate.RiskReview,
		content: "doctl compute ssh-key list --format ID,Name,FingerPrint\n# doctl compute ssh-key delete OLD_KEY_ID"},
	"do-ssh-key-weak-algorithm": {risk: remediate.RiskReview,
		content: "ssh-keygen -t ed25519 -f ~/.ssh/do_ed25519\ndoctl compute ssh-key import new --public-key-file ~/.ssh/do_ed25519.pub\ndoctl compute ssh-key delete OLD_KEY_ID --force"},
	"do-volume-orphan":             {risk: remediate.RiskReview, content: "doctl compute volume delete VOLUME_ID --force"},
	"do-volume-unformatted-orphan": {risk: remediate.RiskReview, content: "doctl compute volume delete VOLUME_ID --force"},
}

func init() { registerLegacyDoctl(legacyComputeDoctlEntries) }
