package terraform

import "github.com/darpanzope/compliancekit/internal/remediate"

// v0.19 phase 9 — legacy backfill for v0.9-vintage CDN, certificate,
// SSH-key, and volume checks. These don't yet warrant per-category
// v0.19 strategies, so this file is backfill-only.

var legacyComputeTFEntries = map[string]legacyTFEntry{
	"do-cdn-no-custom-cert": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_certificate\" \"cdn\" {\n  name    = \"cdn-cert\"\n  type    = \"lets_encrypt\"\n  domains = [\"cdn.example.com\"]\n}\n\nresource \"digitalocean_cdn\" \"app\" {\n  origin         = digitalocean_spaces_bucket.assets.bucket_domain_name\n  certificate_id = digitalocean_certificate.cdn.id\n  custom_domain  = \"cdn.example.com\"\n}\n"},
	"do-cdn-no-custom-domain": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_cdn\" \"app\" {\n  origin        = digitalocean_spaces_bucket.assets.bucket_domain_name\n  custom_domain = \"cdn.example.com\"\n}\n"},
	"do-certificate-near-expiry": {risk: remediate.RiskReview,
		content: "# For uploaded certs: re-issue from CA then:\nresource \"digitalocean_certificate\" \"renewed\" {\n  name              = \"renewed\"\n  type              = \"custom\"\n  private_key       = file(\"renewed.key\")\n  leaf_certificate  = file(\"renewed.crt\")\n  certificate_chain = file(\"renewed.chain\")\n}\n# For Let's Encrypt: should auto-renew; if not, recreate the resource."},
	"do-certificate-uploaded-not-managed": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_certificate\" \"managed\" {\n  name    = \"managed\"\n  type    = \"lets_encrypt\"\n  domains = [\"app.example.com\"]\n}\n"},
	"do-ssh-key-too-many": {risk: remediate.RiskReview,
		content: "# Drop unused digitalocean_ssh_key resources from .tf source.\n# Audit: doctl compute ssh-key list --format ID,Name,FingerPrint"},
	"do-ssh-key-weak-algorithm": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_ssh_key\" \"new\" {\n  name       = \"new-ed25519\"\n  public_key = file(\"~/.ssh/do_ed25519.pub\")\n}\n# Then drop the weak-algo digitalocean_ssh_key resource."},
	"do-volume-orphan": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_volume_attachment\" \"web\" {\n  droplet_id = digitalocean_droplet.web.id\n  volume_id  = digitalocean_volume.app.id\n}\n# OR remove the digitalocean_volume block + apply."},
	"do-volume-unformatted-orphan": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_volume\" \"app\" {\n  initial_filesystem_type = \"ext4\"\n}\n"},
}

func init() { registerLegacyTF(legacyComputeTFEntries) }
