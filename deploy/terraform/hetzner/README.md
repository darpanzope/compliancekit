# terraform-hetzner-compliancekit

Provisions compliancekit on Hetzner Cloud: one server running the
daemon + co-located Postgres, fronted by a Hetzner Load Balancer
with TLS termination at the LB.

## Why co-located Postgres

Hetzner Cloud doesn't expose a managed Postgres in the same shape
AWS RDS / GCP Cloud SQL / DO Managed DBs do; for the v1.15 "one
command brings it up" pattern we run Postgres on the same VM via
the Ubuntu apt package. For HA Postgres, point the daemon at a
Hetzner Cloud-hosted Patroni cluster you manage separately + set
`CK_DB_DSN` via cloud-init override.

## Usage

```hcl
module "compliancekit" {
  source = "github.com/darpanzope/compliancekit//deploy/terraform/hetzner?ref=v1.15.0"

  domain             = "compliancekit.example.com"
  location           = "fsn1"
  server_type        = "cpx21"
  ssh_key_ids        = ["123456"]
  tls_certificate_id = "987654"   # upload via hcloud certs create
  dns_zone_id        = "abcdef"   # Hetzner DNS zone, optional
  compliancekit_version = "v1.15.0"
}
```

## TLS

Upload your certificate to Hetzner first:

```sh
hcloud certificate create --name compliancekit \
  --type uploaded \
  --cert-file fullchain.pem --key-file privkey.pem
```

The returned ID is `tls_certificate_id` for the module. Renewal is
manual on the uploaded-cert path; the manage-certificates upgrade
ships at v1.15.x once the hcloud-go SDK exposes managed-cert
lifecycle.

## DNS

If you use Hetzner DNS, supply `dns_zone_id` and the module
creates the A record. If you use a different DNS host, leave
`dns_zone_id` empty and point an A record at the LB's IPv4
output yourself.
