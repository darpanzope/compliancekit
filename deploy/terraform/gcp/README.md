# terraform-gcp-compliancekit

Provisions compliancekit on GCP: Compute Engine + Cloud SQL +
Google HTTPS LB + Cloud DNS.

## Usage

```hcl
module "compliancekit" {
  source = "github.com/darpanzope/compliancekit//deploy/terraform/gcp?ref=v1.15.0"

  project          = "my-gcp-project"
  region           = "us-central1"
  zone             = "us-central1-a"
  domain           = "compliancekit.example.com"
  dns_managed_zone = "example-com-zone"

  regional              = true
  compliancekit_version = "v1.15.0"
}
```

## What's provisioned

| Layer | Resource | Notes |
|---|---|---|
| Edge | `google_compute_global_forwarding_rule` + managed SSL cert | TLS via Google-managed cert |
| Compute | `google_compute_instance` `e2-small` + Ubuntu 24.04 LTS | cloud-init systemd unit |
| State | `google_sql_database_instance` Postgres 16 | Regional HA, PITR, 14-day backups |
| Network | Private IP on Cloud SQL via the default VPC | No public Postgres |

## DNS

`dns_managed_zone` is the Cloud DNS zone *name* (not the DNS name).
Create the zone in advance:

```sh
gcloud dns managed-zones create example-com-zone \
  --dns-name=example.com. --description="example.com root zone"
```

## Updating

```sh
terraform apply -var=compliancekit_version=v1.15.1
```

The Compute Engine instance reads cloud-init only on first boot;
to upgrade the binary, taint + reapply (or SSH and re-pull the
release tarball + `systemctl restart compliancekit`).
