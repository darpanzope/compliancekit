# Terraform modules for compliancekit

Provision a complete compliancekit deployment on each major cloud
in one `terraform apply`. Each module brings up:

| Per module | Resource |
|---|---|
| Compute | One VM running the compliancekit binary via systemd |
| State | A managed Postgres (or self-hosted on Hetzner) |
| Edge | A load balancer with TLS termination |
| DNS | An A/CNAME record pointing at the LB |

| Module | Cloud | Path |
|---|---|---|
| `aws` | AWS | [./aws/](./aws) |
| `gcp` | GCP | [./gcp/](./gcp) |
| `digitalocean` | DO | [./digitalocean/](./digitalocean) |
| `hetzner` | Hetzner Cloud | [./hetzner/](./hetzner) |

Use as Terraform modules:

```hcl
module "compliancekit" {
  source  = "darpanzope/compliancekit/aws"
  version = "1.15.0"

  domain = "compliancekit.example.com"
  region = "us-east-1"
  # ...
}
```

Publishing to the Terraform Registry happens at v1.15.x. Until then,
pull via the git subdir source path:

```hcl
module "compliancekit" {
  source = "github.com/darpanzope/compliancekit//deploy/terraform/aws?ref=v1.15.0"
  # ...
}
```

## What each module DOES NOT do

* TLS certificate issuance — every cloud has a different
  flavor (ACM / Google-managed certs / Let's Encrypt). The
  module assumes you point an existing cert ARN / cert name at
  the variable; the README per module shows the recipe.
* Cluster-grade observability — Prometheus, Grafana, alerting.
  Use the v1.15 phase 8 Grafana dashboards alongside whatever
  Prometheus you already run.
* Backup off-site replication — the daemon writes its v1.12
  phase 8 backups to a local PVC by default; pair with your
  cloud's snapshot tooling for off-host durability.

## Choosing between modules

| Use | When |
|---|---|
| `aws` | Already on AWS; want RDS-managed Postgres; need IAM-role auth for scanners. |
| `gcp` | Already on GCP; want Cloud SQL; using Workload Identity for scans. |
| `digitalocean` | Smaller deploys; cost-conscious; want managed-Postgres backups out of the box. |
| `hetzner` | EU data-residency hard requirement; want the cheapest viable HA. |
