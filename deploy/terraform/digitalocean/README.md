# terraform-digitalocean-compliancekit

Provisions compliancekit on DigitalOcean: Droplet + Managed Postgres +
Load Balancer (Let's Encrypt) + DO DNS.

## Usage

```hcl
module "compliancekit" {
  source = "github.com/darpanzope/compliancekit//deploy/terraform/digitalocean?ref=v1.15.0"

  domain                = "compliancekit.example.com"
  region                = "nyc3"
  droplet_size          = "s-1vcpu-2gb"
  db_size               = "db-s-1vcpu-1gb"
  standby               = false
  ssh_key_ids           = [12345678]
  operator_cidrs        = ["203.0.113.0/24"]
  compliancekit_version = "v1.15.0"
}
```

## What's provisioned

| Layer | Resource | Notes |
|---|---|---|
| Edge | `digitalocean_loadbalancer` + `digitalocean_certificate` (Let's Encrypt) | DO-managed cert renewal |
| Compute | `digitalocean_droplet` Ubuntu 24.04 | cloud-init systemd unit, monitoring on |
| State | `digitalocean_database_cluster` Postgres 16 | Optional standby for HA |
| DNS | `digitalocean_record` A | Inferred from the FQDN |
| Security | `digitalocean_firewall` (SSH + LB only) + `digitalocean_database_firewall` (Droplet only) | |

## DNS

The module assumes the parent zone is managed in DigitalOcean. If
you use a different registrar / DNS host, drop the
`digitalocean_record` resource and add an A record there pointing
at the LB IP (output as `digitalocean_loadbalancer.main.ip`).
