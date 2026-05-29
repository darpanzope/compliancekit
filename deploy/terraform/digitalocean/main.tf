# v1.15 phase 5 — DigitalOcean Terraform module for compliancekit.
#
# Provisions:
#   - One Droplet running the compliancekit systemd unit (cloud-init
#     drops the latest release tarball).
#   - A DO Managed Postgres cluster (basic 1GB tier by default,
#     standby toggleable via var.standby).
#   - A DO Load Balancer in front (Let's Encrypt cert managed by DO).
#   - A DO DNS A record at the configured domain.

terraform {
  required_version = ">= 1.6"
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.40"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

variable "domain" {
  description = "Fully qualified domain the daemon is served at."
  type        = string
}

variable "region" {
  description = "DO region slug."
  type        = string
  default     = "nyc3"
}

variable "droplet_size" {
  description = "Droplet size slug."
  type        = string
  default     = "s-1vcpu-2gb"
}

variable "db_size" {
  description = "Managed DB size slug."
  type        = string
  default     = "db-s-1vcpu-1gb"
}

variable "standby" {
  description = "Add a standby Postgres node for failover."
  type        = bool
  default     = false
}

variable "compliancekit_version" {
  description = "Tag of the compliancekit release to install."
  type        = string
  default     = "v1.19.1"
}

variable "ssh_key_ids" {
  description = "DigitalOcean SSH key IDs permitted to log into the Droplet."
  type        = list(string)
  default     = []
}

variable "operator_cidrs" {
  description = "CIDRs permitted to SSH into the Droplet."
  type        = list(string)
  default     = []
}

# ─── Managed Postgres ──────────────────────────────────────────

resource "digitalocean_database_cluster" "postgres" {
  name       = "compliancekit"
  engine     = "pg"
  version    = "16"
  size       = var.db_size
  region     = var.region
  node_count = var.standby ? 2 : 1
}

resource "digitalocean_database_db" "main" {
  cluster_id = digitalocean_database_cluster.postgres.id
  name       = "compliancekit"
}

resource "digitalocean_database_user" "main" {
  cluster_id = digitalocean_database_cluster.postgres.id
  name       = "compliancekit"
}

# ─── Droplet + firewall ────────────────────────────────────────

locals {
  cloud_init = <<-CLOUDINIT
    #cloud-config
    package_update: true
    packages: [curl, ca-certificates, jq]
    write_files:
      - path: /etc/systemd/system/compliancekit.service
        content: |
          [Unit]
          Description=compliancekit daemon
          After=network-online.target
          Wants=network-online.target
          [Service]
          Type=simple
          User=compliancekit
          Group=compliancekit
          Environment=CK_DB_DSN=postgres://${digitalocean_database_user.main.name}:${digitalocean_database_user.main.password}@${digitalocean_database_cluster.postgres.private_host}:${digitalocean_database_cluster.postgres.port}/compliancekit?sslmode=require
          ExecStart=/usr/local/bin/compliancekit serve --addr 127.0.0.1 --port 8080 --db $${CK_DB_DSN}
          Restart=always
          RestartSec=5
          [Install]
          WantedBy=multi-user.target
    runcmd:
      - useradd --system --user-group --create-home --home-dir /var/lib/compliancekit --shell /usr/sbin/nologin compliancekit
      - curl -fsSL https://github.com/darpanzope/compliancekit/releases/download/${var.compliancekit_version}/compliancekit_${replace(var.compliancekit_version, "v", "")}_linux_amd64.tar.gz | tar xz -C /tmp
      - install -m 0755 /tmp/compliancekit /usr/local/bin/compliancekit
      - systemctl daemon-reload && systemctl enable --now compliancekit
  CLOUDINIT
}

resource "digitalocean_droplet" "daemon" {
  name      = "compliancekit"
  image     = "ubuntu-24-04-x64"
  region    = var.region
  size      = var.droplet_size
  ssh_keys  = var.ssh_key_ids
  user_data = local.cloud_init
  monitoring = true
}

resource "digitalocean_firewall" "daemon" {
  name        = "compliancekit"
  droplet_ids = [digitalocean_droplet.daemon.id]
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.operator_cidrs
  }
  inbound_rule {
    protocol                  = "tcp"
    port_range                = "8080"
    source_load_balancer_uids = [digitalocean_loadbalancer.main.id]
  }
  outbound_rule {
    protocol              = "tcp"
    port_range            = "all"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "udp"
    port_range            = "all"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

resource "digitalocean_database_firewall" "postgres" {
  cluster_id = digitalocean_database_cluster.postgres.id
  rule {
    type  = "droplet"
    value = digitalocean_droplet.daemon.id
  }
}

# ─── Load balancer + DNS ────────────────────────────────────────

resource "digitalocean_loadbalancer" "main" {
  name   = "compliancekit"
  region = var.region
  forwarding_rule {
    entry_port       = 443
    entry_protocol   = "https"
    target_port      = 8080
    target_protocol  = "http"
    certificate_name = digitalocean_certificate.main.name
  }
  healthcheck {
    port     = 8080
    protocol = "http"
    path     = "/health"
  }
  droplet_ids = [digitalocean_droplet.daemon.id]
}

resource "digitalocean_certificate" "main" {
  name    = "compliancekit-cert"
  type    = "lets_encrypt"
  domains = [var.domain]
}

locals {
  domain_parts = split(".", var.domain)
  parts_count  = length(local.domain_parts)
  # apex_domain is always the last two labels of var.domain (e.g.
  # "example.com" from "app.example.com"). subdomain is everything
  # before the apex, or "@" if var.domain is already the apex.
  apex_domain = join(".", slice(local.domain_parts, local.parts_count - 2, local.parts_count))
  subdomain   = local.parts_count > 2 ? join(".", slice(local.domain_parts, 0, local.parts_count - 2)) : "@"
}

resource "digitalocean_record" "main" {
  # HCL's `+` operator is arithmetic only; the v1.15.0 code path
  # tried to concat strings with `+` and `terraform validate` failed
  # at every plan. v1.15.1 phase 2 fix.
  domain = local.apex_domain
  type   = "A"
  name   = local.subdomain
  value  = digitalocean_loadbalancer.main.ip
  ttl    = 300
}

output "endpoint" { value = "https://${var.domain}" }
output "droplet_ip" { value = digitalocean_droplet.daemon.ipv4_address }
output "db_uri" {
  value     = digitalocean_database_cluster.postgres.private_uri
  sensitive = true
}
