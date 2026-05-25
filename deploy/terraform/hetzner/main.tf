# v1.15 phase 5 — Hetzner Cloud Terraform module for compliancekit.
#
# Hetzner Cloud doesn't ship managed Postgres as cleanly as the
# bigger clouds, so this module runs Postgres on the same server
# as the daemon (binary on top of Postgres 16 from the Ubuntu repo).
# A Hetzner Load Balancer fronts the daemon with TLS terminated at
# the LB using the certificate the operator uploads in advance.
#
# Provisions:
#   - One CPX21 server running compliancekit + Postgres 16 via
#     systemd, fronted by a Hetzner LB.
#   - Hetzner LB with HTTPS termination + the configured cert.
#   - Hetzner DNS A record at the domain (when var.dns_zone_id set).

terraform {
  required_version = ">= 1.6"
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.50"
    }
    hetznerdns = {
      source  = "germanbrew/hetznerdns"
      version = "~> 3.0"
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

variable "location" {
  description = "Hetzner Cloud location."
  type        = string
  default     = "fsn1"
}

variable "server_type" {
  description = "Hetzner server type."
  type        = string
  default     = "cpx21"
}

variable "ssh_key_ids" {
  description = "Hetzner Cloud SSH key IDs permitted to log into the server."
  type        = list(string)
  default     = []
}

variable "tls_certificate_id" {
  description = "ID of a pre-uploaded Hetzner managed certificate (issue + upload before apply)."
  type        = string
}

variable "dns_zone_id" {
  description = "Hetzner DNS zone ID. Empty disables the DNS record creation; manage the record externally."
  type        = string
  default     = ""
}

variable "compliancekit_version" {
  description = "Tag of the compliancekit release to install."
  type        = string
  default     = "v1.15.0"
}

# ─── Server + cloud-init ───────────────────────────────────────

resource "random_password" "postgres" {
  length  = 32
  special = false
}

locals {
  cloud_init = <<-CLOUDINIT
    #cloud-config
    package_update: true
    packages: [curl, ca-certificates, jq, postgresql, postgresql-contrib]
    write_files:
      - path: /etc/systemd/system/compliancekit.service
        content: |
          [Unit]
          Description=compliancekit daemon
          After=network-online.target postgresql.service
          Wants=network-online.target
          Requires=postgresql.service
          [Service]
          Type=simple
          User=compliancekit
          Group=compliancekit
          Environment=CK_DB_DSN=postgres://compliancekit:${random_password.postgres.result}@127.0.0.1:5432/compliancekit?sslmode=disable
          ExecStart=/usr/local/bin/compliancekit serve --addr 0.0.0.0 --port 8080 --db $${CK_DB_DSN}
          Restart=always
          RestartSec=5
          [Install]
          WantedBy=multi-user.target
    runcmd:
      - sudo -u postgres psql -c "CREATE USER compliancekit WITH PASSWORD '${random_password.postgres.result}';"
      - sudo -u postgres psql -c "CREATE DATABASE compliancekit OWNER compliancekit;"
      - useradd --system --user-group --create-home --home-dir /var/lib/compliancekit --shell /usr/sbin/nologin compliancekit
      - curl -fsSL https://github.com/darpanzope/compliancekit/releases/download/${var.compliancekit_version}/compliancekit_${replace(var.compliancekit_version, "v", "")}_linux_amd64.tar.gz | tar xz -C /tmp
      - install -m 0755 /tmp/compliancekit /usr/local/bin/compliancekit
      - systemctl daemon-reload && systemctl enable --now compliancekit
  CLOUDINIT
}

resource "hcloud_server" "daemon" {
  name        = "compliancekit"
  image       = "ubuntu-24.04"
  server_type = var.server_type
  location    = var.location
  ssh_keys    = var.ssh_key_ids
  user_data   = local.cloud_init
  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }
}

resource "hcloud_firewall" "daemon" {
  name = "compliancekit"
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "22"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "8080"
    source_ips = ["0.0.0.0/0", "::/0"] # LB lives outside the firewall's view; HC LB->target traffic always allowed by HC
  }
  apply_to {
    server = hcloud_server.daemon.id
  }
}

# ─── Load balancer ─────────────────────────────────────────────

resource "hcloud_load_balancer" "main" {
  name               = "compliancekit"
  load_balancer_type = "lb11"
  location           = var.location
}

resource "hcloud_load_balancer_target" "daemon" {
  type             = "server"
  load_balancer_id = hcloud_load_balancer.main.id
  server_id        = hcloud_server.daemon.id
  use_private_ip   = false
}

resource "hcloud_load_balancer_service" "https" {
  load_balancer_id = hcloud_load_balancer.main.id
  protocol         = "https"
  listen_port      = 443
  destination_port = 8080
  http {
    certificates = [var.tls_certificate_id]
  }
  health_check {
    protocol = "http"
    port     = 8080
    interval = 15
    timeout  = 10
    retries  = 3
    http {
      path = "/health"
    }
  }
}

# ─── DNS (optional) ────────────────────────────────────────────

resource "hetznerdns_record" "main" {
  count   = var.dns_zone_id == "" ? 0 : 1
  zone_id = var.dns_zone_id
  name    = split(".", var.domain)[0]
  type    = "A"
  value   = hcloud_load_balancer.main.ipv4
  ttl     = 300
}

output "endpoint"    { value = "https://${var.domain}" }
output "server_ipv4" { value = hcloud_server.daemon.ipv4_address }
output "lb_ipv4"     { value = hcloud_load_balancer.main.ipv4 }
