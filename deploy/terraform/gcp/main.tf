# v1.15 phase 5 — GCP Terraform module for compliancekit.
#
# Provisions:
#   - A Compute Engine `e2-small` instance running the compliancekit
#     systemd unit via cloud-init.
#   - A Cloud SQL Postgres 16 instance (regional HA when var.regional
#     = true).
#   - A regional managed-SSL Google Load Balancer (HTTPS) fronting
#     the instance.
#   - A Cloud DNS A record pointing the domain at the LB.

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.30"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

variable "project" {
  description = "GCP project ID."
  type        = string
}

variable "region" {
  description = "GCP region."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone for the compute instance."
  type        = string
  default     = "us-central1-a"
}

variable "domain" {
  description = "Fully qualified domain the daemon is served at."
  type        = string
}

variable "dns_managed_zone" {
  description = "Cloud DNS managed zone name (not the DNS name)."
  type        = string
}

variable "machine_type" {
  description = "Compute Engine machine type."
  type        = string
  default     = "e2-small"
}

variable "db_tier" {
  description = "Cloud SQL tier."
  type        = string
  default     = "db-custom-1-3840"
}

variable "regional" {
  description = "Enable Cloud SQL regional HA (synchronous standby in another zone)."
  type        = bool
  default     = true
}

variable "compliancekit_version" {
  description = "Tag of the compliancekit release to install."
  type        = string
  default     = "v1.15.0"
}

# ─── Cloud SQL ──────────────────────────────────────────────────

resource "random_password" "postgres" {
  length  = 32
  special = false
}

resource "google_sql_database_instance" "main" {
  name             = "compliancekit"
  database_version = "POSTGRES_16"
  region           = var.region
  settings {
    tier              = var.db_tier
    availability_type = var.regional ? "REGIONAL" : "ZONAL"
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      backup_retention_settings { retained_backups = 14 }
    }
    ip_configuration {
      ipv4_enabled    = false
      private_network = data.google_compute_network.default.id
    }
  }
  deletion_protection = true
}

resource "google_sql_database" "main" {
  instance = google_sql_database_instance.main.name
  name     = "compliancekit"
}

resource "google_sql_user" "main" {
  instance = google_sql_database_instance.main.name
  name     = "compliancekit"
  password = random_password.postgres.result
}

data "google_compute_network" "default" {
  name = "default"
}

# ─── Compute Engine ─────────────────────────────────────────────

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
          Environment=CK_DB_DSN=postgres://compliancekit:${random_password.postgres.result}@${google_sql_database_instance.main.private_ip_address}:5432/compliancekit?sslmode=require
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

resource "google_compute_instance" "daemon" {
  name         = "compliancekit"
  machine_type = var.machine_type
  zone         = var.zone
  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      size  = 20
    }
  }
  network_interface {
    network    = data.google_compute_network.default.name
    access_config {}
  }
  metadata = {
    user-data = local.cloud_init
  }
  tags = ["compliancekit"]
}

# ─── HTTPS Load Balancer ────────────────────────────────────────

resource "google_compute_managed_ssl_certificate" "main" {
  name = "compliancekit-cert"
  managed {
    domains = [var.domain]
  }
}

resource "google_compute_global_address" "main" {
  name = "compliancekit-ip"
}

resource "google_compute_instance_group" "daemon" {
  name      = "compliancekit-ig"
  zone      = var.zone
  instances = [google_compute_instance.daemon.id]
  named_port {
    name = "http"
    port = 8080
  }
}

resource "google_compute_health_check" "daemon" {
  name = "compliancekit-hc"
  http_health_check {
    port         = 8080
    request_path = "/health"
  }
}

resource "google_compute_backend_service" "daemon" {
  name                  = "compliancekit-be"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTP"
  port_name             = "http"
  health_checks         = [google_compute_health_check.daemon.id]
  backend {
    group = google_compute_instance_group.daemon.self_link
  }
}

resource "google_compute_url_map" "main" {
  name            = "compliancekit-urlmap"
  default_service = google_compute_backend_service.daemon.id
}

resource "google_compute_target_https_proxy" "main" {
  name             = "compliancekit-https"
  url_map          = google_compute_url_map.main.id
  ssl_certificates = [google_compute_managed_ssl_certificate.main.id]
}

resource "google_compute_global_forwarding_rule" "main" {
  name                  = "compliancekit-fr"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.main.id
  ip_address            = google_compute_global_address.main.address
}

resource "google_dns_record_set" "main" {
  name         = "${var.domain}."
  managed_zone = var.dns_managed_zone
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_global_address.main.address]
}

output "endpoint" { value = "https://${var.domain}" }
output "db_address" {
  value     = google_sql_database_instance.main.private_ip_address
  sensitive = true
}
