# v1.15 phase 5 — AWS Terraform module for compliancekit.
#
# Provisions:
#   - One t4g.small EC2 instance running the compliancekit systemd
#     unit (cloud-init pulls the latest release tarball + drops it
#     at /usr/local/bin/compliancekit).
#   - An RDS Postgres 16 instance (multi-AZ when var.multi_az = true).
#   - A security group permitting only the ALB + an operator CIDR
#     into the instance.
#   - An ALB with HTTPS termination + the configured ACM cert.
#   - Route 53 A record pointing the domain at the ALB.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

# ─── Inputs ──────────────────────────────────────────────────────

variable "domain" {
  description = "Fully qualified domain the daemon is served at (e.g. compliancekit.example.com)."
  type        = string
}

variable "route53_zone_id" {
  description = "Hosted zone ID for the domain's parent zone."
  type        = string
}

variable "acm_certificate_arn" {
  description = "ARN of an ACM certificate covering var.domain (issue in advance via aws_acm_certificate)."
  type        = string
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "Target VPC."
  type        = string
}

variable "subnet_ids" {
  description = "At least two subnet IDs across distinct AZs for the ALB + RDS multi-AZ standby."
  type        = list(string)
}

variable "instance_type" {
  description = "EC2 instance type."
  type        = string
  default     = "t4g.small"
}

variable "rds_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.small"
}

variable "multi_az" {
  description = "Enable RDS multi-AZ."
  type        = bool
  default     = true
}

variable "compliancekit_version" {
  description = "Tag of the compliancekit release to install (e.g. v1.15.0)."
  type        = string
  default     = "v2.0.1"
}

variable "operator_cidrs" {
  description = "CIDRs permitted to SSH to the EC2 instance."
  type        = list(string)
  default     = []
}

# ─── Networking + security ──────────────────────────────────────

resource "aws_security_group" "alb" {
  name        = "compliancekit-alb"
  description = "ALB ingress (TCP 443 from the internet)."
  vpc_id      = var.vpc_id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "daemon" {
  name        = "compliancekit-daemon"
  description = "Compliancekit EC2 instance — accepts 8080 from ALB + 22 from operator CIDRs."
  vpc_id      = var.vpc_id
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.operator_cidrs
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ─── RDS Postgres ───────────────────────────────────────────────

resource "random_password" "postgres" {
  length  = 32
  special = false
}

resource "aws_db_subnet_group" "main" {
  name       = "compliancekit"
  subnet_ids = var.subnet_ids
}

resource "aws_db_instance" "postgres" {
  identifier              = "compliancekit"
  engine                  = "postgres"
  engine_version          = "16"
  instance_class          = var.rds_instance_class
  allocated_storage       = 50
  max_allocated_storage   = 200
  storage_type            = "gp3"
  storage_encrypted       = true
  username                = "compliancekit"
  password                = random_password.postgres.result
  db_name                 = "compliancekit"
  multi_az                = var.multi_az
  publicly_accessible     = false
  db_subnet_group_name    = aws_db_subnet_group.main.name
  vpc_security_group_ids  = [aws_security_group.daemon.id]
  skip_final_snapshot     = false
  final_snapshot_identifier = "compliancekit-final-${formatdate("YYYY-MM-DD", timestamp())}"
  backup_retention_period = 7
  deletion_protection     = true
}

# ─── EC2 instance ──────────────────────────────────────────────

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-*"]
  }
}

locals {
  cloud_init = <<-CLOUDINIT
    #cloud-config
    package_update: true
    packages: [curl, ca-certificates, jq]
    write_files:
      - path: /etc/systemd/system/compliancekit.service
        permissions: '0644'
        content: |
          [Unit]
          Description=compliancekit daemon
          After=network-online.target
          Wants=network-online.target
          [Service]
          Type=simple
          User=compliancekit
          Group=compliancekit
          Environment=CK_DB_DSN=postgres://compliancekit:${random_password.postgres.result}@${aws_db_instance.postgres.address}:5432/compliancekit?sslmode=require
          ExecStart=/usr/local/bin/compliancekit serve --addr 127.0.0.1 --port 8080 --db $${CK_DB_DSN}
          Restart=always
          RestartSec=5
          [Install]
          WantedBy=multi-user.target
    runcmd:
      - useradd --system --user-group --create-home --home-dir /var/lib/compliancekit --shell /usr/sbin/nologin compliancekit
      - mkdir -p /var/lib/compliancekit && chown compliancekit:compliancekit /var/lib/compliancekit
      - curl -fsSL https://github.com/darpanzope/compliancekit/releases/download/${var.compliancekit_version}/compliancekit_${replace(var.compliancekit_version, "v", "")}_linux_arm64.tar.gz | tar xz -C /tmp
      - install -m 0755 /tmp/compliancekit /usr/local/bin/compliancekit
      - systemctl daemon-reload
      - systemctl enable --now compliancekit
  CLOUDINIT
}

resource "aws_instance" "daemon" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_ids[0]
  vpc_security_group_ids = [aws_security_group.daemon.id]
  user_data              = local.cloud_init
  metadata_options {
    http_tokens = "required"
  }
  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
  }
  tags = {
    Name        = "compliancekit"
    Application = "compliancekit"
  }
}

# ─── ALB + Route 53 ─────────────────────────────────────────────

resource "aws_lb" "main" {
  name               = "compliancekit"
  load_balancer_type = "application"
  subnets            = var.subnet_ids
  security_groups    = [aws_security_group.alb.id]
}

resource "aws_lb_target_group" "daemon" {
  name        = "compliancekit"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "instance"
  health_check {
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 15
  }
}

resource "aws_lb_target_group_attachment" "daemon" {
  target_group_arn = aws_lb_target_group.daemon.arn
  target_id        = aws_instance.daemon.id
  port             = 8080
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.daemon.arn
  }
}

resource "aws_route53_record" "main" {
  zone_id = var.route53_zone_id
  name    = var.domain
  type    = "A"
  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

# ─── Outputs ────────────────────────────────────────────────────

output "endpoint" {
  description = "https URL of the deployed daemon."
  value       = "https://${var.domain}"
}

output "db_address" {
  description = "RDS endpoint hostname."
  value       = aws_db_instance.postgres.address
  sensitive   = true
}

output "instance_id" {
  description = "EC2 instance ID."
  value       = aws_instance.daemon.id
}
