# terraform-aws-compliancekit

Provisions the daemon end-to-end on AWS: EC2 + RDS Postgres + ALB +
Route 53.

## Usage

```hcl
module "compliancekit" {
  source = "github.com/darpanzope/compliancekit//deploy/terraform/aws?ref=v1.15.0"

  domain              = "compliancekit.example.com"
  route53_zone_id     = "Z01234..."
  acm_certificate_arn = "arn:aws:acm:us-east-1:...:certificate/..."

  region     = "us-east-1"
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.a.id, aws_subnet.b.id, aws_subnet.c.id]

  multi_az              = true
  operator_cidrs        = ["203.0.113.0/24"]  # office IP for SSH
  compliancekit_version = "v1.15.0"
}

output "url" { value = module.compliancekit.endpoint }
```

## What's provisioned

| Layer | Resource | Notes |
|---|---|---|
| Edge | `aws_lb` (ALB) + `aws_lb_listener` (443/TLS) + `aws_route53_record` | TLS 1.2/1.3 only |
| Compute | `aws_instance` (`t4g.small` ARM) + cloud-init systemd unit | Ubuntu 24.04 LTS, root EBS encrypted |
| State | `aws_db_instance` Postgres 16 (`db.t4g.small`, gp3, encrypted, multi-AZ, 7-day backups, deletion_protection) | |
| Security | Two security groups (ALB-only + operator-SSH ingress) | IMDSv2 required |

## Defaults

* Compute: `t4g.small` (2 vCPU, 2 GiB; ARM). Bump to `t4g.medium`
  if you scan more than ~50 resources / hour.
* DB: `db.t4g.small` (2 vCPU, 2 GiB; ARM), multi-AZ, gp3, 50 GiB
  autoscaling to 200 GiB, encrypted at rest, 7-day automated
  backups, deletion_protection ON.
* Edge: ALB with TLS 1.2-2021-06 policy, HTTP-only health checks
  to `/health`.

## DNS + certs

* `route53_zone_id` is the parent zone; the module creates a
  single A-alias record at `var.domain`.
* `acm_certificate_arn` must be issued + validated in advance
  via `aws_acm_certificate` + `aws_acm_certificate_validation`
  (use a `*.example.com` wildcard cert or pre-issue an exact-
  match cert).

## State storage

This module uses no backend — wrap it in a root module with your
remote state config (S3 + DynamoDB lock is the canonical AWS
shape).

## Updating

```sh
# Bump the daemon version
terraform apply -var=compliancekit_version=v1.15.1
# Cloud-init re-runs on instance replacement; otherwise SSH to
# upgrade in-place + restart the systemd unit.
```

The cleanest path: roll the EC2 instance whenever the daemon
version changes (taint + apply). RDS state survives the rebuild.
