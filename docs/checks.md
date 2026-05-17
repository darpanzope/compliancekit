# Check catalog

<!--
  AUTO-GENERATED FILE -- DO NOT EDIT BY HAND.
  Regenerate with: make docs
  Source of truth: internal/checks/**/*.go (the core.Check vars).
-->

This catalog is generated from the live registry on each release. At the current revision, compliancekit ships **482 checks** across the providers below.

Each check below has:

- A stable **ID** (the string CI gates and waiver files reference).
- A **severity** in {`critical`, `high`, `medium`, `low`, `info`}.
- A list of **framework controls** it maps to (SOC 2 TSC, ISO 27001:2022 Annex A, CIS Controls v8).
- A **description** of the underlying concern.
- A copy-pastable **remediation** for the typical hosting setup.

To inspect a single check from the CLI: `compliancekit checks show <id>`.

## By provider

| Provider | Checks |
|---|---:|
| `aws` | 30 |
| `digitalocean` | 144 |
| `gcp` | 25 |
| `hetzner` | 15 |
| `kubernetes` | 149 |
| `linux` | 119 |
| **total** | **482** |

## By severity

| Severity | Checks |
|---|---:|
| `critical` | 18 |
| `high` | 120 |
| `medium` | 196 |
| `low` | 148 |

## aws

### `aws-cloudtrail-enabled`

**At least one CloudTrail trail must be actively logging** &middot; severity `high` &middot; service `cloudtrail` &middot; resource `aws.account`

CloudTrail is the API audit log for AWS. Without an active trail, post-incident investigation cannot answer who called what API, when, or from where. CIS AWS Foundations 3.1 prescribes at least one trail covering every region, actively logging.

_Remediation:_

> Create a trail: 'aws cloudtrail create-trail --name <name> --s3-bucket-name <bucket> --is-multi-region-trail --enable-log-file-validation' then 'aws cloudtrail start-logging --name <name>'. Ensure the S3 bucket has tight access controls.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.10` | Retain Audit Logs |
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.2` | System Component Monitoring |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `audit-logging`, `cloudtrail`

---

### `aws-cloudtrail-log-file-validation`

**CloudTrail trails must have log file validation enabled** &middot; severity `medium` &middot; service `cloudtrail` &middot; resource `aws.cloudtrail.trail`

Log file validation publishes a SHA-256 digest of every hour's log batch to a separate file in the same S3 bucket. The digest is signed with an account-specific private key whose public counterpart is stored by AWS. Without it, post-tamper detection of log files is not possible. CIS AWS Foundations 3.2.

_Remediation:_

> Enable: 'aws cloudtrail update-trail --name <name> --enable-log-file-validation'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `cloudtrail`, `integrity`

---

### `aws-cloudtrail-multi-region`

**At least one CloudTrail trail must be multi-region** &middot; severity `medium` &middot; service `cloudtrail` &middot; resource `aws.account`

A single-region trail misses API calls in every other region the account uses, including the global IAM, S3, and CloudFront APIs. A multi-region trail captures the entire account. CIS AWS Foundations 3.1 prescribes at least one multi-region trail.

_Remediation:_

> Convert: 'aws cloudtrail update-trail --name <name> --is-multi-region-trail'. If you have multiple single-region trails, consolidating to one multi-region trail reduces cost and improves forensic coverage.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit-logging`, `cloudtrail`, `multi-region`

---

### `aws-config-delivery-channel`

**AWS Config must have a delivery channel configured** &middot; severity `low` &middot; service `config` &middot; resource `aws.config.region`

Config's recorder produces a stream of events; the delivery channel is the S3 bucket (and optional SNS topic) those events get written to. Without a delivery channel the recorder records into the void -- the audit trail is invisible to the operator.

_Remediation:_

> Configure a delivery channel: 'aws configservice put-delivery-channel --delivery-channel ...'. The S3 bucket should be in the same region and tightly access-controlled.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.10` | Retain Audit Logs |
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit-logging`, `config`

---

### `aws-config-recorder-on`

**AWS Config must be enabled in every region** &middot; severity `medium` &middot; service `config` &middot; resource `aws.config.region`

AWS Config records resource state changes over time, providing the change-log a forensic investigation needs to answer 'when did this resource look the way it did?' Without it, the answer is 'we don't know.' CIS AWS Foundations 3.5 prescribes a recorder in every region.

_Remediation:_

> Enable Config in the region: AWS Console -> Config -> Get started, or via CLI: 'aws configservice put-configuration-recorder --configuration-recorder ... --recording-group ...' then 'aws configservice start-configuration-recorder --configuration-recorder-name ...'. Consider an org-level Config aggregator if you scan many accounts.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.2` | System Component Monitoring |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `audit-logging`, `change-tracking`, `config`

---

### `aws-ec2-ebs-encrypted`

**EBS volumes must be encrypted at rest** &middot; severity `high` &middot; service `ec2` &middot; resource `aws.ec2.volume`

EBS volumes hold the persistent data attached to EC2 instances. Encryption at rest defends against snapshot disclosure and disk reuse. AWS lets you enable default encryption per region so new volumes are encrypted automatically; this check catches existing volumes that pre-date that flag. CIS AWS Foundations 2.2.

_Remediation:_

> Create a snapshot of the unencrypted volume, copy the snapshot with --encrypted, restore a new volume from the encrypted snapshot, detach the old volume from the instance, and attach the new one. Enable the region-wide default ('aws ec2 enable-ebs-encryption-by-default') so future volumes are encrypted automatically.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `data-at-rest`, `ebs`, `ec2`, `encryption`

---

### `aws-ec2-imdsv2-required`

**EC2 instances must require IMDSv2** &middot; severity `high` &middot; service `ec2` &middot; resource `aws.ec2.instance`

Instance Metadata Service v2 requires session-token authentication for every metadata request, which defeats the SSRF + IMDSv1 = credential exfiltration attack that has produced multiple high-profile cloud breaches (e.g. Capital One 2019). CIS AWS Foundations 5.6 mandates IMDSv2 on every running instance.

_Remediation:_

> Enforce IMDSv2: 'aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-endpoint enabled'. For new instances bake this into launch templates and AMI defaults.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `ec2`, `metadata-service`, `ssrf`

---

### `aws-ec2-no-default-vpc-in-use`

**EC2 instances must not run in the default VPC** &middot; severity `medium` &middot; service `ec2` &middot; resource `aws.ec2.instance`

AWS provisions a default VPC in every region with overly permissive defaults: every subnet is public, the default security group allows all egress, and instances launched without explicit network config land here. Production workloads belong in a purpose-built VPC with private subnets and explicit ingress/egress rules.

_Remediation:_

> Build a new VPC ('aws ec2 create-vpc --cidr-block 10.0.0.0/16'), create private subnets across two AZs, set up NAT for outbound, then migrate workloads. Consider deleting the default VPC in every region with no workloads ('aws ec2 delete-vpc --vpc-id <default-vpc>').

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `ec2`, `network`, `vpc`

---

### `aws-ec2-no-public-amis`

**AMIs owned by this account must not be public** &middot; severity `high` &middot; service `ec2` &middot; resource `aws.ec2.ami`

Public AMIs are visible to every AWS account. A public AMI may leak baked-in secrets (credentials in cloud-init, hardcoded API keys in software), internal IP schemes, and a complete list of installed software an attacker can fingerprint for vulnerabilities. Public AMIs are only appropriate for software the organization explicitly distributes to other AWS users.

_Remediation:_

> Mark the AMI private: 'aws ec2 modify-image-attribute --image-id <ami-id> --launch-permission Remove='[{"Group":"all"}]'. Review the AMI's installed software for any leaked secrets before continuing to use it; an exposed AMI is a credential-disclosure incident.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `cis-v8` | `3.4` | Enforce Data Retention |
| `iso27001` | `A.8.12` | Data leakage prevention |
| `iso27001` | `A.8.3` | Information access restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `ami`, `data-exposure`, `ec2`

---

### `aws-ec2-sg-no-ingress-from-any`

**EC2 security groups must not allow ingress from 0.0.0.0/0 except on 80/443** &middot; severity `high` &middot; service `ec2` &middot; resource `aws.ec2.security_group`

Security groups with 0.0.0.0/0 (or ::/0) ingress expose every port they cover to the entire internet. SSH (22), RDP (3389), and database ports are the high-leverage attacker targets; only HTTP (80) and HTTPS (443) have any business being open to all. CIS AWS Foundations 5.2 (ingress from any to administrative ports) and 5.3 (default SGs allow all egress).

_Remediation:_

> Narrow the source CIDR to the actual caller: 'aws ec2 revoke-security-group-ingress --group-id <id> --protocol tcp --port 22 --cidr 0.0.0.0/0' then re-authorize with the office or VPN CIDR. For long-running access prefer SSM Session Manager over open-port SSH.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.21` | Security of network services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `ec2`, `exposure`, `network`

---

### `aws-guardduty-enabled`

**GuardDuty must be enabled in every region** &middot; severity `high` &middot; service `guardduty` &middot; resource `aws.guardduty.region`

GuardDuty is AWS's managed threat-detection service. It analyzes VPC Flow Logs, CloudTrail, and DNS logs for known IOCs and behavioral anomalies -- credential exfiltration, crypto-mining workloads, communication with known C2 endpoints. CIS AWS Foundations 3.10 prescribes GuardDuty in every region.

_Remediation:_

> Enable: 'aws guardduty create-detector --enable'. Consider organization-level GuardDuty for multi-account coverage. Wire findings into a SIEM or compliancekit ingest at v0.13 once the OCSF ingest path ships.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `13.1` | Centralize Security Event Alerting |
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.2` | System Component Monitoring |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `guardduty`, `threat-detection`

---

### `aws-iam-access-key-age`

**IAM user access keys must be rotated within 90 days** &middot; severity `high` &middot; service `iam` &middot; resource `aws.iam.user`

Long-lived access keys are the source of the majority of AWS breaches in the public record. Rotating them every 90 days limits the blast radius of an undetected disclosure. CIS AWS Foundations Benchmark 1.14.

_Remediation:_

> Run 'aws iam list-access-keys --user-name <name>' to find the key, create a replacement, deploy it everywhere, then deactivate the old key (aws iam update-access-key --status Inactive) before deleting it. Consider rotating to short-lived STS credentials via role assumption instead of long-lived keys.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `credentials`, `iam`, `rotation`

---

### `aws-iam-console-user-mfa`

**IAM users with console access must have MFA enabled** &middot; severity `high` &middot; service `iam` &middot; resource `aws.iam.user`

Console-enabled IAM users without MFA are the most common AWS breach vector after leaked access keys. The password reduces to a single factor an attacker only needs to phish once. CIS AWS Foundations Benchmark 1.10.

_Remediation:_

> Have the user sign in and enable MFA at IAM -> Users -> Security credentials -> Multi-factor authentication. Enforce organisationally via an IAM policy with 'aws:MultiFactorAuthPresent: true' on the actions that matter.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.3` | Require MFA for Externally-Exposed Applications |
| `cis-v8` | `6.5` | Require MFA for Administrative Access |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `console`, `iam`, `mfa`

---

### `aws-iam-no-star-inline-policies`

**IAM inline policies must not grant `*:*` permissions** &middot; severity `high` &middot; service `iam` &middot; resource `aws.iam.user`

An inline policy with Action='*' and Resource='*' grants the user the equivalent of root on the account. Such policies are a common shortcut during incident response that gets forgotten. CIS AWS Foundations Benchmark 1.17 (full-administrative privileges).

_Remediation:_

> Replace the inline policy with a least-privilege managed policy and attach it via group/role: 'aws iam delete-user-policy --user-name <user> --policy-name <name>', then create a scoped policy with only the actions the user actually needs.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `audit-risk`, `iam`, `least-privilege`

---

### `aws-iam-no-user-managed-policies`

**IAM policies must attach to groups or roles, not users** &middot; severity `low` &middot; service `iam` &middot; resource `aws.iam.user`

Attaching managed policies directly to IAM users scatters permission management across user accounts; group / role attachments consolidate it. CIS AWS Foundations Benchmark 1.16 prescribes no direct user-managed-policy attachments. (Inline policies on users are covered by a separate check.)

_Remediation:_

> Move the policy to an IAM group: 'aws iam create-group --group-name <name>', 'aws iam attach-group-policy', then 'aws iam add-user-to-group --user-name <user> --group-name <group>', finally 'aws iam detach-user-policy --user-name <user> --policy-arn <arn>'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `governance`, `iam`, `least-privilege`

---

### `aws-iam-password-policy`

**AWS account must enforce a strong password policy** &middot; severity `medium` &middot; service `iam` &middot; resource `aws.account`

A strong password policy raises the cost of brute-force and credential-stuffing attacks. The AWS account password policy applies to IAM users with console access. CIS AWS Foundations Benchmark 1.8 prescribes minimum length 14, requires lowercase / uppercase / numbers / symbols, reuse prevention >= 24, max age <= 90 days.

_Remediation:_

> Sign in to IAM, navigate to Account settings -> Password policy, and set: minimum length 14, require all character classes, prevent reuse of last 24, expire after 90 days, allow users to change own password.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.2` | Use Unique Passwords |
| `cis-v8` | `6.3` | Require MFA for Externally-Exposed Applications |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `iam`, `password-policy`

---

### `aws-iam-root-access-key`

**AWS root account must have no access keys** &middot; severity `critical` &middot; service `iam` &middot; resource `aws.account`

The AWS root account has un-revokable permissions across every service. Access keys for root cannot be scoped, cannot be rotated to a least-privilege subset, and leak the entire account on disclosure. CIS AWS Foundations Benchmark 1.4 prescribes that no access keys exist for root.

_Remediation:_

> Sign in as root, navigate to IAM -> My security credentials -> Access keys, and delete every key. Use IAM users + roles for any programmatic access instead.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `cis-v8` | `6.5` | Require MFA for Administrative Access |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `credentials`, `iam`, `root`

---

### `aws-iam-root-mfa`

**AWS root account must have MFA enabled** &middot; severity `high` &middot; service `iam` &middot; resource `aws.account`

MFA on the root account is the single most effective control against root-account takeover. Without MFA, root reduces to a password the attacker only needs to phish once. CIS AWS Foundations Benchmark 1.5.

_Remediation:_

> Sign in as root, navigate to IAM -> My security credentials -> Multi-factor authentication, and activate a virtual or hardware MFA device. Prefer a hardware key (YubiKey) for production accounts.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.3` | Require MFA for Externally-Exposed Applications |
| `cis-v8` | `6.5` | Require MFA for Administrative Access |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `iam`, `mfa`, `root`

---

### `aws-iam-unused-users`

**IAM users inactive for 90 days must be removed** &middot; severity `medium` &middot; service `iam` &middot; resource `aws.iam.user`

Dormant IAM users are an attack surface with no business benefit. CIS AWS Foundations Benchmark 1.13 prescribes removing users with no activity for 90 days. Consider quarterly access reviews to flag candidates for removal.

_Remediation:_

> Confirm with the user's manager that the account is no longer needed, then delete it: 'aws iam delete-user --user-name <name>' after deleting access keys, MFA devices, and policies attached to that user.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.3` | Disable Dormant Accounts |
| `cis-v8` | `6.2` | Establish an Access Revoking Process |
| `iso27001` | `A.5.16` | Identity management |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `iam`, `least-privilege`, `lifecycle`

---

### `aws-kms-cmk-rotation`

**Customer-managed symmetric KMS keys must have rotation enabled** &middot; severity `medium` &middot; service `kms` &middot; resource `aws.kms.key`

KMS key rotation automatically rotates the underlying cryptographic material every year, capping the exposure window of any leaked key. Only customer-managed symmetric keys support rotation; AWS-managed and asymmetric keys are out of scope for this check. Pending-deletion keys are also skipped (rotation during pending-deletion would be misleading). CIS AWS Foundations 3.8.

_Remediation:_

> Enable: 'aws kms enable-key-rotation --key-id <key-id>'. Rotation is free and transparent to applications; the old key material remains decryptable for already-encrypted data.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `encryption`, `kms`, `rotation`

---

### `aws-kms-no-pending-deletion`

**Customer-managed KMS keys must not be pending deletion** &middot; severity `high` &middot; service `kms` &middot; resource `aws.kms.key`

A KMS key in PendingDeletion state will be permanently deleted at the end of its waiting window (7-30 days, default 30). Once deleted, all data encrypted with that key becomes undecryptable forever. This check catches in-flight deletes before the window closes -- the cost of catching one false positive is trivial, the cost of missing one true positive is catastrophic.

_Remediation:_

> Cancel the deletion: 'aws kms cancel-key-deletion --key-id <key-id>'. Then audit who scheduled it and why; that's almost always an incident worth investigating.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `iso27001` | `A.8.13` | Information backup |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `data-loss`, `kms`

---

### `aws-rds-backup-retention`

**RDS DB instances must have backup retention >= 7 days** &middot; severity `medium` &middot; service `rds` &middot; resource `aws.rds.instance`

Automated backups are RDS's point-in-time recovery mechanism. BackupRetentionPeriod=0 disables them entirely; values < 7 days reduce the recovery window below the industry-standard floor for production data.

_Remediation:_

> Set retention: 'aws rds modify-db-instance --db-instance-identifier <name> --backup-retention-period 7 --apply-immediately'. For production-tier data consider 30 days.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.8.13` | Information backup |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `backup`, `rds`, `recovery`

---

### `aws-rds-deletion-protection`

**RDS DB instances must have deletion protection enabled** &middot; severity `medium` &middot; service `rds` &middot; resource `aws.rds.instance`

Deletion protection is a guard against the worst-case operator-error / compromised-credential outcome: a single 'aws rds delete-db-instance' call destroying customer data. With protection on, the call fails with an explicit error and forces the operator to disable protection first. CIS AWS Foundations 2.3.2.

_Remediation:_

> Enable: 'aws rds modify-db-instance --db-instance-identifier <name> --deletion-protection --apply-immediately'. Set as a default in IaC modules so new instances inherit it.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `iso27001` | `A.8.13` | Information backup |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `guard-rail`, `lifecycle`, `rds`

---

### `aws-rds-encrypted`

**RDS DB instances must be encrypted at rest** &middot; severity `high` &middot; service `rds` &middot; resource `aws.rds.instance`

RDS storage encryption at rest is a checkbox at creation time that cannot be retroactively flipped on an existing instance. Without it, RDS snapshots, replicas, and underlying storage carry unencrypted customer data. CIS AWS Foundations 2.3.1.

_Remediation:_

> Encryption cannot be enabled in-place. Snapshot the instance, copy the snapshot with --kms-key-id specified, restore the encrypted snapshot to a new instance, then cut over via DNS or connection strings. For new instances always set --storage-encrypted at create-time.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `data-at-rest`, `encryption`, `rds`

---

### `aws-rds-not-publicly-accessible`

**RDS DB instances must not be publicly accessible** &middot; severity `critical` &middot; service `rds` &middot; resource `aws.rds.instance`

A publicly accessible RDS instance receives a public DNS name and is reachable from the internet (subject to security group rules). Combined with a permissive SG, this is the most common path to a database breach. Production databases belong in private subnets, reachable only from application security groups inside the VPC. CIS AWS Foundations 2.3.3.

_Remediation:_

> Set the instance to private: 'aws rds modify-db-instance --db-instance-identifier <name> --no-publicly-accessible --apply-immediately'. Update the security group to allow ingress only from the application tier.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.21` | Security of network services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `exposure`, `network`, `rds`

---

### `aws-s3-default-encryption`

**S3 buckets must have default server-side encryption** &middot; severity `high` &middot; service `s3` &middot; resource `aws.s3.bucket`

Default encryption ensures every object written to the bucket is encrypted at rest without requiring the caller to set the header. SSE-S3 (AES256) is the minimum; SSE-KMS gives per-key audit trails for sensitive data. AWS has enabled SSE-S3 by default on new buckets since January 2023 but pre-existing buckets retain their original setting. CIS AWS Foundations 2.1.2.

_Remediation:_

> Enable default encryption: 'aws s3api put-bucket-encryption --bucket <name> --server-side-encryption-configuration '"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'. Use SSEAlgorithm=aws:kms for KMS-managed keys.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `data-at-rest`, `encryption`, `s3`

---

### `aws-s3-logging`

**S3 buckets must have server access logging enabled** &middot; severity `low` &middot; service `s3` &middot; resource `aws.s3.bucket`

Server access logs are the forensic trail when a bucket is the source of a security incident. Without them, 'who accessed this bucket at this timestamp' is unanswerable. CIS AWS Foundations 3.6 (formerly 2.6 in v1.x of the benchmark).

_Remediation:_

> Enable logging to a dedicated log-aggregation bucket: 'aws s3api put-bucket-logging --bucket <name> --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"<log-bucket>","TargetPrefix":"<prefix>/"}}'. The target bucket should NOT be the source bucket (creates a logging loop).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.10` | Retain Audit Logs |
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit-logging`, `forensics`, `s3`

---

### `aws-s3-no-public-acls`

**S3 buckets must not have public ACLs** &middot; severity `high` &middot; service `s3` &middot; resource `aws.s3.bucket`

S3 ACLs that grant the AllUsers or AuthenticatedUsers groups make a bucket publicly readable or writable. Combined with a misconfigured Public Access Block (PAB), this is the most common path to a public bucket. PAB is the safety net; this check catches buckets where PAB is off and an ACL has slipped public.

_Remediation:_

> Remove the public grant: 'aws s3api put-bucket-acl --bucket <name> --acl private'. If specific objects need to be public, prefer a least-privilege bucket policy over an ACL.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.3` | Information access restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `acl`, `data-exposure`, `s3`

---

### `aws-s3-public-access-block`

**S3 buckets must have Block Public Access fully enabled** &middot; severity `critical` &middot; service `s3` &middot; resource `aws.s3.bucket`

S3 Public Access Block is the account-and-bucket-level safety net against accidental data exposure: even if a bucket policy or ACL tries to grant public access, PAB overrides. All four flags (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) must be true. CIS AWS Foundations 2.1.1.

_Remediation:_

> Enable all four settings: 'aws s3api put-public-access-block --bucket <name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'. Consider account-level PAB ('aws s3control put-public-access-block --account-id ...') for defense-in-depth.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.3` | Information access restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `data-exposure`, `public-access`, `s3`

---

### `aws-s3-versioning`

**S3 buckets must have versioning enabled** &middot; severity `medium` &middot; service `s3` &middot; resource `aws.s3.bucket`

Bucket versioning preserves prior versions of every object, recovering from ransomware encryption-in-place, accidental deletion, and silent corruption. Versioning is a prerequisite for S3 Object Lock and MFA Delete -- enabling it now is the minimum viable backup story for S3.

_Remediation:_

> Enable versioning: 'aws s3api put-bucket-versioning --bucket <name> --versioning-configuration Status=Enabled'. Consider lifecycle rules to expire old non-current versions if storage cost is a concern.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.8.13` | Information backup |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `backup`, `recovery`, `s3`

---

## digitalocean

### `do-account-api-token-rotation-cadence`

**API tokens must be rotated on a documented cadence (≤90d)** &middot; severity `high` &middot; service `account` &middot; resource `digitalocean.account`

DO API tokens are long-lived bearer credentials. The DO public API does not expose token creation dates, scopes, or last-use time — the dashboard is the only audit surface. SOC2 CC6.3 + ISO A.5.16 + CIS 5.4 each require documented rotation intervals (typically ≤90 days) and revocation of unused tokens. This finding records the control gap so the auditor knows to gather rotation logs.

_Remediation:_

> Cloud Panel → API → Tokens. Sort by 'Last Used'; revoke any token unused for >30 days, and any token older than 90 days regardless of last-use. Issue replacements via the same page; update consumers; capture the before/after roster as audit evidence.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.16` | Identity management |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `account`, `credentials`, `manual-verify`

---

### `do-account-audit-log-retention`

**Account audit logs must be retained ≥90 days** &middot; severity `high` &middot; service `account` &middot; resource `digitalocean.account`

Audit logs document every team-member action against control-plane resources. DigitalOcean's audit log is available only via the dashboard (no public API endpoint at the time of writing) and the default retention is ≤30 days on most tiers. SOC2 CC7.2, ISO A.8.15, and CIS 8.1 each require ≥90 days of log retention with tamper-evident storage. This finding records the control gap.

_Remediation:_

> Cloud Panel → Settings → Audit Logs. Confirm logs are enabled and retention is ≥90 days. If retention is below policy, enable the audit-log-export integration (Splunk / Datadog / S3) to extend retention beyond the in-platform default. Capture configuration as audit evidence.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.1` | Establish and Maintain an Audit Log Management Process |
| `cis-v8` | `8.10` | Retain Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `account`, `audit-trail`, `manual-verify`

---

### `do-account-billing-alert-thresholds`

**Monthly billing alerts must be configured at documented thresholds** &middot; severity `medium` &middot; service `account` &middot; resource `digitalocean.account`

DigitalOcean's billing-alerts surface is dashboard-only; no public API exposes the configured monthly threshold or recipient roster. An unaccompanied invoice doubling — typical of a runaway autoscaler or unauthorized resource provisioning — is a financial AND security signal. SOC2 A1.2 requires capacity alerts that catch budget anomalies before billing close.

_Remediation:_

> Cloud Panel → Settings → Billing → Alerts. Set monthly alert at 80% and 100% of expected spend; route to finance + engineering distribution lists, not a single inbox. Document the threshold and recipients in the runbook.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.1` | Ensure Network Infrastructure is Up-to-Date |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |

_Tags:_ `account`, `billing`, `manual-verify`

---

### `do-account-droplet-quota-headroom`

**Droplet usage must leave >20% headroom against the account limit** &middot; severity `medium` &middot; service `account` &middot; resource `digitalocean.account`

DO sets a per-account droplet_limit; bumping against it means new droplets fail to provision — autoscalers stall, recovery flows can't spin replacements, blue/green deploys break. Production accounts should stay below 80% utilization so a sudden burst (incident response, traffic spike) has runway.

_Remediation:_

> Two paths: (1) request a quota bump — 'doctl account ratelimit' shows your support contact and the cloud panel has a quota increase form. (2) Prune orphan droplets via 'doctl compute droplet list --format ID,Name,Status,Created' and delete anything stale.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.1` | Ensure Network Infrastructure is Up-to-Date |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `account`, `capacity`

---

### `do-account-email-verified`

**DigitalOcean account email must be verified** &middot; severity `medium` &middot; service `account` &middot; resource `digitalocean.account`

Email verification is the prerequisite for billing alerts, password-reset flows, and 2FA recovery codes being delivered to the right inbox. An unverified email means every account-recovery story falls back to support tickets, which is too slow for incident response.

_Remediation:_

> Open the verification email DO sent at signup. If missing, log in and request a fresh one from Settings > Account. Change the address first if the current one is compromised or a personal inbox -- production accounts should point at a role-based address (eg. ops@example.com) with at least two readers.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.1` | Establish an Access Granting Process |
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.16` | Identity management |
| `iso27001` | `A.5.17` | Authentication information |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `account`, `identity`

---

### `do-account-mfa-required`

**Account must require two-factor authentication for all members** &middot; severity `critical` &middot; service `account` &middot; resource `digitalocean.account`

Mandatory 2FA across every team member is table stakes for any audit framework (SOC2 CC6.1, ISO A.5.16, CIS 6.5). DigitalOcean enforces this via the team settings UI but does not expose enforcement state in the public API — every audit therefore requires manual evidence: a screenshot of the team Security page showing the toggle on plus a roster of members with 2FA enabled. This finding records the control gap so the auditor knows to gather that evidence.

_Remediation:_

> Cloud Panel → Settings → Security → 'Require two-factor authentication'. Toggle on. Confirm every team member has 2FA enrolled (Members tab → 2FA column). Record screenshot evidence alongside this report.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.5` | Require MFA for Administrative Access |
| `iso27001` | `A.5.16` | Identity management |
| `iso27001` | `A.5.17` | Authentication information |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `account`, `identity`, `manual-verify`

---

### `do-account-monitoring-alert-coverage`

**Account should have enabled alerts for CPU, memory, disk, and load** &middot; severity `medium` &middot; service `monitoring` &middot; resource `digitalocean.account`

Beyond 'at least one alert exists', SOC2 CC7.2 and ISO A.8.16 expect coverage across the four primary droplet vitals: CPU, memory, disk, and load. A monitoring posture missing any of these leaves blind spots that page operators too late.

_Remediation:_

> Create the missing alert types. Example for CPU: 'doctl monitoring alert create --type v1/insights/droplet/cpu --description "high cpu" --compare GreaterThan --value 80 --window 5m --emails ops@example.com'. Repeat for memory, disk, and load with thresholds appropriate to your workloads.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.2` | System Component Monitoring |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `alerting`, `monitoring`

---

### `do-account-owner-delegation-policy`

**Owner-delegation policy must be documented (bus-factor ≥2)** &middot; severity `high` &middot; service `account` &middot; resource `digitalocean.account`

DigitalOcean does not expose team-owner change history or delegation procedures via API. A single owner = bus-factor 1 across billing, member-management, and account-deletion — the highest-blast-radius operations on the platform. SOC2 CC1.4 and ISO A.5.2 require segregation-of-duties + at least one documented delegate.

_Remediation:_

> Cloud Panel → Settings → Team → Members. Confirm ≥2 members carry the 'Owner' role (or that an explicit succession policy is recorded with co-administrator credentials). Document the delegation procedure in the security runbook and review quarterly.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.7` | Centralize Access Control |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.5.2` | Information security roles and responsibilities |
| `soc2` | `CC1.4` | Commitment to Competence |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `account`, `bus-factor`, `manual-verify`

---

### `do-account-reserved-ip-quota-headroom`

**Reserved-IP usage must leave >20% headroom** &middot; severity `low` &middot; service `account` &middot; resource `digitalocean.account`

Reserved IPs are the basis for static-IP services and failover patterns. Hitting reserved_ip_limit during an incident means the failover script can't allocate the replacement IP. The 80% headroom rule applies.

_Remediation:_

> Request a quota bump, OR free orphan reserved IPs ('doctl compute reserved-ip list --format IP,DropletID' — empty DropletID means assigned to nothing).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.1` | Ensure Network Infrastructure is Up-to-Date |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `account`, `capacity`, `networking`

---

### `do-account-status-active`

**DigitalOcean account must be in 'active' status** &middot; severity `high` &middot; service `account` &middot; resource `digitalocean.account`

DigitalOcean's account.status field surfaces billing failures, ToS holds, and suspensions. A 'warning' or 'locked' account loses access to new droplet creation, snapshot restoration, and any recovery flow that depends on billing being current. Continuous compliance evidence becomes impossible to collect from a non-active account.

_Remediation:_

> Check the DO control panel for the operative warning. Common causes: expired payment method, exceeded prepaid balance, ToS dispute. Resolve before any subsequent compliance-relevant change; everything else in this report depends on the platform being responsive.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.1` | Establish and Maintain a Data Recovery Process |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `account`, `platform-health`

---

### `do-account-status-message-clean`

**Account.status_message must be empty** &middot; severity `high` &middot; service `account` &middot; resource `digitalocean.account`

DO sets status_message when the account is flagged for billing arrears, ToS review, or platform-team intervention. Any non-empty value is a signal the account is restricted; continuous-compliance evidence loses meaning while the flag is in place.

_Remediation:_

> Open the cloud panel banner DO shows when status_message is non-empty; resolve the root cause (failed payment method, ToS dispute, support ticket). Don't dismiss the banner without reading it.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.1` | Establish and Maintain a Data Recovery Process |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC2.1` | Obtains or Generates Relevant Quality Information |

_Tags:_ `account`, `platform-health`

---

### `do-account-uses-named-team`

**Production DigitalOcean accounts should use a named team** &middot; severity `low` &middot; service `account` &middot; resource `digitalocean.account`

DigitalOcean creates an implicit 'Personal' team for every new account. Running production workloads under the Personal team is single-user by definition -- if the operator is unavailable (sick, on leave, departed) there is no second party authorized to issue tokens, manage billing, or rotate credentials. A named team with at least two members is the minimum bus-factor.

_Remediation:_

> Create a team via 'doctl invoice list --team <name>' workflow or the Settings > Team UI. Move resources by transferring projects under the new team. Add at least one co-administrator. The Personal team can stay for non-prod experiments; the audit-relevant workloads belong on a real team.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.7` | Centralize Access Control |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.5.2` | Information security roles and responsibilities |
| `soc2` | `CC1.4` | Commitment to Competence |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `account`, `bus-factor`

---

### `do-account-volume-quota-headroom`

**Block-storage volume usage must leave >20% headroom** &middot; severity `medium` &middot; service `account` &middot; resource `digitalocean.account`

DO sets a per-account volume_limit. A volume exhaustion event is a hard-stop for any droplet that needs persistent storage attached on boot or after autoscaling. The same 80% headroom rule applies; account-level limits are easier to raise proactively than under incident pressure.

_Remediation:_

> Request a quota bump from the cloud panel, OR prune orphan volumes ('doctl compute volume list --format Name,DropletIDs,Size'). Volumes with empty DropletIDs are paying for storage attached to nothing.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.1` | Ensure Network Infrastructure is Up-to-Date |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `account`, `capacity`, `storage`

---

### `do-app-build-secret-scan`

**App Platform builds must scan for committed secrets** &middot; severity `high` &middot; service `apps` &middot; resource `digitalocean.app`

DO App Platform does not run secret-scanning as part of the build pipeline. A secret committed to the source repo becomes part of every deployed image, and is recoverable from the build cache for the lifetime of the cache. SOC2 CC6.7 requires credential hygiene; verify a pre-commit or CI step (gitleaks, trufflehog) runs against every PR.

_Remediation:_

> Add a CI step on the source repo BEFORE the DO build trigger: run 'gitleaks detect' or 'trufflehog filesystem .' and fail the CI on findings. Block deploy-on-push to apps whose CI lacks this gate.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `16.4` | Establish and Manage an Inventory of Third-Party Software Components |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `apps`, `manual-verify`, `secret-scan`

---

### `do-app-cdn-attachment`

**Public-facing apps should consider DO Spaces CDN for static asset delivery** &middot; severity `low` &middot; service `apps` &middot; resource `digitalocean.app`

App Platform serves static assets directly from the app container, charging full bandwidth + CPU. Offloading to a Spaces+CDN attachment cuts cost + latency. The App spec doesn't carry CDN integration state, so this is manual.

_Remediation:_

> Move static assets to a Spaces bucket; enable the CDN attachment on the bucket (do-cdn-no-custom-domain check covers the CDN side). Update the app to reference the CDN endpoint for asset URLs.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.1` | Ensure Network Infrastructure is Up-to-Date |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `soc2` | `A1.1` | Capacity Management |

_Tags:_ `apps`, `cdn`, `manual-verify`, `performance`

---

### `do-app-database-not-production-marked`

**App Platform databases must be marked production** &middot; severity `medium` &middot; service `apps` &middot; resource `digitalocean.app`

App Platform databases default to dev_database = true (shared/free tier). production: true upgrades to a dedicated managed cluster with HA + automated backups. Production workloads on dev databases lose data on any control-plane event.

_Remediation:_

> In the app spec, set 'databases: [{name: ..., engine: PG, production: true, cluster_name: <managed-db-cluster>}]'. Plan a cutover: dev DBs are not backed up, so manual dump+restore to the new cluster is required.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.8.13` | Information backup |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `apps`, `database`, `production`

---

### `do-app-deploy-on-push-no-branch-protection`

**Deploy-on-push services must target protected branches** &middot; severity `high` &middot; service `apps` &middot; resource `digitalocean.app`

Deploy-on-push means a git push to the source branch triggers a production deployment. Without branch protection (required reviews, status checks) on the source side, any git collaborator can ship to production without review. The App spec carries the branch name but the GitHub/GitLab branch-protection state is on the source side, not DO's API.

_Remediation:_

> GitHub: Settings → Branches → add a protection rule on the deploy branch (require ≥1 review, require status checks). GitLab: Settings → Repository → Protected Branches. Document the deploy branch + protection rules in the runbook.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `16.1` | Establish and Maintain a Secure Application Development Process |
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.32` | Change management |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `apps`, `deploy-on-push`, `manual-verify`

---

### `do-app-domain-cert-rotation`

**Custom-domain certs must auto-renew (Let's Encrypt or uploaded with auto-rotation)** &middot; severity `medium` &middot; service `apps` &middot; resource `digitalocean.app`

App Platform Let's Encrypt certs auto-renew. Uploaded certs do not — they expire silently and break HTTPS for the custom domain. The DO API does not expose 'is this cert DO-managed or uploaded' on a custom domain at runtime; the operator must confirm via the dashboard or by issuing every cert through Let's Encrypt at create time.

_Remediation:_

> Either: (1) ensure every custom domain uses Let's Encrypt — declare the domain in the app spec without a cert_id, which triggers DO-managed Let's Encrypt. (2) For uploaded certs, set a renewal calendar reminder ≥30d before expiry.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `apps`, `cert-rotation`, `manual-verify`, `tls`

---

### `do-app-domain-tls-below-1-3`

**App Platform custom domains should enforce TLS 1.3** &middot; severity `medium` &middot; service `apps` &middot; resource `digitalocean.app`

Existing do-app-domain-weak-tls flags TLS < 1.2. v0.19 phase 5 raises the floor to 1.3 for production-grade domains. TLS 1.2 remains supported but 1.3 is the current state of the art (forward-secrecy by default, fewer cipher choices, mandatory AEAD).

_Remediation:_

> Update the App spec domain block: 'domains: [{domain: ..., minimum_tls_version: "1.3"}]'. Verify clients don't break — TLS 1.3 is universally supported across browsers + tools released after 2020.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `apps`, `domain`, `tls`

---

### `do-app-domain-weak-tls`

**App Platform custom domains must require TLS 1.2 or higher** &middot; severity `medium` &middot; service `apps` &middot; resource `digitalocean.app`

App Platform domains expose a minimum_tls_version setting per domain. Default at v1.2 today; explicitly setting "1.2" or "1.3" makes the policy auditable. Empty or "1.0"/"1.1" is the regression-prone shape.

_Remediation:_

> In each domain block under the app spec, set minimum_tls_version: "1.2" (or "1.3" for modern apps with no legacy client requirements). Apply via 'doctl apps update'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `app-platform`, `tls`

---

### `do-app-no-alerts`

**App Platform apps should have alerts configured** &middot; severity `low` &middot; service `apps` &middot; resource `digitalocean.app`

Alerts on App Platform apps fire on deploy failure, crash loop, or restart rate. Without them an app can fail silently with the only signal being the user complaint. Configure at least DEPLOYMENT_FAILED + RESTART_COUNT.

_Remediation:_

> Add alerts to the app spec: 'alerts: - rule: DEPLOYMENT_FAILED' etc. The DO docs list the available rule types; pair with a notification destination (slack, email).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.2` | System Component Monitoring |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `alerting`, `app-platform`

---

### `do-app-no-custom-domain`

**Production App Platform apps should have a custom domain** &middot; severity `low` &middot; service `apps` &middot; resource `digitalocean.app`

App Platform apps default to the ondigitalocean.app subdomain. Production apps should serve from a custom domain for branding, certificate ownership, and DNS-level traffic control. No custom domain is fine for dev/preview deployments but a posture-anti-pattern for prod.

_Remediation:_

> Add a domain in the App spec under 'domains:'. Point your DNS at the app's CNAME and DO will provision a managed Let's Encrypt cert automatically.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `app-platform`, `branding`

---

### `do-app-no-vpc`

**App Platform apps should bind to a VPC** &middot; severity `low` &middot; service `apps` &middot; resource `digitalocean.app`

App Platform supports binding the egress side of an app to a specific VPC so the app can reach private droplets or managed DBs via private addressing. Apps without a VPC bind can only reach public endpoints -- forcing prod DB connections through the public internet.

_Remediation:_

> Add a vpc: block to the app spec naming the target VPC. Applies on next deployment.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `app-platform`, `network`

---

### `do-app-plain-env-vars`

**App Platform apps must mark secrets as SECRET type** &middot; severity `high` &middot; service `apps` &middot; resource `digitalocean.app`

App Platform variable definitions have a type field: GENERAL (plaintext, visible in spec) or SECRET (encrypted at rest, never returned). Storing API keys / DB passwords / OAuth secrets as GENERAL plaintext leaks them to anyone with app:read permission on the project. Mark every credential SECRET.

_Remediation:_

> Edit the app spec, change type from GENERAL to SECRET on every credential-bearing env var. Either through the DO control panel or 'doctl apps spec' + 'doctl apps update'. After the change, rotate any credential that was previously plaintext -- assume it was logged somewhere.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.1` | Establish and Maintain a Data Management Process |
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `iso27001` | `A.5.17` | Authentication information |
| `iso27001` | `A.8.10` | Information deletion |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `app-platform`, `secrets`

---

### `do-app-services-no-healthcheck`

**Every App Platform service must declare a HealthCheck** &middot; severity `high` &middot; service `apps` &middot; resource `digitalocean.app`

Without a HealthCheck declaration App Platform falls back to TCP-port liveness — a hung process that still holds the socket is treated as healthy. SOC2 A1.2 and ISO A.8.16 expect explicit liveness probes on production services.

_Remediation:_

> Add a http_path-based HealthCheck per service in the app spec: 'health_check: {http_path: /healthz}'. Pair with a liveness endpoint that exercises critical dependencies (database connection, downstream API).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |

_Tags:_ `apps`, `healthcheck`

---

### `do-app-services-no-log-destinations`

**App Platform services should forward logs to a long-retention sink** &middot; severity `medium` &middot; service `apps` &middot; resource `digitalocean.app`

App Platform's built-in log viewer retains ~7 days of logs — insufficient for audit (SOC2 CC7.2 expects ≥90d). The app spec's 'log_destinations:' block forwards to Papertrail, Datadog, Logtail, or a generic OpenSearch endpoint.

_Remediation:_

> Add a log_destinations block per service: 'log_destinations: [{name: prod, datadog: {api_key: $DD_KEY, endpoint: ...}}]'. Pair with a sink that meets the retention SLA.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `apps`, `logging`, `retention`

---

### `do-app-services-no-service-alerts`

**App Platform services should each declare their own alerts** &middot; severity `medium` &middot; service `apps` &middot; resource `digitalocean.app`

App-level alerts (covered by do-app-no-alerts) catch deploy + domain events. Service-level alerts catch per-service behavior: CPU > X, restart count > Y, request latency > Z. SOC2 CC7.2 expects per-component monitoring; a single app-level alert isn't sufficient for multi-service apps.

_Remediation:_

> Add 'alerts:' to each service spec with at minimum DEPLOYMENT_FAILED + CPU_UTILIZATION + MEM_UTILIZATION rules.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `alerts`, `apps`, `per-service`

---

### `do-app-tier-below-production`

**Apps tagged production should run on professional tier or above** &middot; severity `medium` &middot; service `apps` &middot; resource `digitalocean.app`

Basic-tier App Platform shares droplet pools and lacks the autoscaling + per-tenant isolation production typically needs. SOC2 A1.1 + ISO A.8.14 expect production capacity planning; the tier slug is the simplest proxy.

_Remediation:_

> Bump to a professional tier: 'doctl apps update <id> --spec spec.yaml' with 'tier_slug: professional-xs' (or higher). Migration is online; expect a redeploy.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.1` | Capacity Management |

_Tags:_ `apps`, `capacity`, `tier`

---

### `do-billing-cdn-traffic-cost`

**CDN traffic cost must be tracked monthly** &middot; severity `low` &middot; service `billing` &middot; resource `digitalocean.account`

DO Spaces CDN bills egress separately from origin storage. A misconfigured cache (TTL=0, no Cache-Control headers) multiplies origin hits + CDN cost.

_Remediation:_

> Monthly: review CDN bandwidth in the billing breakout. If unexpected: audit cache headers + TTL on the CDN config.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.1` | Ensure Network Infrastructure is Up-to-Date |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `soc2` | `A1.1` | Capacity Management |

_Tags:_ `billing`, `cdn`, `manual-verify`

---

### `do-billing-cost-breakout-documented`

**Per-project cost breakout must be exportable monthly** &middot; severity `low` &middot; service `billing` &middot; resource `digitalocean.account`

DO exposes invoices via API but not per-project cost breakout; finance teams typically need that for chargeback.

_Remediation:_

> Monthly: pull the invoice CSV from the dashboard, sort by project tag, archive in finance shared drive.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.1` | Ensure Network Infrastructure is Up-to-Date |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |

_Tags:_ `billing`, `manual-verify`

---

### `do-billing-database-pause-audit`

**Paused managed databases are still billed; audit retention** &middot; severity `medium` &middot; service `billing` &middot; resource `digitalocean.account`

DO managed databases bill in 'offline' (paused) state at standard rate. Pause-and-forget is a common waste pattern.

_Remediation:_

> Quarterly: list `doctl databases list`; for any in offline state, decide resume vs delete.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.1` | Ensure Network Infrastructure is Up-to-Date |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `soc2` | `A1.1` | Capacity Management |

_Tags:_ `billing`, `manual-verify`

---

### `do-billing-monthly-alert-review`

**Monthly billing alert thresholds + recipients reviewed** &middot; severity `medium` &middot; service `billing` &middot; resource `digitalocean.account`

Billing alert thresholds + recipient roster need quarterly review — costs grow, headcount changes, alerts go stale. DO doesn't expose the alert config via API.

_Remediation:_

> Quarterly: open the billing dashboard, confirm thresholds still match the budget, confirm distros still resolve.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.1` | Ensure Network Infrastructure is Up-to-Date |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |

_Tags:_ `billing`, `manual-verify`

---

### `do-billing-payment-method-valid`

**Primary payment method must not be near expiry** &middot; severity `high` &middot; service `billing` &middot; resource `digitalocean.account`

An expired card pauses the account; account status drops to warning. DO doesn't expose card-expiry via API.

_Remediation:_

> Quarterly: confirm the card on file has ≥3 months until expiry. Add a backup method.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.1` | Ensure Network Infrastructure is Up-to-Date |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |

_Tags:_ `billing`, `manual-verify`

---

### `do-billing-reserved-commitments-reviewed`

**DO Reserved (1y/3y) commitments reviewed against utilization** &middot; severity `low` &middot; service `billing` &middot; resource `digitalocean.account`

DO reserved pricing is opt-in; without periodic review you either miss savings or over-commit on workloads that have moved.

_Remediation:_

> Quarterly: compare reserved-instance attribution vs actual droplet usage. Cancel under-utilized reservations.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.1` | Ensure Network Infrastructure is Up-to-Date |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `soc2` | `A1.1` | Capacity Management |

_Tags:_ `billing`, `manual-verify`

---

### `do-billing-snapshot-retention-policy`

**Snapshot retention policy must be documented + enforced** &middot; severity `low` &middot; service `billing` &middot; resource `digitalocean.account`

DO snapshots accumulate forever at $0.05/GB/month. Without a documented retention SLA, the snapshot bill grows unbounded.

_Remediation:_

> Document retention (e.g. 90d for ad-hoc, 1y for release baselines). Implement via cron: `doctl compute snapshot list --format ID,Created` + age-based delete.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.5.34` | Privacy and protection of PII |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `billing`, `manual-verify`, `snapshots`

---

### `do-cdn-no-custom-cert`

**CDN endpoints with custom domains should use a custom cert** &middot; severity `medium` &middot; service `cdn` &middot; resource `digitalocean.cdn`

A CDN with a custom domain but no attached certificate serves the domain over HTTP only or relies on the DO default cert which doesn't cover your apex. Pair every custom domain with a managed (Let's Encrypt) or uploaded certificate.

_Remediation:_

> Create a managed cert via 'doctl compute certificate create --type lets_encrypt --domains cdn.example.com'. Update the CDN: 'doctl compute cdn update <id> --certificate-id <id>'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `cdn`, `tls`

---

### `do-cdn-no-custom-domain`

**CDN endpoints should use a custom domain** &middot; severity `medium` &middot; service `cdn` &middot; resource `digitalocean.cdn`

A CDN endpoint without a custom domain serves traffic on the ondigitaloceanspaces.com subdomain. Production traffic should resolve under your domain so DNS-level controls (CAA, DNSSEC) apply and the user-visible URL matches your brand.

_Remediation:_

> Configure a custom domain via 'doctl compute cdn update <id> --custom-domain cdn.example.com --certificate-id <cert-id>' and point your DNS at the CDN's endpoint.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `cdn`

---

### `do-certificate-near-expiry`

**Certificates should not expire within 30 days** &middot; severity `high` &middot; service `certificates` &middot; resource `digitalocean.certificate`

A cert that expires in less than 30 days is in the renewal-or-outage window. DO managed certs auto-renew but the renewal needs DNS / file-system access that might be broken; uploaded certs need a human to refresh. 30 days is the industry-standard cushion that gives an incident response team time to find the problem.

_Remediation:_

> Managed certs (type=lets_encrypt): verify the cert's DNS challenge can still resolve and reach DO. Uploaded certs: rotate. 'doctl compute certificate create --type lets_encrypt --domains <names>' creates a new managed cert ready to swap into LB forwarding rules.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `expiry`, `tls`

---

### `do-certificate-uploaded-not-managed`

**Uploaded certificates should be reviewed for migration to managed** &middot; severity `low` &middot; service `certificates` &middot; resource `digitalocean.certificate`

Custom (uploaded) certificates require a human-driven renewal cycle. DO's managed certs (Let's Encrypt) auto-renew every 90 days with zero operator involvement. For LB-attached certs without an EV / wildcard requirement, managed is the strictly safer default -- one fewer thing to fall off the on-call backlog.

_Remediation:_

> If the cert protects domains DO can DNS-challenge, create a managed equivalent and swap: 'doctl compute certificate create --type lets_encrypt --domains <names>'. For wildcard or EV certs that require purchased provenance, document the manual-rotation procedure and assign an owner.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `managed-cert`, `renewal`, `tls`

---

### `do-db-engine-eol`

**Managed databases should not run EOL engine versions** &middot; severity `medium` &middot; service `databases` &middot; resource `digitalocean.database`

DO accepts older engine versions at create time but once an engine version is upstream-EOL, security patches stop. Examples: Postgres 13 is EOL Nov 2025; MySQL 5.7 is EOL Oct 2023. Running these means the DB is missing fixes that will never ship.

_Remediation:_

> Upgrade in place: 'doctl databases upgrade-major <db-id> --version <new>'. Always take a backup first. Plan for application-side compatibility testing.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `2.2` | Ensure Authorized Software is Currently Supported |
| `cis-v8` | `7.4` | Perform Automated Application Patch Management |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |

_Tags:_ `database`, `eol`, `patching`

---

### `do-db-firewall-includes-public`

**Managed databases must not allow public CIDRs in trusted sources** &middot; severity `critical` &middot; service `databases` &middot; resource `digitalocean.database`

A trusted-source rule of type ip_addr with value 0.0.0.0/0 or ::/0 is the explicit shape of 'allow the entire internet.' This is the catastrophic database misconfiguration; it leaves TLS + password as the only defense against everyone who can find your hostname (which is on a predictable do-managed namespace).

_Remediation:_

> Remove the public rule: 'doctl databases firewalls remove <db-id> --uuid <rule-uuid>'. Replace with narrow droplet/tag/cluster references.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.5` | Implement and Manage a Firewall on End-User Devices |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `catastrophic`, `database`, `network-exposure`

---

### `do-db-ip-only-trust`

**Managed databases should trust named resources, not raw IPs** &middot; severity `low` &middot; service `databases` &middot; resource `digitalocean.database`

Trusted-source rules of type ip_addr break silently when droplets are recreated and get new IPs. Named references (droplet:<id>, tag:<name>, k8s:<cluster-id>) survive recreation; IPs need manual update on every droplet rotation. Mixing both is fine; relying only on IPs is fragile.

_Remediation:_

> Convert ip_addr rules to droplet/tag refs: 'doctl databases firewalls append <db-id> --rule droplet:<id>'. Remove the corresponding ip_addr rule.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `iso27001` | `A.8.31` | Separation of development, test, and production environments |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `database`, `operations`

---

### `do-db-no-firewall-rules`

**Managed databases should have at least one trusted source** &middot; severity `critical` &middot; service `databases` &middot; resource `digitalocean.database`

DO managed databases default to a public hostname + port. The trusted-sources allowlist (DatabaseFirewallRule) is what restricts inbound. An empty list means the DB is open to every IP the DO platform accepts -- effectively the public internet, modulo TLS + password.

_Remediation:_

> Restrict to your droplet, K8s cluster, or tag: 'doctl databases firewalls append <db-id> --rule droplet:<id>' (or 'tag:<tag>', 'k8s:<cluster-id>', or 'ip_addr:<cidr>').

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `database`, `network-exposure`

---

### `do-db-no-maintenance-window`

**Managed databases should have a configured maintenance window** &middot; severity `low` &middot; service `databases` &middot; resource `digitalocean.database`

Without an explicit maintenance window, DO chooses one based on the DB's region default. If the default lands during your business hours, scheduled patches cause unexpected outages. Set an explicit off-hours window.

_Remediation:_

> 'doctl databases maintenance-window update <db-id> --day sunday --hour 02:00'. Pick a low-traffic window for your application.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.3` | Perform Automated Operating System Patch Management |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.5` | Recovery from Security Incidents |

_Tags:_ `database`, `operations`, `patching`

---

### `do-db-no-vpc`

**Managed databases must belong to a VPC** &middot; severity `medium` &middot; service `databases` &middot; resource `digitalocean.database`

A managed DB without a VPC sits on the legacy region-wide private network shared by every droplet -- the private endpoint isn't private anymore. Recreating in a VPC restores the segmentation guarantee.

_Remediation:_

> Recreate the DB inside a named VPC. DO does not support changing the VPC after creation; the migration is app-downtime + restore-from-backup. Schedule accordingly.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `database`, `network`, `segmentation`

---

### `do-db-single-node`

**Production databases should run with replicas** &middot; severity `low` &middot; service `databases` &middot; resource `digitalocean.database`

A single-node managed DB has no HA story: any host- or zone-level failure takes the DB offline until DO reschedules. Multi-node clusters (DO supports up to 3-node high-availability) survive single-host failure transparently. Skip for dev/staging.

_Remediation:_

> Scale up: 'doctl databases resize <db-id> --num-nodes 2' (or 3 for high-availability clusters). Plan a brief maintenance window; DO promotes a standby and the failover is fast but not instant.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.3` | Protect Recovery Data |
| `iso27001` | `A.8.13` | Information backup |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC7.5` | Recovery from Security Incidents |

_Tags:_ `availability`, `database`

---

### `do-db-tls-disabled`

**Managed databases must require TLS on public endpoints** &middot; severity `high` &middot; service `databases` &middot; resource `digitalocean.database`

The connection.ssl flag toggles whether the public endpoint accepts unencrypted connections. With ssl=false, a DB user's password is sent in plaintext over the wire on every connection -- catastrophic for any DB reachable from anywhere other than localhost.

_Remediation:_

> DO managed DBs ship with TLS support but the per-DB override on this flag can disable it. Verify in the DO control panel under Settings > Connection Details; require SSL for all users.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `database`, `encryption-in-transit`, `tls`

---

### `do-domain-caa-no-iodef`

**CAA records should declare an iodef= contact** &middot; severity `low` &middot; service `domains` &middot; resource `digitalocean.domain`

RFC 8659 'iodef' tag in a CAA record gives CAs a mailto:/URL to use when they reject an issuance request. Without iodef, CA-side rejections (e.g. domain validation failures from rogue Let's Encrypt requests) are invisible to the operator. The tag adds zero attack surface; missing it is hygiene.

_Remediation:_

> Add a CAA record: '0 iodef "mailto:secops@example.com"' alongside the existing 'issue "letsencrypt.org"' records.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.3` | Perform Automated Operating System Patch Management |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `caa`, `domains`, `reporting`, `tls`

---

### `do-domain-caa-wildcard`

**CAA records should name specific CAs, not allow any** &middot; severity `low` &middot; service `domains` &middot; resource `digitalocean.domain`

A CAA record with a literal ';' or empty value effectively says 'any CA may issue.' This is better than no CAA at all (CAA-aware receivers honor the syntax) but defeats the point of CAA. Name your CAs explicitly: letsencrypt.org for managed certs, digicert.com / sectigo.com for purchased certs.

_Remediation:_

> Replace the wildcard CAA entry with explicit issuers. Audit existing records: 'doctl compute domain records list <domain> --format Type,Name,Data | grep CAA'. Remove the wildcard, add explicit issue/issuewild entries for the CAs you actually use.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `ca-hygiene`, `dns`, `tls`

---

### `do-domain-dkim-no-selector`

**DKIM selector record(s) must be present** &middot; severity `high` &middot; service `domains` &middot; resource `digitalocean.domain`

DKIM signs outgoing mail with a public key published at <selector>._domainkey.<domain>. Without at least one DKIM selector, DMARC 'pass' relies on SPF alignment alone — and any mail forwarded through an intermediary breaks the SPF chain. DKIM survives forwarding; SPF generally does not.

_Remediation:_

> Issue a key pair (typically RSA-2048) and publish the public key as a TXT record at '<selector>._domainkey'. Common selectors: 'google' (Google Workspace), 'k1' (Mailgun), 'pm' (Postmark), '<custom>' if rolling your own MTA. Rotate selectors annually with overlapping validity.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `9.4` | Restrict Unnecessary or Unauthorized Browser and Email Client Extensions |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `dkim`, `domains`, `email-auth`

---

### `do-domain-dmarc-no-rua`

**DMARC rua= (aggregate reporting) must be configured** &middot; severity `medium` &middot; service `domains` &middot; resource `digitalocean.domain`

Without rua= a domain receives no aggregate DMARC reports — every receiver evaluates the policy in silence. Aggregate reports are the only feedback loop for catching misconfigured senders BEFORE enforcement starts dropping legitimate mail.

_Remediation:_

> Append 'rua=mailto:dmarc-reports@yourdomain.com' to the _dmarc record. Common consumers: dmarcian, Postmark DMARC, Valimail, in-house parser into ELK.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `9.4` | Restrict Unnecessary or Unauthorized Browser and Email Client Extensions |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `dmarc`, `domains`, `reporting`

---

### `do-domain-dmarc-no-ruf`

**DMARC ruf= (forensic reporting) should be configured** &middot; severity `low` &middot; service `domains` &middot; resource `digitalocean.domain`

ruf= asks receivers to forward forensic copies of failing messages. Coverage is patchy (Gmail does not honor ruf), but where it works it provides per-incident detail aggregate reports lack. Severity is low — ruf is best-effort, not a hard requirement.

_Remediation:_

> Append 'ruf=mailto:dmarc-forensics@yourdomain.com' to the _dmarc record. Use a dedicated mailbox; forensic reports can include PII from message bodies.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `9.4` | Restrict Unnecessary or Unauthorized Browser and Email Client Extensions |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `best-effort`, `dmarc`, `domains`, `reporting`

---

### `do-domain-dmarc-pct-not-full`

**DMARC pct= should be 100 once monitoring is complete** &middot; severity `low` &middot; service `domains` &middot; resource `digitalocean.domain`

DMARC 'pct=' controls the percentage of messages subjected to the policy. During rollout, operators may stage pct=10 → pct=50 → pct=100. A production domain that's been on enforcement >30 days should be at pct=100 (or omit pct, which defaults to 100). Staying at lower pct indefinitely is a half-finished rollout.

_Remediation:_

> Raise pct stepwise as monitoring confirms no legitimate senders are caught. Target: pct=100 or omit the tag entirely.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `9.4` | Restrict Unnecessary or Unauthorized Browser and Email Client Extensions |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `dmarc`, `domains`, `rollout`

---

### `do-domain-dmarc-policy-not-strict`

**DMARC policy must be quarantine or reject** &middot; severity `high` &middot; service `domains` &middot; resource `digitalocean.domain`

A DMARC record with 'p=none' is a monitoring posture — receivers report failures but do nothing with them. Production domains should advance to 'p=quarantine' (mail to junk) or 'p=reject' (drop) once monitoring shows legitimate senders are DKIM/SPF-aligned. SOC2 CC6.7 + ISO A.8.20 + DMARC.org all recommend an enforcement policy.

_Remediation:_

> Update the _dmarc TXT record. Phase: start with 'p=quarantine; pct=10', monitor aggregate reports for 2 weeks, raise pct in 25% steps. Final state: 'p=reject; pct=100'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `9.4` | Restrict Unnecessary or Unauthorized Browser and Email Client Extensions |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `dmarc`, `domains`, `email-auth`

---

### `do-domain-dmarc-subdomain-policy`

**DMARC sp= (subdomain policy) must be set** &middot; severity `medium` &middot; service `domains` &middot; resource `digitalocean.domain`

Without an explicit 'sp=' tag, subdomains inherit the parent's 'p=' — but only when 'sp=' is unset. Some receivers interpret missing sp= as 'unenforced'. Set sp= explicitly to 'quarantine' or 'reject' (typically the same as p=) so subdomain spoofing is caught regardless of receiver interpretation.

_Remediation:_

> Append 'sp=reject;' to the _dmarc TXT record (or 'sp=quarantine' if you're not at p=reject yet).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `9.4` | Restrict Unnecessary or Unauthorized Browser and Email Client Extensions |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `dmarc`, `domains`, `subdomain`

---

### `do-domain-dnssec-via-registrar`

**DNSSEC must be enabled at the registrar (DO does not manage DS records)** &middot; severity `high` &middot; service `domains` &middot; resource `digitalocean.domain`

DigitalOcean managed DNS does NOT serve signed zones — DS records and zone signing happen at the registrar level. This is a hard limitation, not a misconfiguration. SOC2 CC6.7 and ISO A.8.20 require DNSSEC where the operating environment supports it; for DO this means verifying DS records at the registrar AND keeping the chain-of-trust intact when DO's nameservers change. This finding records the gap so the auditor can capture registrar-side evidence.

_Remediation:_

> At the registrar (Namecheap / Gandi / Cloudflare etc.): enable DNSSEC for the domain, generate / accept the DS record. Verify chain-of-trust via 'dig +dnssec example.com' (must see AD flag) or https://dnssec-analyzer.verisignlabs.com. Capture a screenshot of the registrar DNSSEC status for the audit pack.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `9.4` | Restrict Unnecessary or Unauthorized Browser and Email Client Extensions |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `dnssec`, `domains`, `manual-verify`, `unsupported`

---

### `do-domain-no-caa`

**Managed domains should publish a CAA record** &middot; severity `medium` &middot; service `domains` &middot; resource `digitalocean.domain`

A CAA (Certification Authority Authorization) record declares which public CAs may issue certificates for the domain. Without it, any CA in the public trust store can issue a cert against a successful HTTP/DNS challenge, which a compromised DNS account or an MITM during validation can abuse. CAA is the cheapest single mitigation against rogue issuance.

_Remediation:_

> Publish a CAA record naming your CAs of record. For DO Managed Certs (which use Let's Encrypt): 'doctl compute domain records create <domain> --record-type CAA --record-name @ --record-flags 0 --record-tag issue --record-data letsencrypt.org'. Add additional CAs as needed.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `ca-hygiene`, `dns`, `tls`

---

### `do-domain-no-dmarc`

**Mail-sending domains should publish DMARC** &middot; severity `medium` &middot; service `domains` &middot; resource `digitalocean.domain`

A domain with MX but no DMARC (TXT record on _dmarc.<domain>) tells receivers 'I have no opinion about what to do with mail that fails authentication.' Combined with SPF + DKIM, DMARC publishes the reject/quarantine policy that closes the spoofing loop.

_Remediation:_

> Add a TXT record on _dmarc.<domain>. Start in reporting-only mode: 'v=DMARC1; p=none; rua=mailto:dmarc@example.com'. Once you see clean reports for two weeks, harden to 'p=quarantine' then 'p=reject'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `9.1` | Ensure Use of Only Fully Supported Browsers and Email Clients |
| `cis-v8` | `9.2` | Use DNS Filtering Services |
| `iso27001` | `A.5.14` | Information transfer |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `dns`, `email-auth`, `spoofing`

---

### `do-domain-no-spf`

**Mail-sending domains should publish SPF** &middot; severity `medium` &middot; service `domains` &middot; resource `digitalocean.domain`

A domain with an MX record but no SPF (a TXT record on the apex starting 'v=spf1') is trivially spoofable -- the receiver has no policy to consult and any sender claiming to be the domain gets a fair hearing. SPF is the minimum email sender-policy a domain can publish; DMARC + DKIM stack on top.

_Remediation:_

> Add a TXT record on the apex publishing your SPF policy. Minimum: 'v=spf1 -all' to declare 'no mail from this domain.' If you send mail, list your senders: 'v=spf1 include:_spf.mx.example.com -all'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `9.1` | Ensure Use of Only Fully Supported Browsers and Email Clients |
| `cis-v8` | `9.2` | Use DNS Filtering Services |
| `iso27001` | `A.5.14` | Information transfer |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `dns`, `email-auth`, `spoofing`

---

### `do-domain-spf-not-strict-fail`

**SPF must end in -all (hard fail), not ~all or ?all** &middot; severity `high` &middot; service `domains` &middot; resource `digitalocean.domain`

The terminating qualifier in SPF determines what happens to messages NOT matched by any prior mechanism. '-all' is hard fail (drop); '~all' is soft fail (mark as suspicious); '?all' is neutral. Production domains should use '-all' once SPF coverage is verified — anything weaker undermines downstream DMARC enforcement.

_Remediation:_

> Change the trailing qualifier in the root TXT record from '~all'/'?all'/'+all' to '-all'. Verify with the DMARC aggregate reports first to confirm no legitimate senders will be hard-failed.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `9.4` | Restrict Unnecessary or Unauthorized Browser and Email Client Extensions |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `domains`, `email-auth`, `spf`

---

### `do-domain-spf-uses-redirect`

**SPF should not use redirect= for primary policy** &middot; severity `low` &middot; service `domains` &middot; resource `digitalocean.domain`

redirect= delegates the entire SPF decision to another domain. This silently inherits whatever that domain publishes — a change at the redirect target changes your SPF posture without your knowledge. Per RFC 7208 §6.1 redirect= is discouraged; prefer 'include:<domain>' which adds rules without giving up the terminating all qualifier.

_Remediation:_

> Replace 'redirect=<other>.com' with 'include:<other>.com -all'. The include mechanism layers the other domain's allowed senders into your policy without surrendering control of the terminator.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `9.4` | Restrict Unnecessary or Unauthorized Browser and Email Client Extensions |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `best-practice`, `domains`, `spf`

---

### `do-droplet-aged-no-rightsizing`

**Droplets >180 days old should be reviewed for right-sizing** &middot; severity `low` &middot; service `droplets` &middot; resource `digitalocean.droplet`

Droplet sizes commonly outgrow or undergrow the workload over 6 months. DO doesn't auto-rightsize. A periodic review of long-running droplets vs their CPU/memory utilization history catches both under- and over-provisioning before they either fail SLO or burn budget.

_Remediation:_

> Review the monitoring dashboard for sustained CPU + memory utilization over 30 days. If sustained < 30%, resize down: `doctl compute droplet-action resize <id> --size s-1vcpu-2gb`. If > 80%, resize up.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.1` | Ensure Network Infrastructure is Up-to-Date |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `soc2` | `A1.1` | Capacity Management |

_Tags:_ `cost`, `droplets`, `rightsizing`

---

### `do-droplet-backups-disabled`

**Droplet backups must be enabled** &middot; severity `medium` &middot; service `droplets` &middot; resource `digitalocean.droplet`

DigitalOcean droplet backups take a weekly snapshot used to recover from incidents, ransomware, or accidental deletion. SOC 2 CC6.6 and CIS Controls v8 11.2 both require some form of backup capability for production data.

_Remediation:_

> Enable backups for the droplet via 'doctl compute droplet-action enable-backups <id>' or set 'backups: true' in your Terraform digitalocean_droplet resource.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `iso27001` | `A.8.13` | Information backup |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `backup`, `recovery`

---

### `do-droplet-monitoring-disabled`

**Droplets should have the DigitalOcean monitoring agent enabled** &middot; severity `medium` &middot; service `droplets` &middot; resource `digitalocean.droplet`

DigitalOcean's monitoring agent (do-agent) is required for the platform's alerting and dashboard story. Without it, resource-level metrics (CPU, memory, disk, network) are not reported and the alerts API has nothing to fire on. SOC 2 CC7.2 + CC7.3 and ISO 27001 A.8.16 both require continuous operational monitoring of production resources.

_Remediation:_

> Enable monitoring via 'doctl compute droplet-action enable-monitoring <id>' or set 'monitoring = true' in the Terraform digitalocean_droplet resource. New droplets created via the UI have a checkbox for this at create time.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.2` | System Component Monitoring |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `alerting`, `droplet`, `monitoring`

---

### `do-droplet-no-firewall`

**Public-IP droplets must have at least one firewall attached** &middot; severity `high` &middot; service `droplets` &middot; resource `digitalocean.droplet`

A droplet exposed to the internet via a public IPv4 address with no firewall has every listening port reachable from anywhere. Cloud-native compliance frameworks treat this as a critical control gap: SOC 2 CC6.6 (logical access controls), CIS Controls v8 4.4 (network filtering), and ISO 27001 A.8.21 all require restricted network access for production resources.

_Remediation:_

> Create a DigitalOcean Cloud Firewall and attach it: 'doctl compute firewall create --name web-fw --inbound-rules "protocol:tcp,ports:443,sources:address:0.0.0.0/0" --droplet-ids <id>'. In Terraform, use the digitalocean_firewall resource and set droplet_ids on it.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.21` | Security of network services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `cross-resource`, `exposure`, `network`

---

### `do-droplet-no-tags`

**Droplets should carry attribution tags** &middot; severity `low` &middot; service `droplets` &middot; resource `digitalocean.droplet`

Tags are how DigitalOcean resources are grouped for firewall membership, cost attribution, and operational queries. A droplet without any tags is effectively orphaned: incidents are harder to triage, costs harder to allocate, and bulk operations harder to scope. SOC 2 CC1.4 and CIS Controls v8 1.1 both expect inventory attribution.

_Remediation:_

> Add at least one tag identifying environment and owner: 'doctl compute droplet tag <id> --tag-name prod' or set 'tags' in your Terraform digitalocean_droplet resource.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC1.4` | Commitment to Competence |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `attribution`, `inventory`

---

### `do-droplet-no-vpc`

**Droplets must belong to a VPC** &middot; severity `medium` &middot; service `droplets` &middot; resource `digitalocean.droplet`

DigitalOcean droplets created before mid-2020 may not be associated with a VPC. Without VPC membership the droplet sits on a region-wide shared private network where every droplet in the region can reach every other droplet's private interface. VPC isolation is the modern baseline; a missing vpc_uuid is almost certainly a legacy droplet that should be migrated.

_Remediation:_

> Create or pick a VPC: 'doctl vpcs list'. Move the droplet by destroying and recreating inside the VPC (DO does not support migrating an existing droplet across VPCs in place; the move is destructive). Take a snapshot first.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `12.4` | Establish and Maintain Architecture Diagram(s) |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `droplet`, `network`, `segmentation`

---

### `do-droplet-old-image`

**Droplet base image should be less than one year old** &middot; severity `medium` &middot; service `droplets` &middot; resource `digitalocean.droplet`

A droplet running an image older than one year is likely missing patches for vulnerabilities disclosed since the image was built. Rebuilding from a current image (or rotating the droplet) is the cleanest mitigation. SOC 2 CC7.1 and CIS Controls v8 7.5 both require a documented patch cadence.

_Remediation:_

> Rebuild the droplet from a current image ('doctl compute droplet-action rebuild <id> --image ubuntu-22-04-x64') or rotate it via an updated Terraform digitalocean_droplet block.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.5` | Perform Automated Vulnerability Scans of Internal Enterprise Assets |
| `iso27001` | `A.8.19` | Installation of software on operational systems |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `patching`, `vulnerability`

---

### `do-droplet-private-networking-disabled`

**Droplets must have private networking enabled** &middot; severity `medium` &middot; service `droplets` &middot; resource `digitalocean.droplet`

Without the 'private_networking' feature, a droplet has no internal interface; every connection to a peer in the same region routes over the public Internet, bypasses the firewall's allow-from-private-only rules, and inflates egress bandwidth bills. Modern DO droplets enable this by default; legacy droplets sometimes have it disabled.

_Remediation:_

> DO does not support enabling private networking on an existing droplet -- the droplet must be recreated. Take a snapshot, destroy the droplet, recreate from the snapshot with the 'private_networking' feature enabled (default for new droplets since 2022).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `12.4` | Establish and Maintain Architecture Diagram(s) |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `droplet`, `network`, `private-networking`

---

### `do-droplet-status-non-active`

**Droplets should be in 'active' status** &middot; severity `low` &middot; service `droplets` &middot; resource `digitalocean.droplet`

A droplet in any state other than 'active' is either powered off (still billing, not running services), partially provisioned (state new), archived, or in an unknown state the API can't classify. Each of these is a posture signal worth reviewing -- powered-off droplets in particular often indicate forgotten environments that still cost money and still have attack surface (their public IPs are reserved).

_Remediation:_

> List non-active droplets with 'doctl compute droplet list --format Name,Status'. For each, decide: bring it back online (power-on), destroy if obsolete, or document the reason in the resource tags.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `cis-v8` | `1.2` | Address Unauthorized Assets |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `droplet`, `hygiene`

---

### `do-droplet-stopped-too-long`

**Stopped droplets accumulate cost without serving traffic** &middot; severity `low` &middot; service `droplets` &middot; resource `digitalocean.droplet`

DO bills droplets in 'off' state at standard rate. A droplet powered off > 30 days is either staging-leftover or a forgotten experiment. Either way: not generating value.

_Remediation:_

> Audit: `doctl compute droplet list --format ID,Name,Status,Created`. For genuinely orphaned droplets, snapshot then destroy: `doctl compute droplet-action snapshot <id> --snapshot-name backup` then `doctl compute droplet delete <id> --force`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `soc2` | `A1.1` | Capacity Management |

_Tags:_ `cost`, `droplets`, `hygiene`

---

### `do-firewall-any-port-from-any`

**Firewalls must not allow any-port from the public internet** &middot; severity `critical` &middot; service `firewalls` &middot; resource `digitalocean.firewall`

A firewall rule with sources 0.0.0.0/0 (or ::/0) AND portRange of 'all' or every-port effectively disables the firewall. This is the catastrophic shape of an accidental 'allow everything' rule -- usually pasted in during incident triage and never reverted. CIS Controls v8 4.5 prescribes explicit deny baselines with narrowly-scoped allow rules.

_Remediation:_

> Open the firewall and remove or scope down any rule with 'ports: all' from a public source. Replace with the specific ports + sources actually needed. Audit by source: 'doctl compute firewall get <id> --format Name,Inbound,Outbound'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.5` | Implement and Manage a Firewall on End-User Devices |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `catastrophic`, `exposure`, `network`

---

### `do-firewall-broad-port-range`

**Firewalls must not open broad port ranges to the public internet** &middot; severity `medium` &middot; service `firewalls` &middot; resource `digitalocean.firewall`

An inbound rule from a public source that spans more than 1024 ports is almost always a mistake -- the intent was a single port (or a small contiguous family) and the typo opened the whole unprivileged range. The check fails on any public-internet inbound rule whose port count exceeds 1024.

_Remediation:_

> Narrow the port range. 'doctl compute firewall update <id>' with the actual port(s) you intended. Audit the rule history if available; broad ranges in firewall rules tend to land via copy/paste error during incident triage.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `exposure`, `network`, `port-hygiene`

---

### `do-firewall-orphan`

**Firewalls should be attached to at least one droplet or tag** &middot; severity `low` &middot; service `firewalls` &middot; resource `digitalocean.firewall`

A firewall with zero attached droplets and zero matched tags protects nothing -- it shows up in the audit trail and in incident response readouts but its rules apply to no workload. These accumulate as droplets are destroyed and the firewall is left behind. Cleaning them up makes 'what firewall protects this resource?' answerable in one query.

_Remediation:_

> Either attach the firewall to droplets/tags that actually need it, or delete it: 'doctl compute firewall delete <id>'. Match firewall lifecycle to the tag or droplet group it protects.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `hygiene`, `network`

---

### `do-firewall-outbound-any-to-any`

**Firewalls should not allow outbound any-to-any** &middot; severity `low` &middot; service `firewalls` &middot; resource `digitalocean.firewall`

An outbound rule with destinations 0.0.0.0/0 (or ::/0) AND portRange 'all' is the egress-allow-everything shape. Data exfiltration leaves over outbound; restricting outbound to known destinations (Spaces endpoint, GitHub Container Registry, NTP, your own DNS resolver) is the standard hardening step. This check is informational at v0.9 because most droplets legitimately need broad outbound for OS package updates -- but the rule should be explicit, not catch-all.

_Remediation:_

> Replace the catch-all with explicit destinations + ports. At minimum: outbound to your update mirrors, to your observability provider, to known internal subnets. Drop the 0.0.0.0/0 / 'all' combo.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `13.4` | Perform Traffic Filtering Between Network Segments |
| `cis-v8` | `13.6` | Collect Network Traffic Flow Logs |
| `iso27001` | `A.8.21` | Security of network services |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `egress`, `exfiltration`, `network`

---

### `do-firewall-rdp-from-any`

**Firewalls must not allow RDP (port 3389) from the public internet** &middot; severity `high` &middot; service `firewalls` &middot; resource `digitalocean.firewall`

Public-Internet RDP exposure on port 3389 is the single highest-velocity ransomware entry vector in the field. Even with rate-limiting, valid-credential discovery by botnet is measured in days. Restrict RDP to bastion / jump-host IPs or a managed VPN range; never expose it to 0.0.0.0/0 / ::/0.

_Remediation:_

> Narrow the source list: 'doctl compute firewall update <id> --inbound-rules "protocol:tcp,ports:3389,sources:address:203.0.113.0/24"'. Better: put Windows hosts behind a VPN concentrator and remove the 3389 rule entirely.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.21` | Security of network services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `exposure`, `network`, `rdp`

---

### `do-firewall-ssh-from-any`

**Firewalls must not allow SSH (port 22) from the public internet** &middot; severity `high` &middot; service `firewalls` &middot; resource `digitalocean.firewall`

An inbound firewall rule allowing TCP port 22 from 0.0.0.0/0 or ::/0 exposes SSH brute-force attempts to every host on the internet. Restrict SSH to bastion IPs, VPN ranges, or use the DigitalOcean web console SSH gateway. SOC 2 CC6.6, ISO 27001 A.8.21, and CIS Controls v8 4.4 all require restricted administrative access.

_Remediation:_

> Replace the rule with a narrow source range: 'doctl compute firewall update <id> --inbound-rules "protocol:tcp,ports:22,sources:address:203.0.113.0/24"'. In Terraform, narrow the 'sources.addresses' list on the matching inbound_rule block.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.21` | Security of network services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `exposure`, `network`, `ssh`

---

### `do-functions-access-key-rotation`

**Functions access keys must be rotated on a documented cadence** &middot; severity `high` &middot; service `functions` &middot; resource `digitalocean.functions_namespace`

Functions access keys are long-lived bearer credentials that authorize invocation of every function in the namespace. godo does not expose key creation timestamps; rotation cadence must be tracked manually. SOC2 CC6.3 + ISO A.5.16 + CIS 5.4 each require ≤90d rotation on long-lived credentials.

_Remediation:_

> Run quarterly: `doctl serverless namespace list-keys <ns>`, revoke any key older than 90 days, issue replacements, rotate consumers. Document the procedure + last-rotation in the runbook.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `iso27001` | `A.5.16` | Identity management |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `credentials`, `functions`, `manual-verify`

---

### `do-functions-cold-start-mitigation`

**Latency-sensitive functions must mitigate cold starts** &middot; severity `low` &middot; service `functions` &middot; resource `digitalocean.functions_namespace`

DO Functions cold-start latency can reach multi-second on first invocation after idle. Latency-sensitive paths (synchronous webhook handlers, customer-facing APIs) need a scheduled keepalive trigger or a different runtime entirely. Hygiene check; the right mitigation depends on the workload.

_Remediation:_

> Add a SCHEDULED trigger at 30s-1m cadence that invokes each cold-sensitive function: `doctl serverless trigger create --type SCHEDULED --cron '* * * * *' <fn>`. Cost is low; impact on p99 latency is meaningful.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `soc2` | `A1.1` | Capacity Management |

_Tags:_ `cold-start`, `functions`, `manual-verify`

---

### `do-functions-disabled-trigger-ratio`

**Disabled-trigger ratio must be 0 (no orphan triggers)** &middot; severity `low` &middot; service `functions` &middot; resource `digitalocean.functions_namespace`

Disabled triggers indicate either an in-progress migration left half-finished or a once-used schedule abandoned. Either way they accumulate as cognitive cost on every audit. Existing do-functions-disabled-triggers covers "all"; this check counts the ratio so partial drift is visible.

_Remediation:_

> List + decide: `doctl serverless trigger list <ns>`. Either re-enable or delete with `doctl serverless trigger delete`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `functions`, `hygiene`, `triggers`

---

### `do-functions-disabled-triggers`

**Functions namespaces should not have disabled triggers** &middot; severity `low` &middot; service `functions` &middot; resource `digitalocean.functions_namespace`

Disabled triggers indicate either a forgotten test or a manual disable during incident response that was never re-enabled. Either way the trigger should be cleaned up so the active surface matches the deployed surface.

_Remediation:_

> List: 'doctl serverless triggers list'. For each disabled trigger, re-enable or delete.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `functions`, `hygiene`

---

### `do-functions-env-vars-plain`

**Functions env vars containing secrets must use --encrypted** &middot; severity `high` &middot; service `functions` &middot; resource `digitalocean.functions_namespace`

DO Functions support encrypted-at-rest env vars via `doctl serverless functions deploy --encrypted`. Without the flag, env vars are stored in plaintext alongside the function package. The DO API does not differentiate encrypted vs plain in the namespace listing.

_Remediation:_

> Re-deploy with `doctl serverless deploy --env-file .env --encrypted`. Audit existing deploys via the dashboard's per-function env-var inspector.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `iso27001` | `A.8.24` | Use of cryptography |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `functions`, `manual-verify`, `secrets`

---

### `do-functions-log-export`

**Functions logs must be exported to a long-retention sink** &middot; severity `high` &middot; service `functions` &middot; resource `digitalocean.functions_namespace`

DO Functions logs are accessible via `doctl serverless activations logs --last` with a short retention window. SOC2 CC7.2 + ISO A.8.15 expect ≥90d retention of invocation logs. No native log-forwarding configuration exists; operators ship logs from inside the function (HTTP to Datadog / Logtail / Splunk).

_Remediation:_

> Wrap each function with a try/finally that POSTs the invocation record to a log sink. OR pull via doctl on a cron and ship to S3/Spaces (`doctl serverless activations list -o json | curl ...`). Document retention SLA.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `functions`, `logging`, `manual-verify`

---

### `do-functions-namespace-empty`

**Functions namespaces should host at least one trigger** &middot; severity `low` &middot; service `functions` &middot; resource `digitalocean.functions_namespace`

A namespace with zero triggers is provisioned but unused. Functions billing has a free tier so the cost is low; the audit-trail confusion isn't. Either delete or deploy something into it.

_Remediation:_

> List triggers: 'doctl serverless namespaces get <namespace>'. If empty, 'doctl serverless namespaces delete'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `functions`, `hygiene`

---

### `do-functions-namespace-no-access-key`

**Functions namespaces must have at least one access key registered** &middot; severity `high` &middot; service `functions` &middot; resource `digitalocean.functions_namespace`

A namespace without an access key has no way to invoke functions outside the DO control panel. Either the namespace is unused (consider deletion) or the operator is invoking with their personal session token (poor audit trail). Either way: not a production posture.

_Remediation:_

> Create a scoped key: `doctl serverless functions invoke --access-key` flow requires a registered key. Issue via `doctl serverless namespace add-key` (or the dashboard).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.1` | Establish and Maintain an Inventory of Accounts |
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.5.16` | Identity management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `credentials`, `functions`

---

### `do-functions-namespace-no-environment-tag`

**Functions namespaces should carry an environment label** &middot; severity `low` &middot; service `functions` &middot; resource `digitalocean.functions_namespace`

Without an environment label in the namespace name (prefix or suffix), production + non-prod namespaces are indistinguishable to billing reports + on-call dashboards. DO Functions namespaces don't carry separate tag fields; convention has to live in the label.

_Remediation:_

> Name new namespaces with explicit prefix: `functions-prod`, `functions-staging`. Existing namespaces need recreate to rename — plan a migration window.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `functions`, `manual-verify`, `naming`

---

### `do-functions-namespace-no-region`

**Functions namespaces must declare an explicit region** &middot; severity `medium` &middot; service `functions` &middot; resource `digitalocean.functions_namespace`

An unset region means functions deploy wherever DO defaults — typically NYC1 — which may not match data-residency requirements. SOC2 CC6.1 + ISO A.5.31 expect regional placement to be a deliberate decision recorded against the workload.

_Remediation:_

> Recreate the namespace with --region: `doctl serverless namespaces create --label <l> --region nyc1`. Migrate existing functions via `doctl serverless deploy`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.5` | Securely Dispose of Data |
| `iso27001` | `A.5.31` | Legal, statutory, regulatory, and contractual requirements |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `functions`, `region`, `residency`

---

### `do-functions-no-access-keys`

**Functions namespaces should have at least one access key** &middot; severity `low` &middot; service `functions` &middot; resource `digitalocean.functions_namespace`

DO Functions namespaces ship with an implicit owner key but explicit access keys are how applications + CI systems authenticate. Zero access keys is either an unused namespace (delete it) or an over-reliance on the implicit owner key (rotate to scoped keys).

_Remediation:_

> Either delete the unused namespace via the DO control panel, or create scoped access keys per workload that connects to it.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `iso27001` | `A.5.15` | Access control |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `credential-hygiene`, `functions`

---

### `do-functions-runtime-eol`

**Functions runtimes must not be EOL (Node 14/16, Python 3.8, etc.)** &middot; severity `high` &middot; service `functions` &middot; resource `digitalocean.functions_namespace`

DO Functions support a fixed list of runtimes; older versions move to EOL and stop receiving CVE patches. Per-function runtime is NOT in the public namespace API — operators must check via project.yml or the dashboard.

_Remediation:_

> Inspect: `doctl serverless functions list <pkg>/<fn>` shows the runtime per function. Update project.yml runtime: "nodejs:20" (or python:3.11), then `doctl serverless deploy`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.3` | Perform Automated Operating System Patch Management |
| `cis-v8` | `7.4` | Perform Automated Application Patch Management |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |

_Tags:_ `functions`, `manual-verify`, `patching`, `runtime`

---

### `do-functions-source-secret-scan`

**Function source must pass secret scanning before deploy** &middot; severity `high` &middot; service `functions` &middot; resource `digitalocean.functions_namespace`

`doctl serverless deploy` packages local source verbatim — no secret-scan gate. Any AWS key / DO token committed to the function repo ships to production. SOC2 CC6.7 + CIS 16.4 each require pre-deploy credential hygiene.

_Remediation:_

> Add a pre-deploy step in CI: `gitleaks detect` or `trufflehog filesystem .` against the function source tree. Block deploy on any non-zero exit.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `16.4` | Establish and Manage an Inventory of Third-Party Software Components |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `functions`, `manual-verify`, `secret-scan`

---

### `do-fw-empty-tag-source`

**Firewall tag sources should resolve to ≥1 droplet** &middot; severity `low` &middot; service `firewalls` &middot; resource `digitalocean.firewall`

A rule sourcing 'tag:bastion' resolves at runtime to all droplets carrying that tag. If 0 droplets do, the rule silently allows nothing — usually a typo. godo doesn't surface tag resolution at firewall-list time; verify manually.

_Remediation:_

> List the rules: `doctl compute firewall get <id>`. For each tag source, run `doctl compute droplet list --tag-name <tag>` and confirm ≥1 droplet.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `firewalls`, `manual-verify`, `tags`

---

### `do-fw-icmp-from-any`

**ICMP from 0.0.0.0/0 leaks host enumeration** &middot; severity `low` &middot; service `firewalls` &middot; resource `digitalocean.firewall`

Allowing ICMP (ping) from the internet lets attackers enumerate live droplets at zero cost. Restrict to known monitoring sources or block entirely.

_Remediation:_

> Remove the wide ICMP rule + replace with a tight one: `doctl compute firewall add-rules <id> --inbound-rules "protocol:icmp,address:10.0.0.0/8"`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `enumeration`, `firewalls`, `icmp`

---

### `do-fw-inbound-rules-duplicated`

**Firewall must not have duplicate inbound rules** &middot; severity `low` &middot; service `firewalls` &middot; resource `digitalocean.firewall`

Duplicate rules add no security but inflate the rule set. DO firewalls cap at 50 rules per firewall — duplicates eat headroom. Common cause: scripted rule additions without a presence check.

_Remediation:_

> Audit + dedupe: `doctl compute firewall get <id>` shows the full rule list. Remove duplicates with `doctl compute firewall remove-rules`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `firewalls`, `hygiene`

---

### `do-fw-outbound-unrestricted`

**Firewalls should restrict outbound traffic** &middot; severity `medium` &middot; service `firewalls` &middot; resource `digitalocean.firewall`

Empty outbound_rules means default-allow-all egress. Modern compromise patterns rely on outbound exfiltration; restricting egress (allow-list to known sinks) limits blast radius. SOC2 CC6.6, ISO A.8.20, CIS 13.4 expect egress controls.

_Remediation:_

> Define outbound rules in the firewall spec; allow only the destinations the workload needs (DB IPs, API endpoints, package mirrors). Anything else gets dropped.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `13.4` | Perform Traffic Filtering Between Network Segments |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `egress`, `firewalls`

---

### `do-image-public`

**Custom images should not be marked public** &middot; severity `high` &middot; service `images` &middot; resource `digitalocean.image`

A custom image (built from your droplet) marked public is downloadable by any DO user. Custom images frequently embed credentials in /etc, /home, or /root; making one public is a leak of those secrets to the entire platform.

_Remediation:_

> Set the image private via the DO control panel (Images > Snapshots / Custom Images > Settings).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.8.3` | Information access restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `data-exposure`, `images`

---

### `do-image-too-old`

**Custom images older than 1 year should be reviewed** &middot; severity `low` &middot; service `images` &middot; resource `digitalocean.image`

A custom image built more than a year ago is almost certainly far behind on patches; restoring it would produce a system out of patch compliance immediately.

_Remediation:_

> Rebuild the image from a current base, then delete the stale one.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.4` | Perform Automated Application Patch Management |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |

_Tags:_ `images`, `patching`

---

### `do-lb-health-check-cleartext`

**Load balancer health checks should not use cleartext HTTP** &middot; severity `medium` &middot; service `load_balancers` &middot; resource `digitalocean.load_balancer`

When the LB terminates HTTPS to its targets, the health check should also use HTTPS (or TCP). An HTTP health check against an HTTPS-only backend hits a TLS-redirect or 400, flapping the LB membership during normal operation and masking real outages.

_Remediation:_

> Update the health check: 'doctl compute load-balancer update <id> --health-check protocol:https,port:443,path:/health'. If the backend is plain HTTP behind a TLS-terminating LB, http health check on the backend port is correct.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `healthcheck`, `lb`

---

### `do-lb-no-https-listener`

**Load balancers must serve at least one HTTPS listener** &middot; severity `high` &middot; service `load_balancers` &middot; resource `digitalocean.load_balancer`

A load balancer with no HTTPS forwarding rule is either an internal-only LB on a private VPC (rare) or, far more commonly, a public LB that forgot to terminate TLS. Either way, the modern baseline is at least one entry on port 443 with a certificate.

_Remediation:_

> Provision a managed cert + add an https forwarding rule: 'doctl compute certificate create --type lets_encrypt --domains example.com,www.example.com' then attach the resulting cert ID to a new https forwarding rule on port 443.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `encryption-in-transit`, `lb`, `tls`

---

### `do-lb-no-vpc`

**Load balancers must belong to a VPC** &middot; severity `medium` &middot; service `load_balancers` &middot; resource `digitalocean.load_balancer`

Load balancers created before the DO VPC GA may sit outside any VPC, exposing the backend droplets via the region-wide shared private network. Modern LBs are VPC-bound; a missing vpc_uuid is almost certainly a legacy resource.

_Remediation:_

> DO does not support changing a load balancer's VPC in place. Recreate the LB inside the target VPC and re-point DNS at the new floating IP. Use Terraform to make the cutover atomic.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `12.4` | Establish and Maintain Architecture Diagram(s) |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `lb`, `network`, `segmentation`

---

### `do-lb-orphan`

**Load balancers should have at least one backend** &middot; severity `low` &middot; service `load_balancers` &middot; resource `digitalocean.load_balancer`

A load balancer with zero attached droplets and no droplet-tag selector responds 503 Service Unavailable to every request. It bills as if it were serving, shows up in DNS and TLS audit trails, and confuses incident response. Either attach backends or delete.

_Remediation:_

> Inspect: 'doctl compute load-balancer get <id> --format Name,DropletIDs,Tag'. If the LB is legitimately retired, 'doctl compute load-balancer delete <id>'. Otherwise attach the backend droplets or the matching tag.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC7.4` | Incident Response |

_Tags:_ `hygiene`, `lb`

---

### `do-lb-proxy-protocol-mismatch`

**PROXY-protocol must match backend support** &middot; severity `medium` &middot; service `load_balancers` &middot; resource `digitalocean.load_balancer`

When the LB sends PROXY-protocol headers but the backend (nginx, etc.) doesn't decode them, every request fails parsing. The DO API exposes the LB's proxy_protocol setting, but not the backend's — verify alignment manually.

_Remediation:_

> If LB has proxy_protocol=true, backend nginx needs 'real_ip_header proxy_protocol' + 'set_real_ip_from <LB CIDR>'. If LB has proxy_protocol=false, backends see the LB's IP — X-Forwarded-For carries the client IP.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `load_balancers`, `manual-verify`, `proxy-protocol`

---

### `do-lb-redirect-http-to-https`

**Load balancers serving HTTP must redirect to HTTPS** &middot; severity `high` &middot; service `load_balancers` &middot; resource `digitalocean.load_balancer`

A load balancer that accepts cleartext HTTP on port 80 and does not redirect to HTTPS sends every request, including every auth cookie + bearer token, over the wire in plaintext to any on-path observer. The redirect_http_to_https flag makes the LB issue a 301 from port 80 to the equivalent https URL.

_Remediation:_

> Enable the redirect via the LB Edit screen, 'doctl compute load-balancer update <id> --redirect-http-to-https', or set redirect_http_to_https = true on the Terraform digitalocean_loadbalancer resource.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.6` | Use of Secure Network Management and Communication Protocols |
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `encryption-in-transit`, `lb`, `tls`

---

### `do-lb-ssl-cipher-floor`

**LB-terminated TLS must drop legacy ciphers** &middot; severity `medium` &middot; service `load_balancers` &middot; resource `digitalocean.load_balancer`

DO LBs run a managed TLS terminator. Cipher / protocol selection is platform-side, not customer-configurable. PCI DSS 4.2 + SOC2 CC6.7 expect documented protocol/cipher floors. Validate the LB's current capabilities via testssl.sh or sslyze and record in the audit pack.

_Remediation:_

> Run `testssl.sh https://<lb-host>` and capture the protocol + cipher report. If unacceptable ciphers appear (SSLv3, RC4, 3DES, NULL, EXPORT), open a DO support ticket. Document in the audit pack.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `ciphers`, `load_balancers`, `manual-verify`, `tls`

---

### `do-lb-sticky-cookie-no-httponly`

**Sticky-session cookies must be HTTPOnly** &middot; severity `medium` &middot; service `load_balancers` &middot; resource `digitalocean.load_balancer`

DO LB sticky sessions issue a cookie back to clients. The DO API doesn't surface the cookie's flags (HttpOnly, Secure, SameSite) — operators must verify via curl against the LB. Per OWASP, the affinity cookie should be HttpOnly + Secure + SameSite=Lax.

_Remediation:_

> DO LB cookie flags are not configurable; if the defaults don't meet your policy, terminate stickiness at the application + use a non-LB cookie under your control.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `load_balancers`, `manual-verify`, `sticky`

---

### `do-lb-tls-passthrough-misconfigured`

**TLS passthrough must pair with an HTTPS-aware backend** &middot; severity `high` &middot; service `load_balancers` &middot; resource `digitalocean.load_balancer`

tls_passthrough=true means the LB does not terminate TLS — the backend must speak TLS on the entry port. If the backend speaks plain HTTP, every connection will fail. Symptom: 502 / handshake errors at the LB.

_Remediation:_

> Either: (1) flip tls_passthrough=false + add a managed cert at the LB, OR (2) configure backend droplets to speak TLS on the entry port (typically 443).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `configuration`, `load_balancers`, `tls`

---

### `do-monitoring-disabled-alert`

**Configured alert policies should be enabled** &middot; severity `low` &middot; service `monitoring` &middot; resource `digitalocean.alert_policy`

A disabled alert policy is dead weight: it shows up in the audit trail but never fires. Common cause: a one-off silence during incident response that was never re-enabled.

_Remediation:_

> Either delete the policy or re-enable it. Avoid the long-lived 'disabled' state.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `alerting`, `hygiene`, `monitoring`

---

### `do-monitoring-no-alerts`

**Account should have at least one configured alert policy** &middot; severity `low` &middot; service `monitoring` &middot; resource `digitalocean.account`

An account with zero alert policies has no signal channel for the standard ops events (high CPU, low disk, droplet down). Configure at least the four basics: CPU sustained, memory sustained, disk usage, droplet status.

_Remediation:_

> Create an alert: 'doctl monitoring alert create --type v1/insights/droplet/cpu --description "high cpu" --compare GreaterThan --value 80 --window 10m --emails ops@example.com'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.2` | System Component Monitoring |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `alerting`, `monitoring`

---

### `do-project-default-no-description`

**The default project should have an explicit description** &middot; severity `low` &middot; service `projects` &middot; resource `digitalocean.project`

The default project gets every resource not assigned elsewhere. Leaving its description empty makes the audit trail ambiguous when a misassigned resource shows up there. Set a description that explains the policy ('catch-all for unsorted; review weekly').

_Remediation:_

> Set a description on the default project via the DO control panel.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC1.4` | Commitment to Competence |

_Tags:_ `projects`

---

### `do-project-no-environment`

**Projects should declare their environment** &middot; severity `low` &middot; service `projects` &middot; resource `digitalocean.project`

DO projects have an environment field (Development / Staging / Production). Setting it correctly drives the right defaults in the control panel and gives an unambiguous signal in audit logs. Empty environments collapse the distinction.

_Remediation:_

> Set via the DO control panel: Projects > Settings > Environment.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC1.4` | Commitment to Competence |

_Tags:_ `projects`

---

### `do-project-no-purpose`

**Projects must declare a non-default purpose** &middot; severity `low` &middot; service `projects` &middot; resource `digitalocean.project`

DO projects carry a 'purpose' field used by billing breakouts. Default purpose ('Service or API') is the catch-all new projects ship with — empty or default purpose makes per-project cost attribution noise.

_Remediation:_

> `doctl projects update <id> --purpose='Production Web Application'`. Conventional purposes: Web Application, Operational, Trying out DigitalOcean, Class project / educational purposes.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `billing`, `projects`, `tagging`

---

### `do-registry-empty`

**Container registries should host at least one repository** &middot; severity `low` &middot; service `registry` &middot; resource `digitalocean.registry`

An empty container registry pays its subscription tier for nothing. Either delete the registry or push the images it was provisioned for.

_Remediation:_

> Inspect: 'doctl registry repository list-v2 <registry>'. If genuinely unused, 'doctl registry delete'. Otherwise complete the image-pipeline setup.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `cost`, `hygiene`, `registry`

---

### `do-registry-no-recent-gc`

**Container registries should run garbage collection regularly** &middot; severity `medium` &middot; service `registry` &middot; resource `digitalocean.registry`

DO Container Registry does not auto-delete untagged or overwritten image layers; only an explicit garbage-collection run reclaims that storage. A registry with no GC for more than 30 days is paying for orphan blobs and accumulating untracked image content -- both a cost and an audit-trail problem.

_Remediation:_

> 'doctl registry garbage-collection start <registry>'. Schedule this in CI on a weekly cadence (e.g. a GitHub Actions cron job). The DO control panel also exposes a manual run.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.5` | Securely Dispose of Data |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `cost`, `hygiene`, `registry`

---

### `do-registry-starter-tier`

**Production container registries should not run on the Starter tier** &middot; severity `low` &middot; service `registry` &middot; resource `digitalocean.registry`

The Starter subscription tier is capped at 500 MB storage + 1 repository -- adequate for evaluation, not for production. A production registry stuck on Starter is one image push from a quota-exhaustion outage. Upgrade to Basic or Professional before scale matters.

_Remediation:_

> 'doctl registry options subscription-tiers' lists the available tiers. Upgrade via the control panel (Registry > Settings > Plan).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.1` | Establish and Maintain a Data Recovery Process |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |

_Tags:_ `capacity`, `registry`

---

### `do-reserved-ip-no-project`

**Reserved IPs should be assigned to a project** &middot; severity `low` &middot; service `reserved_ips` &middot; resource `digitalocean.reserved_ip`

Reserved IPs without a project_id sit in the default project, making cost attribution + access control awkward.

_Remediation:_

> Move the IP to a named project via the DO control panel or 'doctl projects resources assign'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC1.4` | Commitment to Competence |

_Tags:_ `projects`, `reserved-ip`

---

### `do-reserved-ip-no-region`

**Reserved IPs must declare a region** &middot; severity `low` &middot; service `networking` &middot; resource `digitalocean.reserved_ip`

Reserved IPs are region-locked; the API should always return a region. A missing region usually indicates a stale data-collection error or an in-migration reserved IP. Either way: not a valid steady state.

_Remediation:_

> Inspect: `doctl compute reserved-ip get <ip>`. If the region is genuinely missing, delete + recreate via `doctl compute reserved-ip create --region nyc3`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `networking`, `reserved-ip`

---

### `do-reserved-ip-orphan`

**Reserved IPs should be attached to a droplet** &middot; severity `low` &middot; service `reserved_ips` &middot; resource `digitalocean.reserved_ip`

An unattached reserved IP bills regardless of use. Common shape: a droplet was destroyed without releasing its reserved IP, and the IP sits forever paying a fee.

_Remediation:_

> Either attach to a droplet ('doctl compute reserved-ip action assign <ip> <droplet-id>') or release ('doctl compute reserved-ip delete <ip>').

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `cost`, `hygiene`, `reserved-ip`

---

### `do-snapshot-orphan-source`

**Snapshots should have a still-existing source resource** &middot; severity `low` &middot; service `snapshots` &middot; resource `digitalocean.snapshot`

A snapshot whose source resource (droplet or volume) has been deleted is the only copy of that data. This is sometimes intentional (cold-storage snapshot of a retired workload) but often indicates a forgotten cleanup. Worth reviewing in case the data still matters.

_Remediation:_

> List: 'doctl compute snapshot list --format Name,ResourceType,ResourceID'. Cross-reference each ResourceID with the active droplets/volumes. For genuinely cold-storage snapshots, document the retention reason; for forgotten ones, delete.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.8.13` | Information backup |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `hygiene`, `snapshot`

---

### `do-snapshot-too-old`

**Snapshots older than one year should be reviewed** &middot; severity `low` &middot; service `snapshots` &middot; resource `digitalocean.snapshot`

Snapshots are normally taken before a risky change or as part of a weekly backup rotation. A snapshot older than a year is almost always obsolete: the source droplet's base image has long since shifted, restoring it would produce a system way out of patch compliance, and it still bills.

_Remediation:_

> List + filter: 'doctl compute snapshot list --format Name,ResourceType,Created'. Decide whether each old snapshot is needed; delete the rest with 'doctl compute snapshot delete <id>'. Document the retention policy for the rest.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `cis-v8` | `11.5` | Test Data Recovery |
| `iso27001` | `A.8.13` | Information backup |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |

_Tags:_ `cost`, `hygiene`, `snapshot`

---

### `do-spaces-bucket-audit-pairing`

**Audit-relevant buckets must have encryption AND logging both on** &middot; severity `high` &middot; service `spaces` &middot; resource `digitalocean.spaces_bucket`

Two checks already exist for encryption + logging in isolation; this composite check fails when EITHER is off, matching how auditors evaluate the pair. ISO A.5.34 + A.8.15 each require encryption + audit logs as a pair; a bucket with one but not the other doesn't carry an audit narrative.

_Remediation:_

> Enable both: 'aws s3api put-bucket-encryption ...' + 'aws s3api put-bucket-logging ...' against the Spaces endpoint. Logging target should be a dedicated bucket (see do-spaces-bucket-logging-self-target).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `cis-v8` | `8.2` | Collect Audit Logs |
| `iso27001` | `A.5.34` | Privacy and protection of PII |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit`, `encryption`, `logging`, `spaces`

---

### `do-spaces-bucket-cors-wildcard`

**Spaces buckets must not use wildcard CORS origins** &middot; severity `medium` &middot; service `spaces` &middot; resource `digitalocean.spaces_bucket`

A CORS rule with AllowedOrigin '*' lets any browser page on the public Internet fetch + (if PUT/DELETE methods are also allowed) modify objects via XHR. Common shape of accidental public-bucket exposure even when the underlying ACL is correct.

_Remediation:_

> List your application origins explicitly: 'https://app.example.com', 'https://staging.example.com'. Apply via 'aws s3api put-bucket-cors' against the Spaces endpoint. If the workload truly needs '*', restrict methods to GET only.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `cors`, `exposure`, `spaces`

---

### `do-spaces-bucket-encryption-key-rotation-documented`

**Spaces encryption uses platform-managed keys — verify rotation cadence** &middot; severity `medium` &middot; service `spaces` &middot; resource `digitalocean.spaces_bucket`

DO Spaces server-side encryption is SSE-S3-equivalent: DigitalOcean manages the keys. Customer-managed keys (SSE-C, SSE-KMS-equivalent) are not exposed. SOC2 CC6.7 + ISO A.8.24 each ask for documented rotation cadence on encryption keys; since the keys are out of scope, the audit obligation falls on DigitalOcean's published SOC 2 Type 2 report. This finding records the gap so the auditor knows to reference DO's report rather than expecting a customer-side rotation log.

_Remediation:_

> Obtain DigitalOcean's current SOC 2 Type 2 report from the security portal (https://www.digitalocean.com/trust). Cite section addressing CC6.7 encryption-key management in your audit narrative. No customer-side action.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `encryption`, `key-rotation`, `manual-verify`, `spaces`

---

### `do-spaces-bucket-lifecycle-no-expiration`

**Lifecycle configuration must include an expiration rule** &middot; severity `medium` &middot; service `spaces` &middot; resource `digitalocean.spaces_bucket`

A bucket with lifecycle enabled but zero expiration rules is paying full Spaces storage for objects nobody is pruning. The single most common lifecycle misconfiguration: the rule only sets a transition or MPU abort, not an actual TTL on objects. SOC2 CC9.1 + CIS 3.5 expect documented retention; this finding asserts the lifecycle config implements one.

_Remediation:_

> Add an Expiration block: in the dashboard's bucket settings or via the S3 API. Example AWS-CLI shape: 'aws s3api put-bucket-lifecycle-configuration --bucket NAME --lifecycle-configuration file://lifecycle.json --endpoint-url https://REGION.digitaloceanspaces.com'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.5` | Securely Dispose of Data |
| `iso27001` | `A.5.13` | Labelling of information |
| `iso27001` | `A.5.34` | Privacy and protection of PII |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `cost`, `lifecycle`, `retention`, `spaces`

---

### `do-spaces-bucket-lifecycle-no-mpu-cleanup`

**Lifecycle configuration must abort incomplete multipart uploads** &middot; severity `medium` &middot; service `spaces` &middot; resource `digitalocean.spaces_bucket`

Multipart uploads that never call CompleteMultipartUpload leave orphaned parts billed at full Spaces storage rate, sometimes invisibly for years. A lifecycle rule with AbortIncompleteMultipartUpload (DaysAfterInitiation = 7 is the conventional value) reaps these on a schedule. The cost impact is often material; the audit impact is that orphaned parts are not enumerated by GetObject so they're invisible to standard inventory scans.

_Remediation:_

> Add an AbortIncompleteMultipartUpload rule to the existing lifecycle config: 'DaysAfterInitiation: 7' is the conventional default. The S3 API accepts this alongside existing Expiration rules in one PutBucketLifecycleConfiguration call.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.5` | Securely Dispose of Data |
| `iso27001` | `A.5.13` | Labelling of information |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `cost`, `lifecycle`, `multipart`, `spaces`

---

### `do-spaces-bucket-logging-self-target`

**Server-access log target must be a different bucket** &middot; severity `high` &middot; service `spaces` &middot; resource `digitalocean.spaces_bucket`

Targeting server-access logs at the bucket they describe creates a feedback loop: every access-log write is itself a new access logged in the same bucket, ballooning the dataset and making any retention policy meaningless. SOC2 CC7.3 and ISO A.8.15 expect log records to be tamper-segregated; co-mingling target + source defeats that.

_Remediation:_

> Designate a dedicated 'access-logs' bucket with a restrictive lifecycle (90d expiration, no public access, separate access key with logs:Write-only). Update the source bucket's logging config to target the dedicated bucket.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.2` | Collect Audit Logs |
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `logging`, `segregation`, `spaces`

---

### `do-spaces-bucket-mfa-delete-via-team-iam`

**DO Spaces does not support MFA-Delete — verify via team IAM controls** &middot; severity `medium` &middot; service `spaces` &middot; resource `digitalocean.spaces_bucket`

S3 MFA-Delete requires an MFA token to call DeleteObject or PutBucketVersioning. DO Spaces does not implement this. The compensating control is team-level: require 2FA on the team (do-account-mfa-required) AND restrict the Spaces access key permissions so delete operations require a separate least-privilege key whose use is logged. CIS 3.3 and SOC2 CC6.3 each expect deletion to be a privileged operation.

_Remediation:_

> Three layers: (1) ensure team 2FA is enforced; (2) issue a separate Spaces access key for any role that needs delete; (3) restrict that key to specific buckets via the bucket policy. See do-spaces-key-fullaccess for the existing scope-of-key check.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `cis-v8` | `6.5` | Require MFA for Administrative Access |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.5.18` | Access rights |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `manual-verify`, `mfa-delete`, `spaces`, `unsupported`

---

### `do-spaces-bucket-no-encryption`

**Spaces buckets should have default encryption configured** &middot; severity `medium` &middot; service `spaces` &middot; resource `digitalocean.spaces_bucket`

DO Spaces encrypts every object at rest using AES-256 with platform-managed keys regardless of bucket configuration, but the per-bucket default-encryption setting forces clients to acknowledge encryption on every PUT. A bucket without the default-encryption header set will accept unencrypted PUT requests that downgrade to platform-default, which is compliance-detectable.

_Remediation:_

> Apply default encryption via s3-compatible API: 'aws s3api put-bucket-encryption --bucket <name> --server-side-encryption-configuration ...' against the Spaces endpoint.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `encryption-at-rest`, `spaces`

---

### `do-spaces-bucket-no-lifecycle`

**Spaces buckets should have lifecycle rules configured** &middot; severity `low` &middot; service `spaces` &middot; resource `digitalocean.spaces_bucket`

Without lifecycle rules, every object lives forever -- including incomplete multipart uploads, old non-current versions, and superseded build artifacts. Most production buckets benefit from a lifecycle policy that expires transient data and tier-shifts cold objects.

_Remediation:_

> Define a lifecycle XML and apply via s3-compatible API. Minimum baseline: expire incomplete multipart uploads after 1 day, expire non-current versions after 90 days. Tune to the workload.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.5` | Securely Dispose of Data |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `cost`, `hygiene`, `spaces`

---

### `do-spaces-bucket-no-logging`

**Spaces buckets should have access logging configured** &middot; severity `low` &middot; service `spaces` &middot; resource `digitalocean.spaces_bucket`

Spaces server-access logs are the forensic trail when a bucket is the source of a security incident. Without them, 'who accessed this object at this timestamp' is unanswerable. Apply to data-plane buckets; control-plane logs cover the DO API surface separately.

_Remediation:_

> Enable logging into a dedicated log-aggregation bucket via the s3 PUT bucket logging API. The destination bucket must be different from the source bucket (loop prevention).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.10` | Retain Audit Logs |
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit-logging`, `spaces`

---

### `do-spaces-bucket-no-versioning`

**Spaces buckets should have versioning enabled** &middot; severity `medium` &middot; service `spaces` &middot; resource `digitalocean.spaces_bucket`

Object versioning preserves previous versions on overwrite or delete -- the only recovery path for accidental deletes or ransomware-style encrypt-in-place attacks against Spaces. Pair with a lifecycle policy that expires old non- current versions to bound storage cost.

_Remediation:_

> Enable via s3-compatible API: 's3cmd --access_key=$SPACES_KEY --secret_key=$SPACES_SECRET --host=<region>.digitaloceanspaces.com setversioning s3://<bucket> Enabled' (or the equivalent aws-cli put-bucket-versioning).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.8.13` | Information backup |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC7.4` | Incident Response |

_Tags:_ `backup`, `recovery`, `spaces`

---

### `do-spaces-bucket-object-lock-via-app-layer`

**DO Spaces does not support S3 Object Lock — verify app-layer immutability** &middot; severity `high` &middot; service `spaces` &middot; resource `digitalocean.spaces_bucket`

S3 Object Lock provides WORM (write-once-read-many) semantics required by SEC 17a-4, FINRA, CFTC, HIPAA, and some PCI scenarios. DO Spaces does not implement Object Lock — any compliance regime requiring WORM must be satisfied via application-layer immutability (content-addressed storage, hash-locked manifests, off-platform replication to an object-lock-capable target). This finding flags the gap so the auditor can record the compensating control.

_Remediation:_

> If WORM is a regulatory requirement: replicate audit-relevant writes off-Spaces to an S3 Object Lock target (AWS S3, Backblaze B2 with Object Lock, MinIO with WORM mode) and document the application-layer hash-chain. Otherwise, waive via waivers.yaml citing the absence of WORM regulatory requirements.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.5` | Securely Dispose of Data |
| `iso27001` | `A.5.13` | Labelling of information |
| `iso27001` | `A.5.34` | Privacy and protection of PII |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `manual-verify`, `object-lock`, `spaces`, `unsupported`

---

### `do-spaces-bucket-policy-required`

**Production Spaces buckets must declare an explicit bucket policy** &middot; severity `medium` &middot; service `spaces` &middot; resource `digitalocean.spaces_bucket`

Spaces buckets default to no bucket policy — access is governed solely by access keys and ACLs. SOC2 CC6.1 and ISO A.5.15 expect documented authorization rules; the bucket policy is the only structured surface where a Spaces bucket can record an explicit-deny posture (e.g. Deny on Principal:* for s3:GetObject) that survives misconfigured ACLs.

_Remediation:_

> Author a policy that explicitly denies the actions you never want — public reads, ACL changes, multipart abort. Apply via 'aws s3api put-bucket-policy --bucket NAME --policy file://policy.json --endpoint-url https://REGION.digitaloceanspaces.com'. DO docs: https://docs.digitalocean.com/products/spaces/how-to/manage-access/.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.5.15` | Access control |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `access-control`, `policy`, `spaces`

---

### `do-spaces-bucket-public-acl`

**Spaces buckets must not grant public ACLs** &middot; severity `critical` &middot; service `spaces` &middot; resource `digitalocean.spaces_bucket`

A bucket ACL that grants AllUsers or AuthenticatedUsers exposes every object to the public Internet. Spaces buckets default to private but a copied-from-AWS ACL snippet or a CDN-setup misstep can flip them open. The single highest-impact misconfiguration on object storage.

_Remediation:_

> Remove the public ACL: 's3cmd setacl s3://<bucket> --acl-private' (s3cmd-compatible) or use the DO control panel Settings > Permissions. Audit every object that was public during the exposure window.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.5.10` | Acceptable use of information and other associated assets |
| `iso27001` | `A.8.3` | Information access restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `data-exposure`, `public-access`, `spaces`

---

### `do-spaces-bucket-replication-via-external-sync`

**DO Spaces does not support cross-region replication — verify external sync** &middot; severity `high` &middot; service `spaces` &middot; resource `digitalocean.spaces_bucket`

S3 Cross-Region Replication (CRR) is the standard availability + durability control for object stores: a single-region outage doesn't lose objects, RPO ≈ minutes. DO Spaces does not implement CRR. SOC2 A1.2 + ISO A.5.30 each require a documented availability strategy; this finding flags the gap so the auditor can confirm an out-of-band sync (rclone cron, custom job) is in place.

_Remediation:_

> Run a periodic 'rclone sync' between the source Spaces region and a target (different Spaces region OR a different provider). Capture the cron schedule + last-success timestamp in the runbook. If a multi-region availability SLA isn't a business requirement, waive via waivers.yaml.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `iso27001` | `A.8.13` | Information backup |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `manual-verify`, `replication`, `spaces`, `unsupported`

---

### `do-spaces-bucket-versioning-requires-lifecycle`

**Versioned buckets must declare a lifecycle policy** &middot; severity `medium` &middot; service `spaces` &middot; resource `digitalocean.spaces_bucket`

Versioning without lifecycle is a cost-leak pattern: every overwrite + every delete creates a non-current version that's billed at full storage rate, forever. SOC2 A1.2 + CIS 3.5 expect retention and capacity controls together; this finding asserts the cost dimension of the controls pair is in place.

_Remediation:_

> Add a lifecycle rule with NoncurrentVersionExpiration (commonly 30-90 days). Apply via the S3 API or dashboard. Pair with the do-spaces-bucket-lifecycle-no-expiration check to ensure the rule covers current versions too.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.5` | Securely Dispose of Data |
| `iso27001` | `A.5.34` | Privacy and protection of PII |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `cost`, `lifecycle`, `spaces`, `versioning`

---

### `do-spaces-key-fullaccess`

**Spaces keys should be scoped, not fullaccess** &middot; severity `medium` &middot; service `spaces` &middot; resource `digitalocean.spaces_key`

DO Spaces keys can be scoped to specific buckets + permissions (read / readwrite / fullaccess). A fullaccess key or a key with zero grants (which legacy keys default to) can reach every bucket in the account. Lost or leaked, the blast radius is everything.

_Remediation:_

> Rotate to a scoped key: 'doctl spaces keys create <name> --grants bucket=<bucket>,permission=readwrite'. Update the application credential. Revoke the old fullaccess key.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `key-scope`, `least-privilege`, `spaces`

---

### `do-spaces-key-too-old`

**Spaces keys should be rotated at least once a year** &middot; severity `low` &middot; service `spaces` &middot; resource `digitalocean.spaces_key`

Long-lived credentials accumulate exposure risk: more log entries containing the key, more code paths that have loaded it, more former employees who once had it. Rotate Spaces keys at least annually. SOC 2 CC6.1 + ISO 27001 A.5.16 both prescribe periodic credential rotation.

_Remediation:_

> Create a new key with the same grants: 'doctl spaces keys create <new-name> --grants ...'. Update the application credential. Delete the old key once traffic has migrated.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.3` | Disable Dormant Accounts |
| `cis-v8` | `6.1` | Establish an Access Granting Process |
| `iso27001` | `A.5.16` | Identity management |
| `iso27001` | `A.5.17` | Authentication information |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `credential-rotation`, `spaces`

---

### `do-ssh-key-too-many`

**Account-level SSH key count should be bounded** &middot; severity `low` &middot; service `ssh_keys` &middot; resource `digitalocean.ssh_key`

DO account-level SSH keys are auto-injected into every new droplet's root authorized_keys. The more keys live at the account level, the more former-employee or former-laptop keys propagate to new droplets. Prune to active humans only; prefer per-droplet provisioning for ephemeral access.

_Remediation:_

> List + audit: 'doctl compute ssh-key list'. Delete obsolete keys with 'doctl compute ssh-key delete <id>'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.3` | Disable Dormant Accounts |
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.16` | Identity management |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `credential-hygiene`, `ssh-keys`

---

### `do-ssh-key-weak-algorithm`

**Account SSH keys must use strong algorithms** &middot; severity `medium` &middot; service `ssh_keys` &middot; resource `digitalocean.ssh_key`

DSA keys, RSA keys shorter than 3072 bits, or unknown algorithms should not exist in the DO account SSH key list. Anyone holding the corresponding private key can land on every droplet that imports authorized_keys from this account.

_Remediation:_

> Generate a new key: 'ssh-keygen -t ed25519'. Add via 'doctl compute ssh-key import <name> --public-key-file ~/.ssh/id_ed25519.pub'. Delete the weak key.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `iso27001` | `A.8.24` | Use of cryptography |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `crypto-agility`, `ssh-keys`

---

### `do-volume-orphan`

**Block volumes should be attached to a droplet** &middot; severity `low` &middot; service `volumes` &middot; resource `digitalocean.volume`

A DO block volume bills regardless of whether it is attached to a droplet. Unattached volumes accumulate when droplets are destroyed without their volumes; they cost money for nothing and clutter the resource list.

_Remediation:_

> Inspect: 'doctl compute volume list --format Name,DropletIDs,SizeGigabytes'. If the data is no longer needed, 'doctl compute volume delete <id>'. If it is, take a snapshot and document where the data lives.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `cis-v8` | `1.2` | Address Unauthorized Assets |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `cost`, `hygiene`, `volume`

---

### `do-volume-unformatted-orphan`

**Unformatted detached volumes should be cleaned up** &middot; severity `low` &middot; service `volumes` &middot; resource `digitalocean.volume`

A volume with no filesystem_type set AND no droplet attached has never been mounted by anything. These are almost always failed-provision artifacts or test-and-forget leftovers; they bill forever, contain no data, and confuse the audit trail.

_Remediation:_

> 'doctl compute volume delete <id>' for any unformatted, detached volume. If you intend to use the volume, attach it to a droplet and mkfs.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `hygiene`, `volume`

---

### `do-vpc-default-not-in-use`

**Default VPC should not host production droplets** &middot; severity `medium` &middot; service `vpcs` &middot; resource `digitalocean.vpc`

DigitalOcean creates a default VPC per region the first time an account creates a resource there. The default VPC is convenient for experiments but a posture-anti-pattern for production: any droplet without an explicit VPC choice lands in it, mixing prod and dev traffic on the same broadcast domain. A named VPC per environment is the modern baseline.

_Remediation:_

> Create a named VPC per environment: 'doctl vpcs create --name prod-nyc3 --region nyc3 --ip-range 10.10.0.0/16'. Move droplets by snapshotting + recreating into the named VPC (DO does not support in-place VPC migration).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `12.4` | Establish and Maintain Architecture Diagram(s) |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `network`, `segmentation`

---

### `do-vpc-orphan`

**Non-default VPCs should have at least one member** &middot; severity `low` &middot; service `vpcs` &middot; resource `digitalocean.vpc`

A non-default VPC with zero members is dead weight: it reserves an IP range, shows up in firewall and routing audits, and contributes to incident-response confusion ('which VPC protects this droplet?'). Either attach resources or delete it.

_Remediation:_

> List VPCs and members: 'doctl vpcs list' followed by 'doctl vpcs members <vpc-id>'. For empty named VPCs, either move resources in or 'doctl vpcs delete <vpc-id>'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `hygiene`, `network`

---

### `do-vpc-peering-cross-region`

**VPC peering spans must be intra-region (DO does not support cross-region peering)** &middot; severity `high` &middot; service `networking` &middot; resource `digitalocean.vpc_peering`

DO does not support VPC peering across regions. Any peering registered with VPCs in different regions is a stale or impossible config — DO API will reject the bind, but the peering record may persist. Validate.

_Remediation:_

> Drop the cross-region peering: `doctl vpcs peerings delete <id>`. For cross-region connectivity use a VPN tunnel between droplets in each VPC.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.1` | Ensure Network Infrastructure is Up-to-Date |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `networking`, `peering`, `vpc`

---

### `do-vpc-peering-not-active`

**VPC peerings should be in ACTIVE status** &middot; severity `low` &middot; service `vpcs` &middot; resource `digitalocean.vpc_peering`

A VPC peering in PENDING or other non-ACTIVE status is either a half-completed setup (the peering was initiated and never accepted on the other side) or an in-progress administrative action. Stuck peerings can hide misrouted traffic; clean them up.

_Remediation:_

> List peerings: 'doctl vpcs peerings list'. For non-ACTIVE entries, either complete the peering (accept on the other side) or delete: 'doctl vpcs peerings delete <id>'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `hygiene`, `network`, `peering`

---

## gcp

### `gcp-bigquery-default-cmek`

**BigQuery datasets must have a default CMEK configured** &middot; severity `medium` &middot; service `bigquery` &middot; resource `gcp.bigquery.dataset`

BigQuery encrypts data at rest by default with Google-managed keys. Setting a default CMEK at the dataset level ensures every newly-created table inherits a customer-managed key, which is required when downstream controls (audit, key rotation, BYOK, key destruction for crypto-shredding) need to apply uniformly across tables in a dataset.

_Remediation:_

> 'bq update --default_kms_key=projects/<proj>/locations/<loc>/keyRings/<ring>/cryptoKeys/<key> <project>:<dataset>'. Grant the BigQuery service account (bq-<project-number>@bigquery-encryption.iam.gserviceaccount.com) the cloudkms.cryptoKeyEncrypterDecrypter role on the key.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `bigquery`, `cmek`, `encryption`

---

### `gcp-bigquery-no-all-authenticated-users`

**BigQuery datasets must not grant access to allAuthenticatedUsers** &middot; severity `high` &middot; service `bigquery` &middot; resource `gcp.bigquery.dataset`

Even when public anonymous access (allUsers) is denied, granting allAuthenticatedUsers exposes the dataset to every Google account on the internet, not just your organization. This is rarely the intent and is a common path to credential-stuffing data exfiltration. CIS GCP 7.1 / 7.2 prescribe explicit member lists instead.

_Remediation:_

> Remove the allAuthenticatedUsers grant: 'bq remove-iam-policy-binding <project>:<dataset> --member=allAuthenticatedUsers --role=<role>'. Replace with an explicit group or service-account binding.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.5.10` | Acceptable use of information and other associated assets |
| `iso27001` | `A.8.3` | Information access restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `bigquery`, `data-exposure`, `public-access`

---

### `gcp-bigquery-no-public-datasets`

**BigQuery datasets must not grant access to allUsers/allAuthenticatedUsers** &middot; severity `critical` &middot; service `bigquery` &middot; resource `gcp.bigquery.dataset`

Granting any role to allUsers or allAuthenticatedUsers on a BigQuery dataset exposes every table, view, and routine inside it. allUsers is the anonymous-internet grant; allAuthenticatedUsers is any Google account. Both are common shapes of public-data leak.

_Remediation:_

> Identify offending access entries: 'bq show --format=prettyjson <project>:<dataset>' and remove any access entry where specialGroup or iamMember is allUsers or allAuthenticatedUsers. Replace with named groups or service accounts scoped to the actual consumers.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.5.10` | Acceptable use of information and other associated assets |
| `iso27001` | `A.8.3` | Information access restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `bigquery`, `data-exposure`, `public-access`

---

### `gcp-compute-no-broad-scopes`

**GCE instances must not run with cloud-platform service-account scope** &middot; severity `high` &middot; service `compute` &middot; resource `gcp.compute.instance`

The cloud-platform OAuth scope grants the attached service account access to every GCP API the SA has IAM permissions for. Combined with the default Compute Engine SA (which has roles/editor by default), this gives any process on the instance project-wide write access. CIS GCP 4.1 + 4.2 prescribe narrower scopes (specific service-level scopes) or IAM-only access control with no scopes.

_Remediation:_

> Stop the instance, change its scopes to specific service scopes only (e.g. logging-write, monitoring-write): 'gcloud compute instances set-service-account <name> --scopes=logging-write,monitoring-write,storage-ro'. Better: rely on IAM permissions and remove the cloud-platform scope.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `compute`, `least-privilege`, `service-account`

---

### `gcp-compute-no-default-network`

**GCP projects must not use the auto-mode default VPC network** &middot; severity `medium` &middot; service `compute` &middot; resource `gcp.compute.network`

GCP's auto-mode default VPC creates a subnet in every region with predefined firewall rules (allow-ssh, allow-rdp, allow-internal). For production workloads this is too permissive; a purpose-built custom-mode VPC with explicit subnet and firewall design is the right shape. CIS GCP Foundations 3.1.

_Remediation:_

> Migrate workloads to a custom-mode VPC: 'gcloud compute networks create my-vpc --subnet-mode=custom'. Then delete the default network: 'gcloud compute networks delete default'. The delete fails if anything still uses it.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `compute`, `network`

---

### `gcp-compute-no-ssh-from-any`

**Firewall rules must not allow SSH (tcp:22) from 0.0.0.0/0** &middot; severity `high` &middot; service `compute` &middot; resource `gcp.compute.firewall`

SSH (tcp:22) exposed to 0.0.0.0/0 is the canonical brute-force attack target. CIS GCP Foundations 3.6 prescribes scoping SSH ingress to a known CIDR (office IP, VPN, IAP tunnel range). Identity-Aware Proxy (IAP) tunnel is the GCP-native preferred path for SSH access without exposing port 22 at all.

_Remediation:_

> Narrow the source CIDR: 'gcloud compute firewall-rules update <rule> --source-ranges=<your-cidr>'. For zero exposed-port access set up IAP tunneling: https://cloud.google.com/iap/docs/using-tcp-forwarding .

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.21` | Security of network services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `compute`, `exposure`, `firewall`, `ssh`

---

### `gcp-compute-os-login-enabled`

**OS Login must be enabled at project level** &middot; severity `medium` &middot; service `compute` &middot; resource `gcp.compute.project_metadata`

OS Login replaces SSH key management with IAM: an operator with the required IAM role gets short-lived SSH credentials, and revoking access is a single IAM unbind rather than chasing per-instance authorized_keys files. CIS GCP Foundations 4.4 prescribes enabling OS Login at the project metadata level so all new instances inherit it.

_Remediation:_

> 'gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE'. Then grant roles/compute.osLogin (or osAdminLogin) to the principals who should be able to SSH in.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `cis-v8` | `6.5` | Require MFA for Administrative Access |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `compute`, `iam`, `ssh`

---

### `gcp-compute-shielded-vm`

**GCE instances must have Shielded VM fully enabled** &middot; severity `medium` &middot; service `compute` &middot; resource `gcp.compute.instance`

Shielded VM uses a hardened firmware (UEFI), Secure Boot (only Google-signed bootloaders), vTPM (virtual trusted platform module), and integrity monitoring (boot-time checks against a trusted baseline) to defend the boot chain. Without it, a rootkit-level compromise is much harder to detect. CIS GCP 4.8 prescribes all three options on.

_Remediation:_

> Shielded VM settings are set at instance create time; recreate the instance with all three options enabled. For existing instances, the simpler path is 'gcloud compute instances stop <name>' then 'gcloud compute instances update <name> --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring' then start it back up.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.7` | Protection against malware |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |

_Tags:_ `boot-integrity`, `compute`, `shielded-vm`

---

### `gcp-iam-cloudaudit-logging`

**GCP project audit logging must cover admin/read/write activity for allServices** &middot; severity `medium` &middot; service `iam` &middot; resource `gcp.iam.policy`

Cloud Audit Logs are GCP's API-level change record. CIS GCP Foundations 2.1 prescribes a project-level audit config for 'allServices' with ADMIN_READ, DATA_READ, DATA_WRITE all enabled. Without it, post-incident forensics has only partial coverage of who-did-what-when.

_Remediation:_

> Add the audit config via Cloud Console (IAM & Admin -> Audit Logs -> Default audit logs configuration) or set auditConfigs in your Terraform / Deployment Manager templates: `auditConfigs: [{ service: 'allServices', auditLogConfigs: [{ logType: ADMIN_READ }, { logType: DATA_READ }, { logType: DATA_WRITE }] }]`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.10` | Retain Audit Logs |
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.2` | System Component Monitoring |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `audit-logging`, `iam`

---

### `gcp-iam-no-broad-token-creator`

**GCP project must not grant broad service-account impersonation** &middot; severity `high` &middot; service `iam` &middot; resource `gcp.iam.policy`

Project-level grants of roles/iam.serviceAccountTokenCreator or roles/iam.serviceAccountUser let the holder mint short-lived tokens for ANY service account in the project (or impersonate it via gcloud --impersonate-service-account). Scoping these grants to specific service-account resources (not the project) is the CIS GCP 1.6 separation-of-duties baseline.

_Remediation:_

> Replace project-level grants with per-SA grants: 'gcloud iam service-accounts add-iam-policy-binding <sa-email> --member=<principal> --role=roles/iam.serviceAccountTokenCreator'. Then remove the project-level binding via 'gcloud projects remove-iam-policy-binding ...'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `iam`, `impersonation`, `service-account`

---

### `gcp-iam-no-default-sa-in-use`

**GCP default Compute / App Engine service accounts must not be used** &middot; severity `medium` &middot; service `iam` &middot; resource `gcp.iam.service_account`

The default Compute Engine service account (<project-number>-compute@developer.gserviceaccount.com) and App Engine default service account (<project-id>@appspot.gserviceaccount.com) carry the Editor role on the project by default, which is over-broad. Workloads running as these SAs inherit those permissions. CIS GCP 1.5 prescribes replacing them with purpose-built SAs scoped to the actual job.

_Remediation:_

> Create a purpose-built SA: 'gcloud iam service-accounts create my-workload --display-name="My Workload"', grant the specific roles it needs, then redeploy the workload with --service-account=my-workload@<project>.iam.gserviceaccount.com.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `default-sa`, `iam`, `service-account`

---

### `gcp-iam-no-primitive-roles`

**GCP project IAM must not grant primitive roles (Owner/Editor/Viewer)** &middot; severity `high` &middot; service `iam` &middot; resource `gcp.iam.policy`

Primitive GCP roles (Owner, Editor, Viewer) grant access to every API in the project, defeating least-privilege. CIS GCP Foundations Benchmark 1.4 (no service account user impersonation escalation) and 1.8 (separation of duties) prescribe using predefined or custom roles scoped to the actual job instead.

_Remediation:_

> List who has primitive roles: 'gcloud projects get-iam-policy <project> --flatten=bindings --filter="bindings.role:roles/(owner|editor|viewer)"'. For each member, identify the specific actions they need and replace with a predefined role (e.g. roles/storage.objectAdmin) or a custom role.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `iam`, `least-privilege`, `primitive-roles`

---

### `gcp-iam-no-user-managed-sa-keys`

**GCP service accounts should not have user-managed keys** &middot; severity `medium` &middot; service `iam` &middot; resource `gcp.iam.service_account`

User-managed service-account keys are the GCP analog of long-lived AWS access keys -- the canonical credential-leak path. Workload Identity Federation (for GitHub Actions, GitLab CI, AWS-running workloads), GCE metadata server (for GCE VMs), and GKE Workload Identity (for GKE pods) cover the legitimate use cases with short-lived tokens. CIS GCP 1.4 prescribes no user-managed keys.

_Remediation:_

> Migrate to Workload Identity Federation: https://cloud.google.com/iam/docs/workload-identity-federation . Once the WIF provider + service-account binding is in place, delete the user-managed keys: 'gcloud iam service-accounts keys list --iam-account=<sa-email>' then 'gcloud iam service-accounts keys delete <key-id> --iam-account=<sa-email>'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `credentials`, `iam`, `service-account`

---

### `gcp-iam-sa-key-age`

**GCP service-account user-managed keys must be rotated within 90 days** &middot; severity `high` &middot; service `iam` &middot; resource `gcp.iam.service_account`

User-managed service-account keys are long-lived static credentials -- the GCP equivalent of an AWS access key. CIS GCP 1.7 prescribes 90-day rotation to cap the exposure window of any leaked key. (System-managed keys, which Google rotates automatically, are out of scope for this check.)

_Remediation:_

> Rotate via 'gcloud iam service-accounts keys create new-key.json --iam-account=<sa-email>', deploy the new key everywhere it's needed, then 'gcloud iam service-accounts keys delete <old-key-id>'. Better: switch to Workload Identity Federation and remove the need for long-lived keys altogether.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `credentials`, `iam`, `rotation`, `service-account`

---

### `gcp-kms-admin-user-separation`

**KMS key admins must be separate from encrypters/decrypters** &middot; severity `medium` &middot; service `kms` &middot; resource `gcp.kms.crypto_key`

A principal with both roles/cloudkms.admin and roles/cloudkms.cryptoKeyEncrypterDecrypter on the same key can rotate or destroy keys while also reading ciphertext encrypted under them, collapsing the separation of duties that KMS is meant to enforce. CIS GCP Foundations 1.11 prescribes that these roles never coincide on the same principal at the key level.

_Remediation:_

> Audit who holds which key roles: 'gcloud kms keys get-iam-policy <key> --keyring=<ring> --location=<loc>'. Remove the overlap by either revoking the admin role (typical for applications) or moving crypto operations to a dedicated service account distinct from the key admin.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.7` | Centralize Access Control |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `kms`, `least-privilege`, `separation-of-duties`

---

### `gcp-kms-key-rotation`

**KMS encrypt/decrypt keys must rotate at least every 90 days** &middot; severity `medium` &middot; service `kms` &middot; resource `gcp.kms.crypto_key`

Periodic rotation of symmetric keys limits the blast radius of a compromised key version: once rotated, ciphertext written under the old version can still be decrypted but new traffic uses fresh material. CIS GCP Foundations 1.10 prescribes a rotation period of 90 days or less. Asymmetric and signing keys are out of scope (the rotation period field doesn't apply).

_Remediation:_

> 'gcloud kms keys update <key> --keyring=<ring> --location=<location> --rotation-period=90d --next-rotation-time=<rfc3339>'. For Terraform set rotation_period = "7776000s" on the google_kms_crypto_key resource.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `key-management`, `kms`, `rotation`

---

### `gcp-logging-bucket-retention`

**Cloud Logging buckets must retain entries for at least 365 days** &middot; severity `medium` &middot; service `logging` &middot; resource `gcp.logging.bucket`

Most compliance frameworks expect at least 12 months of audit-log retention to cover an annual audit window. The Cloud Logging default is 30 days, which is well short. Lengthening retention on the _Default bucket (or routing to a longer-retention sink) is the cheapest way to clear the bar.

_Remediation:_

> 'gcloud logging buckets update _Default --location=global --retention-days=365 --project=<project>'. Combine with a sink to GCS for retention beyond 3650 days (the bucket maximum).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.10` | Retain Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `audit-trail`, `logging`, `retention`

---

### `gcp-logging-sink-exists`

**Each project must export logs to a long-term sink** &middot; severity `high` &middot; service `logging` &middot; resource `gcp.project`

Cloud Logging buckets default to 30-day retention, which isn't enough for incident response or compliance evidence over an audit window. A sink exporting to GCS / BigQuery / Pub-Sub gives the operator a durable, queryable archive that survives bucket TTL. CIS GCP Foundations 2.2.

_Remediation:_

> Create a project-level sink with no filter (catches everything): 'gcloud logging sinks create all-to-gcs storage.googleapis.com/<bucket> --project=<project>'. Then grant the sink's writer_identity roles/storage.objectCreator on the destination bucket.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.10` | Retain Audit Logs |
| `cis-v8` | `8.2` | Collect Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.2` | System Component Monitoring |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `audit-trail`, `logging`, `retention`

---

### `gcp-sql-automated-backups`

**Cloud SQL instances must have automated backups enabled** &middot; severity `medium` &middot; service `sql` &middot; resource `gcp.sql.instance`

Automated backups are the recovery path from data corruption, accidental delete, and ransomware. Without them the operator is one DROP TABLE away from total loss. CIS GCP Foundations 6.7.

_Remediation:_

> Enable backups: 'gcloud sql instances patch <name> --backup-start-time=03:00'. Pair with point-in-time recovery (--enable-point-in-time-recovery for Postgres, --enable-bin-log for MySQL) for sub-day RPO.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `cis-v8` | `11.3` | Protect Recovery Data |
| `iso27001` | `A.8.13` | Information backup |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC7.4` | Incident Response |

_Tags:_ `backup`, `recovery`, `sql`

---

### `gcp-sql-deletion-protection`

**Cloud SQL instances must have deletion protection enabled** &middot; severity `medium` &middot; service `sql` &middot; resource `gcp.sql.instance`

Deletion protection blocks accidental instance deletion at the API. It's the last guard between a stray Terraform destroy or console click and total loss of the production database (along with the automated backups, which live inside the instance). Cheap to enable, hard to recover without.

_Remediation:_

> 'gcloud sql instances patch <name> --deletion-protection'. For Terraform-managed fleets, set deletion_protection = true on the google_sql_database_instance resource.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.8.13` | Information backup |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC7.4` | Incident Response |

_Tags:_ `data-protection`, `recovery`, `sql`

---

### `gcp-sql-no-public-ip`

**Cloud SQL instances must not have public IPv4** &middot; severity `high` &middot; service `sql` &middot; resource `gcp.sql.instance`

Cloud SQL with a public IPv4 address is reachable from the internet, gated only by authorized-network IP allowlists and the database engine's own auth. Use private IP (VPC peering) so the instance has no public attack surface at all. CIS GCP Foundations 6.6.

_Remediation:_

> Disable public IP: 'gcloud sql instances patch <name> --no-assign-ip --network=projects/<project>/global/networks/<vpc>'. Apps connect via private IP, the Cloud SQL Auth Proxy, or a connector with IAM auth.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.6` | Use of Secure Network Management and Communication Protocols |
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `network-exposure`, `public-access`, `sql`

---

### `gcp-storage-logging`

**GCS buckets must have access logging configured** &middot; severity `low` &middot; service `storage` &middot; resource `gcp.storage.bucket`

GCS access logs are the forensic trail when a bucket is the source of a security incident. Without them, 'who accessed this object at this timestamp' is unanswerable. Cloud Audit Logs cover the management plane; bucket access logs cover the data plane.

_Remediation:_

> Enable access logging to a dedicated log-aggregation bucket: 'gsutil logging set on -b gs://<log-bucket> -o AccessLog gs://<bucket>'. The log bucket must not be the source bucket (would create a logging loop).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.10` | Retain Audit Logs |
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit-logging`, `storage`

---

### `gcp-storage-public-access-prevention`

**GCS buckets must have Public Access Prevention enforced** &middot; severity `critical` &middot; service `storage` &middot; resource `gcp.storage.bucket`

Public Access Prevention is the bucket- or org-level switch that overrides any IAM binding or ACL granting public access. With PAP=enforced, `allUsers` and `allAuthenticatedUsers` grants are rejected outright at the API. Combined with UBLA, this is the strongest defense against accidental public-bucket incidents. CIS GCP Foundations 5.1.

_Remediation:_

> 'gsutil pap set enforced gs://<bucket>'. Better still, set an organization policy (constraints/storage.publicAccessPrevention) so new buckets inherit PAP automatically.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.3` | Information access restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `data-exposure`, `public-access`, `storage`

---

### `gcp-storage-uniform-bucket-level-access`

**GCS buckets must use Uniform Bucket-Level Access** &middot; severity `high` &middot; service `storage` &middot; resource `gcp.storage.bucket`

Uniform Bucket-Level Access disables per-object ACLs and forces all access through IAM bindings at the bucket level. ACLs are the legacy path that produces public buckets via accidental `allUsers` grants; UBLA eliminates that surface entirely. CIS GCP Foundations 5.2.

_Remediation:_

> 'gsutil uniformbucketlevelaccess set on gs://<bucket>'. Once UBLA is on, manage permissions only via IAM at the bucket or project level.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.3` | Information access restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `data-exposure`, `iam`, `storage`

---

### `gcp-storage-versioning`

**GCS buckets must have versioning enabled** &middot; severity `medium` &middot; service `storage` &middot; resource `gcp.storage.bucket`

Object versioning preserves previous versions of every object, giving point-in-time recovery from accidental delete and ransomware encryption-in-place. The CIS GCP Foundations Benchmark does not pin versioning specifically, but every reasonable production-readiness checklist does.

_Remediation:_

> 'gsutil versioning set on gs://<bucket>'. Pair with a lifecycle rule to expire old non-current versions if storage cost is a concern.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.8.13` | Information backup |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `backup`, `recovery`, `storage`

---

## hetzner

### `hetzner-firewall-any-port-from-any`

**Hetzner firewalls must not allow any-port from the public internet** &middot; severity `critical` &middot; service `firewalls` &middot; resource `hetzner.firewall`

Hetzner firewall rules can omit the port to mean 'all ports.' An inbound rule with sources 0.0.0.0/0 and no port (or `1-65535`) for TCP/UDP effectively disables the firewall. Common shape of pasted-in incident-triage rules that survive past the incident.

_Remediation:_

> Replace the rule with explicit port lists. 'hcloud firewall replace-rules <name>' with a narrowly scoped rules.json. Audit history if available.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.5` | Implement and Manage a Firewall on End-User Devices |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `catastrophic`, `exposure`, `firewall`

---

### `hetzner-firewall-orphan`

**Hetzner firewalls should be applied to at least one resource** &middot; severity `low` &middot; service `firewalls` &middot; resource `hetzner.firewall`

A firewall with zero AppliedTo entries protects nothing. They accumulate as servers are deleted but the firewalls are left behind. Cleaning them up makes 'which firewall protects this server?' answerable in one query.

_Remediation:_

> Either apply the firewall to a server or label selector ('hcloud firewall apply-to-resource ...') or delete it ('hcloud firewall delete <name>').

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `firewall`, `hygiene`

---

### `hetzner-firewall-ssh-from-any`

**Hetzner firewalls must not allow SSH (port 22) from the public internet** &middot; severity `high` &middot; service `firewalls` &middot; resource `hetzner.firewall`

An inbound rule allowing TCP 22 from 0.0.0.0/0 or ::/0 exposes SSH brute-force attempts to every host on the internet. Restrict to bastion IPs, VPN ranges, or use the Hetzner Cloud Console SSH gateway.

_Remediation:_

> Replace the rule with a narrow source: 'hcloud firewall replace-rules <name> --rules-file rules.json' with sources scoped to your operator CIDRs.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.21` | Security of network services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `exposure`, `firewall`, `ssh`

---

### `hetzner-floating-ip-orphan`

**Hetzner Floating IPs should be attached to a server** &middot; severity `low` &middot; service `floating_ips` &middot; resource `hetzner.floating_ip`

A Hetzner Cloud Floating IP bills monthly regardless of whether it's attached. Common shape: a server was deleted and the IP wasn't released; it now sits forever paying a fee.

_Remediation:_

> Either attach to a server ('hcloud floating-ip assign <ip-id> <server-name>') or delete ('hcloud floating-ip delete <ip-id>').

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `cost`, `floating-ip`, `hygiene`

---

### `hetzner-lb-http-not-redirected`

**Hetzner LB HTTP services must redirect to HTTPS** &middot; severity `medium` &middot; service `load_balancers` &middot; resource `hetzner.load_balancer`

A Hetzner LB with an HTTP service that does not set redirect_http=true accepts cleartext requests and serves the response back in cleartext. Modern hardening pattern is to accept HTTP only to 301-redirect to HTTPS; never to actually serve content over HTTP.

_Remediation:_

> Set redirect_http on the http service: 'hcloud load-balancer update-service <lb> --listen-port 80 --http-redirect-http=true'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `encryption-in-transit`, `lb`, `tls`

---

### `hetzner-lb-no-https-listener`

**Hetzner load balancers should serve at least one HTTPS listener** &middot; severity `high` &middot; service `load_balancers` &middot; resource `hetzner.load_balancer`

A Hetzner Cloud Load Balancer without an HTTPS service serves every request in cleartext to any on-path observer. At minimum, a public LB should have an `https` service with at least one Certificate attached.

_Remediation:_

> Add an HTTPS service via the Cloud Console or `hcloud load-balancer add-service <name> --protocol https --listen-port 443 --certificates <cert-id>`. Hetzner managed certs are free via the Cloud Console > Certificates page.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `encryption-in-transit`, `lb`, `tls`

---

### `hetzner-network-non-rfc1918`

**Hetzner private networks should use RFC1918 address space** &middot; severity `medium` &middot; service `networks` &middot; resource `hetzner.network`

Hetzner Cloud private networks can be assigned any IPv4 CIDR. RFC1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are the standard private space and what every other tool expects 'private' to mean. A network on a public range may route traffic in surprising ways at the underlying carrier — defensively keep private networks in private space.

_Remediation:_

> Hetzner doesn't support changing a network's IP range in place. Recreate the network with an RFC1918 CIDR ('hcloud network create --name <name> --ip-range 10.20.0.0/16') and reattach members.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `addressing`, `network`

---

### `hetzner-network-orphan`

**Hetzner private networks should have at least one member** &middot; severity `low` &middot; service `networks` &middot; resource `hetzner.network`

A private network with zero servers AND zero load balancers attached protects nothing. Reserved IP range, appears in audit reports, no actual workload uses it. Either attach members or delete.

_Remediation:_

> List: 'hcloud network list --output columns=name,ip_range,servers'. For empty networks, either attach servers via 'hcloud server attach-to-network' or delete via 'hcloud network delete <name>'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `hygiene`, `network`

---

### `hetzner-server-locked`

**Non-production Hetzner servers should not stay locked indefinitely** &middot; severity `low` &middot; service `servers` &middot; resource `hetzner.server`

Hetzner servers expose a delete-protection lock flag. It's correct to leave prod servers locked. It's a hygiene problem to leave dev/staging/test servers locked — operators typically apply the lock during a sensitive change and forget to remove it, which then blocks routine cleanup. This check is informational; expect to skip it for true prod assets via a profile or a waiver from v0.18 onwards.

_Remediation:_

> Audit locks: `hcloud server list --selector environment=production` (and inverse). For each non-prod locked server, unlock via `hcloud server disable-protection <name> --delete`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `hygiene`, `server`

---

### `hetzner-server-no-backups`

**Hetzner servers should have automated backups enabled** &middot; severity `medium` &middot; service `servers` &middot; resource `hetzner.server`

Hetzner Cloud servers expose a BackupWindow setting; non-empty means a daily snapshot runs in that window. Empty means no automated backups. SOC 2 A1.2 and ISO 27001 A.8.13 both prescribe backup capability for production data.

_Remediation:_

> Enable backups via the Hetzner Cloud Console (Server > Backups > Enable Backups) or `hcloud server enable-backup <name>`. Backups carry a 20% surcharge but that's the standard cost of recoverable production.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.8.13` | Information backup |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `backup`, `recovery`, `server`

---

### `hetzner-server-not-running`

**Hetzner servers should be in 'running' status** &middot; severity `low` &middot; service `servers` &middot; resource `hetzner.server`

A Hetzner Cloud server bills regardless of whether it's powered on. A server in `off` or `initializing` status is either a forgotten ops experiment, a half-finished provision, or a fleet item that should have been deleted. Worth reviewing each non-running server.

_Remediation:_

> List + filter: `hcloud server list --output columns=name,status,location`. For each non-running server, either restart it (`hcloud server poweron <name>`) or delete it (`hcloud server delete <name>`).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `cost`, `hygiene`, `server`

---

### `hetzner-server-old-image`

**Hetzner servers should not run from images older than 1 year** &middot; severity `medium` &middot; service `servers` &middot; resource `hetzner.server`

A Hetzner server built from a base image more than a year old will be missing roughly a year of OS-vendor patches unless ongoing apt-upgrade / dnf-upgrade has been bringing the running system forward. Even with package upgrades, kernel + base userland drift is real. Rebuilding from a fresh image forces a clean baseline.

_Remediation:_

> Snapshot the server, build a new server from a current image, restore any custom config, switch DNS / load balancer targets. Hetzner doesn't support in-place rebase. Schedule per server in routine maintenance.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.4` | Perform Automated Application Patch Management |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |

_Tags:_ `patching`, `server`, `supply-chain`

---

### `hetzner-server-rescue-enabled`

**Hetzner servers should not run with rescue mode enabled** &middot; severity `low` &middot; service `servers` &middot; resource `hetzner.server`

Hetzner's rescue mode replaces the boot disk with a recovery image granting temporary root, intended for short maintenance windows. A server stuck in rescue mode is either a forgotten recovery session or a live operator typing into a non-persistent shell — both indicate the resource is not in steady production state.

_Remediation:_

> Power-cycle the server out of rescue: `hcloud server disable-rescue <name>` followed by `hcloud server reset <name>`. Confirm that the underlying issue that triggered rescue mode has been resolved.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `ops-hygiene`, `server`

---

### `hetzner-volume-orphan`

**Hetzner volumes should be attached to a server** &middot; severity `low` &middot; service `volumes` &middot; resource `hetzner.volume`

A Hetzner Cloud volume bills regardless of whether it's attached to a server. Unattached volumes accumulate when servers are deleted but their volumes are left behind; they cost money for nothing.

_Remediation:_

> Either attach to a server ('hcloud volume attach --server <name> <volume>') or delete ('hcloud volume delete <volume>'). If the data matters, snapshot first.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `cost`, `hygiene`, `volume`

---

### `hetzner-volume-unformatted-orphan`

**Unformatted detached Hetzner volumes should be cleaned up** &middot; severity `low` &middot; service `volumes` &middot; resource `hetzner.volume`

A Hetzner Cloud volume with no filesystem format AND no attached server has never been mounted. These are almost always failed-provision artifacts or test-and-forget leftovers — they bill forever and contain no data.

_Remediation:_

> 'hcloud volume delete <volume>'. If you intend to use the volume, attach it ('hcloud volume attach --server <name> <volume>') and mkfs.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `hygiene`, `volume`

---

## kubernetes

### `k8s-configmap-secret-shaped-data`

**ConfigMaps should not hold credential-shaped keys** &middot; severity `high` &middot; service `secrets` &middot; resource `k8s.configmap`

ConfigMap values are stored in plaintext in etcd and visible to anyone with `get configmaps` (which is broader than `get secrets`). A key named `password`, `token`, `api_key`, etc. is almost always a misplaced credential. The developer probably meant to use a Secret.

_Remediation:_

> Move the credential-shaped key into a Secret. The workload's volume mount or env reference should switch from `configMapKeyRef` to `secretKeyRef`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `iso27001` | `A.8.10` | Information deletion |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `configmap`, `k8s`, `secrets`

---

### `k8s-configmap-too-large`

**ConfigMaps should be under 1 MiB** &middot; severity `low` &middot; service `secrets` &middot; resource `k8s.configmap`

Large ConfigMaps stress etcd write replication and slow API responses for tooling that lists them. Mostly an operational signal — a ConfigMap holding a >1 MiB JSON document or a binary blob is usually a sign that another storage primitive would fit better.

_Remediation:_

> For large config bundles, mount from a PVC, fetch at startup, or split into multiple keys.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.1` | Capacity Management |

_Tags:_ `configmap`, `k8s`, `size`

---

### `k8s-cronjob-concurrency`

**CronJobs should not allow concurrent executions** &middot; severity `low` &middot; service `jobs` &middot; resource `k8s.cronjob`

`concurrencyPolicy: Allow` (the default) lets a slow run overlap with the next scheduled run, doubling cluster load and frequently corrupting shared state — backup jobs, cleanup tasks, and any cron that writes data should run one at a time.

_Remediation:_

> Set `concurrencyPolicy: Forbid` (skip overlap) or `Replace` (kill the running instance and start the new one). Allow is appropriate only for read-only, idempotent jobs.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.32` | Change management |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `cron`, `jobs`, `k8s`

---

### `k8s-cronjob-history-limit`

**CronJobs should set successful and failed history limits** &middot; severity `low` &middot; service `jobs` &middot; resource `k8s.cronjob`

Without `successfulJobsHistoryLimit` and `failedJobsHistoryLimit`, the Job objects from every cronjob run accumulate forever. After a year of hourly cronjobs that is 8760 Job + Pod objects per cronjob — etcd bloat plus slow `kubectl get jobs` plus pressure on the controller manager.

_Remediation:_

> Set `spec.successfulJobsHistoryLimit: 3` and `spec.failedJobsHistoryLimit: 5` (or your operational preference). The defaults of 3/1 are usually too small for debugging.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `cron`, `etcd-hygiene`, `jobs`, `k8s`

---

### `k8s-cronjob-starting-deadline`

**CronJobs should set startingDeadlineSeconds** &middot; severity `low` &middot; service `jobs` &middot; resource `k8s.cronjob`

Without `startingDeadlineSeconds`, the controller keeps trying to start missed jobs after the scheduled time, and once more than 100 misses accumulate it stops scheduling the cronjob entirely. Setting an explicit deadline (e.g. 200 seconds) lets old runs expire cleanly.

_Remediation:_

> Set `spec.startingDeadlineSeconds` to a value greater than your scheduling interval. 200 is a common starting point for cronjobs that run more often than every 5 minutes.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `cron`, `jobs`, `k8s`

---

### `k8s-daemonset-control-plane-tolerance`

**Non-system DaemonSets should not tolerate control-plane taints** &middot; severity `low` &middot; service `controllers` &middot; resource `k8s.daemonset`

Tolerating `node-role.kubernetes.io/control-plane` lets the DaemonSet schedule pods on master nodes. That is correct for cluster-critical workloads (CNI agents, log forwarders, node-exporter). For application DaemonSets it is a posture failure: a compromise of the DS pod becomes a control-plane compromise.

_Remediation:_

> Remove the control-plane toleration unless the DS is genuinely cluster-infrastructure. Use namespaces or labels to distinguish infra from workload DaemonSets in policy.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `control-plane`, `controllers`, `k8s`

---

### `k8s-deployment-anti-affinity`

**Multi-replica Deployments should set podAntiAffinity** &middot; severity `low` &middot; service `controllers` &middot; resource `k8s.deployment`

Two replicas on the same node give the appearance of HA without the reality — a single node failure takes both down. `podAntiAffinity` (preferred or required) spreads replicas across nodes (or AZs, with topology spread) and is the standard way to get genuine fault tolerance.

_Remediation:_

> Add `affinity.podAntiAffinity` to the pod template. `preferredDuringSchedulingIgnoredDuringExecution` with `topologyKey: kubernetes.io/hostname` is the right default; upgrade to `required` for critical workloads.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |

_Tags:_ `controllers`, `ha`, `k8s`

---

### `k8s-deployment-min-replicas`

**Deployments should run with at least 2 replicas for HA** &middot; severity `medium` &middot; service `controllers` &middot; resource `k8s.deployment`

A single-replica Deployment has no HA. A node drain, a rolling update, or an OOM kill creates a window of zero available replicas. Production workloads should run with at least two replicas plus a PodDisruptionBudget that keeps one available during voluntary disruptions.

_Remediation:_

> Set `spec.replicas` to at least 2. For cost-sensitive dev/staging Deployments, exclude via a profile or waiver.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `cis-v8` | `12.5` | Centralize Network Authentication, Authorization, and Auditing (AAA) |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |

_Tags:_ `controllers`, `ha`, `k8s`

---

### `k8s-deployment-pdb-missing`

**Multi-replica Deployments should have a PodDisruptionBudget** &middot; severity `medium` &middot; service `controllers` &middot; resource `k8s.deployment`

Without a PodDisruptionBudget, a node drain (cluster autoscaler scale-down, kernel patch, cluster upgrade) can evict every replica simultaneously. A PDB with `minAvailable: 1` or `maxUnavailable: 1` keeps at least one replica up across voluntary disruptions.

_Remediation:_

> Create a PDB selecting the Deployment's pods: `spec.selector` matching the Deployment label and `spec.minAvailable: 1`. For 3+ replica workloads, prefer `maxUnavailable: 25%` so rollouts are not gated unnecessarily.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `cis-v8` | `12.5` | Centralize Network Authentication, Authorization, and Auditing (AAA) |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |

_Tags:_ `controllers`, `ha`, `k8s`

---

### `k8s-deployment-rolling-update`

**Deployments should use the RollingUpdate strategy** &middot; severity `low` &middot; service `controllers` &middot; resource `k8s.deployment`

`strategy.type: Recreate` tears down every existing pod before starting new ones, guaranteeing downtime during every rollout. RollingUpdate is the safe default for stateless workloads; Recreate is correct only when a stateful invariant prevents two versions from co-existing.

_Remediation:_

> Set `strategy.type: RollingUpdate` and tune `rollingUpdate.maxUnavailable` / `maxSurge` based on capacity. Keep Recreate only when you have a documented reason.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.32` | Change management |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `controllers`, `k8s`, `rollout`

---

### `k8s-doks-auto-upgrade`

**DOKS clusters should enable auto-upgrade** &middot; severity `medium` &middot; service `doks` &middot; resource `digitalocean.doks.cluster`

Auto-upgrade lets DO promote the cluster within the maintenance window when a new minor lands. Without it, the cluster sticks at its creation version until manually upgraded — and DO unsupports minor versions on a known schedule.

_Remediation:_

> `doctl kubernetes cluster update <c> --auto-upgrade`. Combine with a maintenance window during low-traffic hours.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.4` | Perform Automated Application Patch Management |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |

_Tags:_ `doks`, `k8s`, `upgrade`

---

### `k8s-doks-cert-manager-installed`

**cert-manager (or equivalent) must manage workload TLS certificates** &middot; severity `high` &middot; service `doks` &middot; resource `digitalocean.doks.cluster`

DOKS does not bundle cert-manager. Without it (or an equivalent like external-dns-issued certs or a service mesh's mTLS plane), workload TLS is operator-driven — manual rotation, manual issuance, easy to miss. SOC2 CC6.7 + ISO A.8.24 expect automated certificate lifecycle.

_Remediation:_

> Install cert-manager via Helm: `helm repo add jetstack https://charts.jetstack.io && helm install cert-manager jetstack/cert-manager -n cert-manager --create-namespace --set installCRDs=true`. Then create a ClusterIssuer for Let's Encrypt + DNS01 backed by the DO webhook (cert-manager-webhook-digitalocean).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `addon`, `doks`, `k8s`, `manual-verify`, `tls`

---

### `k8s-doks-cluster-autoscaler-eligible`

**Production clusters should run cluster-autoscaler (or use DO's built-in)** &middot; severity `medium` &middot; service `doks` &middot; resource `digitalocean.doks.cluster`

DOKS provides per-node-pool autoscaling natively (captured by k8s-doks-nodepool-no-autoscale). For clusters with many node pools or cross-pool scaling needs, the upstream cluster-autoscaler with the DO provider gives finer control. Either is acceptable; what's NOT acceptable is static node counts on a production cluster.

_Remediation:_

> Default: enable per-pool autoscaling (`doctl kubernetes cluster node-pool update <c> <np> --auto-scale --min-nodes=2 --max-nodes=10`). Advanced: deploy upstream cluster-autoscaler with `--cloud-provider=digitalocean`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.4` | Perform Automated Application Patch Management |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.4` | Incident Response |

_Tags:_ `addon`, `autoscaling`, `doks`, `k8s`, `manual-verify`

---

### `k8s-doks-cluster-running`

**DOKS clusters should be in running state** &middot; severity `high` &middot; service `doks` &middot; resource `digitalocean.doks.cluster`

A cluster in degraded / errored / upgrading state needs operator attention. running is the steady-state.

_Remediation:_

> Check the DO control panel for the failure reason. Open a support ticket if the cluster cannot self-heal.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `doks`, `k8s`, `reliability`

---

### `k8s-doks-control-plane-logging-exported`

**DOKS control-plane logs must be exported (API audit, scheduler, controller-manager)** &middot; severity `high` &middot; service `doks` &middot; resource `digitalocean.doks.cluster`

DigitalOcean exposes control-plane logs only via the `doctl kubernetes cluster logs` follow command; there is no native log-export configuration in the DO API. Production clusters must forward those logs to a long-retention sink (Datadog, Loki, ELK) — SOC2 CC7.2 + ISO A.8.15 + CIS 8.5 all require ≥90 day audit-log retention with tamper-evident storage.

_Remediation:_

> Two paths: (1) deploy a vector / fluent-bit DaemonSet to forward node logs + scrape /var/log/kube-apiserver-audit; (2) install the DO Datadog add-on if you're already a Datadog customer (covers control-plane + workload logs in one). Document the sink + retention SLA in the runbook.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.1` | Establish and Maintain an Audit Log Management Process |
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit-trail`, `doks`, `k8s`, `manual-verify`

---

### `k8s-doks-ha-control-plane`

**DOKS clusters should run with HA control plane** &middot; severity `high` &middot; service `doks` &middot; resource `digitalocean.doks.cluster`

DOKS supports an HA control plane (multiple master replicas across zones) for an extra $40/month. Without it, control-plane maintenance windows or zone outages cause API unavailability. For production workloads, HA is the baseline.

_Remediation:_

> `doctl kubernetes cluster update <c> --ha` (creates a new HA control plane; existing workloads continue). For new clusters, pass `--ha` at create time.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |

_Tags:_ `doks`, `ha`, `k8s`

---

### `k8s-doks-maintenance-window`

**DOKS clusters should configure a maintenance window** &middot; severity `low` &middot; service `doks` &middot; resource `digitalocean.doks.cluster`

Without an explicit maintenance window, DO picks one. Set the window to low-traffic hours so upgrades, certificate rotations, and other maintenance events do not coincide with peak load.

_Remediation:_

> `doctl kubernetes cluster update <c> --maintenance-window="sunday 04:00"` (UTC).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.4` | Perform Automated Application Patch Management |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `doks`, `k8s`, `upgrade`

---

### `k8s-doks-maintenance-window-loud-hours`

**Maintenance window should fall outside business hours** &middot; severity `low` &middot; service `doks` &middot; resource `digitalocean.doks.cluster`

DOKS auto-upgrades + node-image refreshes run in the maintenance window. A window between 09:00-17:00 UTC catches most western business hours; production clusters should pick a quieter zone (typically 03:00-05:00 in the cluster's primary customer timezone). This is a hygiene check, not a hard fail.

_Remediation:_

> `doctl kubernetes cluster update <c> --maintenance-window=sunday=04:00`. Pick a day + hour that matches your traffic low. Pair with `do-account-monitoring-alert-coverage` so a maintenance-induced regression pages someone.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.4` | Perform Automated Application Patch Management |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.4` | Incident Response |

_Tags:_ `doks`, `k8s`, `maintenance`, `ops-hygiene`

---

### `k8s-doks-metrics-server-installed`

**metrics-server must be installed (HPA + kubectl top dependency)** &middot; severity `medium` &middot; service `doks` &middot; resource `digitalocean.doks.cluster`

DOKS ships metrics-server in the default add-on set but operators can opt out, and clusters older than 2023 may have been provisioned without it. Without metrics-server, HorizontalPodAutoscaler and `kubectl top` both fail silently. This check is manual-verify because there's no DO API for add-on state — operators run kubectl against the cluster.

_Remediation:_

> Confirm: `kubectl -n kube-system get deployment metrics-server`. Install if missing: `kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `addon`, `doks`, `k8s`, `manual-verify`

---

### `k8s-doks-nodepool-autoscale`

**DOKS node pools should enable autoscaling** &middot; severity `low` &middot; service `doks` &middot; resource `digitalocean.doks.nodepool`

Autoscaling lets the cluster grow under load and shrink under idle, matching capacity to demand. Manual sizing typically over-provisions for peak or under-provisions and trips workloads in surge.

_Remediation:_

> `doctl kubernetes cluster node-pool update <c> <np> --auto-scale=true --min-nodes=<n> --max-nodes=<n>`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `autoscale`, `doks`, `k8s`, `nodepool`

---

### `k8s-doks-nodepool-min-nodes`

**DOKS node pools should have min_nodes >= 2** &middot; severity `medium` &middot; service `doks` &middot; resource `digitalocean.doks.nodepool`

Even with autoscaling, a min_nodes of 1 means the cluster can drop to a single node — no HA, no rolling update headroom, and during a node replacement the cluster has zero capacity in that pool.

_Remediation:_

> `doctl kubernetes cluster node-pool update <c> <np> --min-nodes=2`. For HA workloads, min_nodes >= 3.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |

_Tags:_ `doks`, `ha`, `k8s`, `nodepool`

---

### `k8s-doks-nodepool-no-environment-tag`

**DOKS node pools should declare an environment tag** &middot; severity `low` &middot; service `doks` &middot; resource `digitalocean.doks.nodepool`

Tagging a node pool with the environment (prod / staging / dev) lets billing reports + monitoring alerts route on tag without re-deriving from the cluster name. CIS Controls v8 1.1 expects inventory classification at the asset level.

_Remediation:_

> Add a tag at create: `doctl kubernetes cluster node-pool create <c> --tag=env:production`. Existing pools cannot be retagged via doctl; recreate or use the TF resource.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `1.1` | Establish and Maintain Detailed Enterprise Asset Inventory |
| `iso27001` | `A.5.9` | Inventory of information and other associated assets |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `doks`, `k8s`, `nodepool`, `tagging`

---

### `k8s-doks-nodepool-no-taints`

**Non-default node pools should declare workload-isolation taints** &middot; severity `low` &middot; service `doks` &middot; resource `digitalocean.doks.nodepool`

Multi-tenant DOKS clusters typically segregate workloads by node pool (e.g. 'gpu', 'memory-optimised', 'ingress'). Without taints, the scheduler treats every pool as fair game and security-relevant isolation (egress proxies, secrets vaults) shares hosts with general workloads. Default pools can stay untainted; named pools should declare at least one.

_Remediation:_

> `doctl kubernetes cluster node-pool update <c> <np> --taint dedicated=gpu:NoSchedule`. Then set tolerations on the workloads that should target the pool.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.5.18` | Access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `doks`, `isolation`, `k8s`, `nodepool`

---

### `k8s-doks-nodepool-size-retired`

**DOKS node pools must not use retired droplet sizes** &middot; severity `medium` &middot; service `doks` &middot; resource `digitalocean.doks.nodepool`

DO periodically retires droplet sizes from the DOKS catalog. Pools on retired sizes cannot accept new nodes (autoscaling and replacement on failure both fail), and any pool with autoscaling = on + a retired size is one bad reboot away from being undersized.

_Remediation:_

> Recreate the pool on a supported size: `doctl kubernetes cluster node-pool create <c> --name <new> --size s-2vcpu-4gb` then `delete` the old pool. Drain workloads first.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.3` | Perform Automated Operating System Patch Management |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.1` | Capacity Management |

_Tags:_ `doks`, `k8s`, `nodepool`, `sizing`

---

### `k8s-doks-pod-security-standards-baseline`

**Pod Security Admission must enforce ≥ baseline on production namespaces** &middot; severity `high` &middot; service `doks` &middot; resource `digitalocean.doks.cluster`

PodSecurityPolicy is removed; Pod Security Admission (PSA) labels namespaces with enforce / audit / warn policies at baseline or restricted level. DOKS clusters default PSA to OFF in non-system namespaces. SOC2 CC6.6 + ISO A.8.18 + CIS K8s 5.2 each require pod-level security defaults; this finding flags the gap so the operator confirms enforcement is on.

_Remediation:_

> Label production namespaces: `kubectl label ns <ns> pod-security.kubernetes.io/enforce=baseline pod-security.kubernetes.io/warn=restricted pod-security.kubernetes.io/audit=restricted`. Roll out `warn=` first to find offending workloads, then flip enforce.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.6` | Securely Manage Enterprise Assets and Software |
| `iso27001` | `A.8.18` | Use of privileged utility programs |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `doks`, `k8s`, `manual-verify`, `psa`

---

### `k8s-doks-registry-integration`

**DOKS clusters should integrate with DO Container Registry** &middot; severity `low` &middot; service `doks` &middot; resource `digitalocean.doks.cluster`

Enabling registry integration places a dockerconfigjson Secret in every namespace, letting workloads pull from the DO private Container Registry without manually-managed pull credentials. Strict pull credentials beat sprawling imagePullSecret literals.

_Remediation:_

> `doctl kubernetes cluster registry add <cluster>`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.8.30` | Outsourced development |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `doks`, `k8s`, `registry`

---

### `k8s-doks-surge-upgrade`

**DOKS clusters should enable surge upgrades** &middot; severity `low` &middot; service `doks` &middot; resource `digitalocean.doks.cluster`

Surge upgrades provision replacement nodes before draining old ones — workloads stay available across rolling node-pool upgrades. Without surge, each upgrade hits a capacity dip equal to the node being replaced.

_Remediation:_

> `doctl kubernetes cluster update <c> --surge-upgrade=true`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.1` | Capacity Management |

_Tags:_ `doks`, `k8s`, `upgrade`

---

### `k8s-doks-version-deprecated`

**DOKS cluster version must not be on the DO deprecation list** &middot; severity `high` &middot; service `doks` &middot; resource `digitalocean.doks.cluster`

DigitalOcean unsupports DOKS minor versions roughly 14 months after release. Once unsupported, the cluster stops receiving control-plane patches and node-image refreshes — CVE exposure climbs unbounded. Pin a supported minor; let auto-upgrade keep it inside the supported window.

_Remediation:_

> Upgrade in maintenance window: `doctl kubernetes cluster upgrade <cluster-id> --version=1.30.x-do.x`. Stage in non-prod first; verify no PSA / admission-webhook breakage.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.3` | Perform Automated Operating System Patch Management |
| `cis-v8` | `7.4` | Perform Automated Application Patch Management |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |

_Tags:_ `doks`, `k8s`, `patching`, `version`

---

### `k8s-doks-vpc-attached`

**DOKS clusters should attach to a non-default VPC** &middot; severity `medium` &middot; service `doks` &middot; resource `digitalocean.doks.cluster`

DOKS clusters by default land in the region's default VPC, which is shared across the account. Attaching to a dedicated VPC isolates the cluster's network plane from other workloads and makes firewall rules easier to reason about.

_Remediation:_

> Create a dedicated VPC: `doctl vpcs create --name=k8s --region=<r>`. Recreate the cluster with `--vpc-uuid=<id>` (in-place VPC change is not supported).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.4` | Establish and Maintain Architecture Diagram(s) |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `doks`, `k8s`, `network`

---

### `k8s-eks-authentication-mode`

**EKS clusters should use API access entries (not aws-auth ConfigMap)** &middot; severity `low` &middot; service `eks` &middot; resource `aws.eks.cluster`

The legacy aws-auth ConfigMap is error-prone — one typo locks operators out of the cluster. EKS Access Entries (GA in 2024) are the API-driven replacement: per-principal grants without a YAML round-trip. `authenticationMode: API` or `API_AND_CONFIG_MAP` enables them.

_Remediation:_

> `aws eks update-cluster-config --name <c> --access-config authenticationMode=API_AND_CONFIG_MAP` (with migration window) then API once aws-auth is fully migrated.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `auth`, `eks`, `k8s`

---

### `k8s-eks-cluster-active`

**EKS clusters should be in ACTIVE status** &middot; severity `high` &middot; service `eks` &middot; resource `aws.eks.cluster`

A cluster in CREATING / UPDATING / DELETING is mid-lifecycle; in FAILED state it has a control-plane issue that requires AWS support to resolve. ACTIVE is the only steady-state.

_Remediation:_

> Open an AWS support case if a cluster is stuck in FAILED. For long UPDATING runs, check `aws eks describe-update ...` for the in-flight change.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `eks`, `k8s`, `reliability`

---

### `k8s-eks-control-plane-logging`

**EKS clusters should enable all control-plane log types** &middot; severity `medium` &middot; service `eks` &middot; resource `aws.eks.cluster`

Control-plane logging ships api / audit / authenticator / controllerManager / scheduler logs to CloudWatch. Without audit logs in particular, incident response on a cluster compromise is severely limited.

_Remediation:_

> `aws eks update-cluster-config --name <c> --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.10` | Retain Audit Logs |
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC4.1` | Ongoing and Separate Evaluations |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `eks`, `k8s`, `logging`

---

### `k8s-eks-irsa-enabled`

**EKS clusters should expose an OIDC provider for IRSA** &middot; severity `medium` &middot; service `eks` &middot; resource `aws.eks.cluster`

IAM Roles for Service Accounts (IRSA) requires the EKS cluster to expose an OIDC issuer. Without it, in-cluster workloads must use the node's instance profile credentials — a much broader privilege grant than per-SA roles.

_Remediation:_

> `eksctl utils associate-iam-oidc-provider --cluster <name>` (or terraform aws_iam_openid_connect_provider). Then annotate SAs with `eks.amazonaws.com/role-arn`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `eks`, `iam`, `irsa`, `k8s`

---

### `k8s-eks-nodegroup-bottlerocket`

**EKS node groups should use Bottlerocket or AL2023** &middot; severity `low` &middot; service `eks` &middot; resource `aws.eks.nodegroup`

Bottlerocket is purpose-built for K8s nodes — minimal attack surface, immutable rootfs, kubelet pre-configured. AL2023 is the modern Amazon Linux. AL2 is EOL on the EKS roadmap; Windows AMIs have their own audit considerations.

_Remediation:_

> Set `amiType: BOTTLEROCKET_x86_64` (or `BOTTLEROCKET_ARM_64`) on new node groups. Migrate existing AL2 node groups via blue/green replacement.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `iso27001` | `A.8.9` | Configuration management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.8` | Prevention or Detection of Unauthorized or Malicious Software |

_Tags:_ `ami`, `eks`, `k8s`, `nodegroup`

---

### `k8s-eks-nodegroup-launch-template`

**EKS node groups should use a launch template** &middot; severity `low` &middot; service `eks` &middot; resource `aws.eks.nodegroup`

Without a launch template, EKS provisions instances with default IMDS config (hop limit 2, allowing pods to reach the metadata service and acquire the node role's credentials). A custom launch template lets you set `httpPutResponseHopLimit: 1` plus user-data hardening.

_Remediation:_

> Create an EC2 launch template with `metadataOptions.httpPutResponseHopLimit: 1` and `httpTokens: required`. Reference it in the nodegroup spec.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.9` | Configuration management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `eks`, `imds`, `k8s`, `nodegroup`

---

### `k8s-eks-nodegroup-ssh`

**EKS node groups should not enable SSH remote access** &middot; severity `medium` &middot; service `eks` &middot; resource `aws.eks.nodegroup`

SSH into a node bypasses every K8s control: kubelet credentials, network policy, RBAC. The modern operational replacement is SSM Session Manager, which provides per-session auth + audit. Disable EC2-key-based SSH on node groups.

_Remediation:_

> Recreate the node group without `remoteAccess.ec2SshKey`. For break-glass node access, use SSM Session Manager with per-engineer IAM grants.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.5` | Centralize Network Authentication, Authorization, and Auditing (AAA) |
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `eks`, `k8s`, `nodegroup`, `ssh`

---

### `k8s-eks-nodegroup-version-skew`

**EKS node group version should match the cluster version** &middot; severity `medium` &middot; service `eks` &middot; resource `aws.eks.nodegroup`

K8s supports kubelet versions up to 3 minor releases behind the API server (post-1.28) — but the operational sweet spot is to keep node groups aligned. A persistent skew indicates a stalled upgrade.

_Remediation:_

> `aws eks update-nodegroup-version --cluster-name <c> --nodegroup-name <ng>`. For managed node groups, this triggers a rolling replacement.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.4` | Perform Automated Application Patch Management |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `eks`, `k8s`, `nodegroup`, `upgrade`

---

### `k8s-eks-private-endpoint`

**EKS clusters should enable the private API endpoint** &middot; severity `medium` &middot; service `eks` &middot; resource `aws.eks.cluster`

Enabling `endpointPrivateAccess` puts the API server on a VPC endpoint reachable from within the VPC without transit through the public internet. Even when public access is also enabled, the private endpoint is the preferred path for in-cluster controllers (which would otherwise NAT out and back in).

_Remediation:_

> `aws eks update-cluster-config --name <c> --resources-vpc-config endpointPrivateAccess=true`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.5` | Centralize Network Authentication, Authorization, and Auditing (AAA) |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `eks`, `endpoint`, `k8s`

---

### `k8s-eks-public-endpoint-open`

**EKS API endpoint should not be publicly reachable without CIDR restriction** &middot; severity `high` &middot; service `eks` &middot; resource `aws.eks.cluster`

An EKS cluster with `endpointPublicAccess: true` and publicAccessCidrs of 0.0.0.0/0 exposes the Kubernetes API to the entire internet. The first defense is RBAC, but the primary mitigation is to restrict the API endpoint to your operator CIDRs or run with private-only access.

_Remediation:_

> `aws eks update-cluster-config --name <c> --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs=<your-cidr>`. Better: switch to `endpointPrivateAccess=true,endpointPublicAccess=false` and reach the API via VPN/bastion.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.5` | Centralize Network Authentication, Authorization, and Auditing (AAA) |
| `cis-v8` | `13.6` | Collect Network Traffic Flow Logs |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `critical`, `eks`, `exposure`, `k8s`

---

### `k8s-eks-secrets-encryption`

**EKS clusters should encrypt secrets with KMS** &middot; severity `high` &middot; service `eks` &middot; resource `aws.eks.cluster`

EKS supports envelope encryption of Kubernetes Secrets with a customer KMS key. Without it, Secret values rest in plaintext in etcd. Enabling encryptionConfig at cluster create is the only path; re-encryption of existing clusters requires a cluster replacement.

_Remediation:_

> At cluster creation: `aws eks create-cluster ... --encryption-config resources=secrets,provider={keyArn=<arn>}`. For existing clusters, plan a blue/green migration.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `iso27001` | `A.8.10` | Information deletion |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `eks`, `encryption`, `k8s`, `secrets`

---

### `k8s-eks-version-supported`

**EKS clusters should run a supported K8s version** &middot; severity `high` &middot; service `eks` &middot; resource `aws.eks.cluster`

EKS supports each minor version for 14 months. A cluster on a deprecated minor will be force-upgraded by AWS, often at an inconvenient time. Stay on a current minor (1.28+ as of mid-2026).

_Remediation:_

> `aws eks update-cluster-version --name <c> --kubernetes-version 1.30`. Plan node-group version updates after the control plane is upgraded.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.4` | Perform Automated Application Patch Management |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |

_Tags:_ `eks`, `k8s`, `upgrade`

---

### `k8s-gke-binary-authorization`

**GKE clusters should enable Binary Authorization** &middot; severity `medium` &middot; service `gke` &middot; resource `gcp.gke.cluster`

Binary Authorization enforces that container images come from approved repositories and (optionally) carry attestations from your CI pipeline. It is the GCP-native supply-chain enforcement layer for K8s.

_Remediation:_

> `gcloud container clusters update <c> --binauthz-evaluation-mode=PROJECT_SINGLETON_POLICY_ENFORCE`. Create attestation policies in Binary Authorization.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `16.4` | Establish and Manage an Inventory of Third-Party Software Components |
| `cis-v8` | `16.6` | Establish and Maintain a Severity Rating System and Process for Application Vulnerabilities |
| `iso27001` | `A.8.30` | Outsourced development |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `gke`, `k8s`, `supply-chain`

---

### `k8s-gke-legacy-abac`

**GKE clusters should not enable legacy ABAC** &middot; severity `high` &middot; service `gke` &middot; resource `gcp.gke.cluster`

Legacy ABAC predates RBAC; GKE leaves the flag exposed for old clusters. With it on, every authenticated user has broad permissions regardless of Role/ClusterRoleBinding.

_Remediation:_

> `gcloud container clusters update <c> --no-enable-legacy-authorization` (irreversible — verify RBAC is correctly configured first).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.7` | Centralize Access Control |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `gke`, `k8s`, `legacy`, `rbac`

---

### `k8s-gke-logging-monitoring`

**GKE clusters should enable logging and monitoring** &middot; severity `medium` &middot; service `gke` &middot; resource `gcp.gke.cluster`

Cloud Logging + Cloud Monitoring integration is the GKE-native observability story. Without it, audit and workload logs do not flow to Cloud Logging — degraded incident response.

_Remediation:_

> `gcloud container clusters update <c> --logging=SYSTEM,WORKLOAD --monitoring=SYSTEM`. For compliance-sensitive workloads also include `--logging=...,APISERVER,AUDIT`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.10` | Retain Audit Logs |
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC4.1` | Ongoing and Separate Evaluations |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `gke`, `k8s`, `logging`

---

### `k8s-gke-master-authorized-networks`

**GKE clusters should restrict control-plane CIDR access** &middot; severity `high` &middot; service `gke` &middot; resource `gcp.gke.cluster`

Master Authorized Networks restricts which source CIDRs can reach the GKE control plane. Without it (or with 0.0.0.0/0 in the list), kubectl from anywhere on the internet can attempt to authenticate.

_Remediation:_

> `gcloud container clusters update <c> --enable-master-authorized-networks --master-authorized-networks <cidr1>,<cidr2>`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.5` | Centralize Network Authentication, Authorization, and Auditing (AAA) |
| `cis-v8` | `13.6` | Collect Network Traffic Flow Logs |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `exposure`, `gke`, `k8s`

---

### `k8s-gke-network-policy`

**GKE clusters should enable network policy** &middot; severity `medium` &middot; service `gke` &middot; resource `gcp.gke.cluster`

GKE's network policy (Calico-based) is the enforcement layer for NetworkPolicy resources. Without it, NetworkPolicy objects exist but are no-ops — every workload can talk to every other workload.

_Remediation:_

> `gcloud container clusters update <c> --enable-network-policy`. Existing clusters require a rolling node-pool replacement; plan a maintenance window.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.4` | Establish and Maintain Architecture Diagram(s) |
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `gke`, `k8s`, `network-policy`

---

### `k8s-gke-nodepool-auto-repair`

**GKE node pools should enable auto-repair** &middot; severity `low` &middot; service `gke` &middot; resource `gcp.gke.nodepool`

Auto-repair detects unhealthy nodes (failed kubelet heartbeats, persistent NotReady) and replaces them. Disabling it means a failed node sits in the cluster until manual intervention.

_Remediation:_

> `gcloud container node-pools update <np> --cluster=<c> --enable-autorepair`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `gke`, `k8s`, `nodepool`, `reliability`

---

### `k8s-gke-nodepool-auto-upgrade`

**GKE node pools should enable auto-upgrade** &middot; severity `low` &middot; service `gke` &middot; resource `gcp.gke.nodepool`

Auto-upgrade keeps node pool versions aligned with the cluster control plane on the release channel's cadence. Without it, the node pool drifts and may exceed the supported skew.

_Remediation:_

> `gcloud container node-pools update <np> --cluster=<c> --enable-autoupgrade`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.4` | Perform Automated Application Patch Management |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `gke`, `k8s`, `nodepool`, `upgrade`

---

### `k8s-gke-nodepool-cos`

**GKE node pools should use Container-Optimized OS** &middot; severity `low` &middot; service `gke` &middot; resource `gcp.gke.nodepool`

Container-Optimized OS (COS) is Google's hardened, minimal node OS. Ubuntu node pools are supported but have a larger attack surface and a slower patch cadence than COS.

_Remediation:_

> Create node pools with `--image-type=COS_CONTAINERD`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.8` | Prevention or Detection of Unauthorized or Malicious Software |

_Tags:_ `gke`, `k8s`, `nodepool`, `os`

---

### `k8s-gke-nodepool-default-sa`

**GKE node pools should not use the default Compute Engine SA** &middot; severity `medium` &middot; service `gke` &middot; resource `gcp.gke.nodepool`

The default Compute Engine SA has the Editor role on the project by default. Every node pool using it gives every in-cluster workload (and any pod that escapes to the node) project-Editor — a serious privilege escalation surface.

_Remediation:_

> Create a dedicated minimum-privilege SA for nodes (roles/container.nodeServiceAccount + roles/monitoring.metricWriter + roles/logging.logWriter). Use `--service-account=<sa-email>` on node pool create.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `gke`, `iam`, `k8s`, `nodepool`

---

### `k8s-gke-private-cluster`

**GKE clusters should run with private nodes** &middot; severity `high` &middot; service `gke` &middot; resource `gcp.gke.cluster`

Without `privateClusterConfig.enablePrivateNodes`, every node receives a public IP — a sprawling attack surface plus accidental NAT-less egress. Private clusters keep node IPs RFC1918 and route egress through Cloud NAT.

_Remediation:_

> At cluster creation: `gcloud container clusters create ... --enable-private-nodes`. Existing clusters need a migration; the in-place toggle is limited.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.5` | Centralize Network Authentication, Authorization, and Auditing (AAA) |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `gke`, `k8s`, `private`

---

### `k8s-gke-release-channel`

**GKE clusters should subscribe to a release channel** &middot; severity `low` &middot; service `gke` &middot; resource `gcp.gke.cluster`

Release channels (RAPID/REGULAR/STABLE) let Google manage cluster upgrades on a predictable cadence. Without a channel, the cluster sticks at its creation version forever unless an operator manually triggers upgrades.

_Remediation:_

> `gcloud container clusters update <c> --release-channel=regular`. RAPID for dev, REGULAR for most, STABLE for risk-averse production.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.4` | Perform Automated Application Patch Management |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |

_Tags:_ `gke`, `k8s`, `upgrade`

---

### `k8s-gke-shielded-nodes`

**GKE clusters should enable Shielded Nodes** &middot; severity `medium` &middot; service `gke` &middot; resource `gcp.gke.cluster`

Shielded Nodes turn on secure boot + integrity monitoring on the underlying GCE instances. Without it, a node-level bootkit / rootkit can persist across reboots and silently exfiltrate kubelet credentials.

_Remediation:_

> `gcloud container clusters update <c> --enable-shielded-nodes`. Combine with shielded VM config on each node pool.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.9` | Configuration management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.8` | Prevention or Detection of Unauthorized or Malicious Software |

_Tags:_ `gke`, `k8s`, `shielded`

---

### `k8s-gke-workload-identity`

**GKE clusters should enable Workload Identity** &middot; severity `high` &middot; service `gke` &middot; resource `gcp.gke.cluster`

Workload Identity is the GKE-native way to bind Kubernetes ServiceAccounts to GCP IAM Service Accounts. Without it, in-cluster workloads inherit the node's compute engine SA — typically over-privileged and shared across every workload on the node.

_Remediation:_

> `gcloud container clusters update <c> --workload-pool=<project>.svc.id.goog`. Annotate K8s SAs with `iam.gke.io/gcp-service-account` to bind.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `gke`, `iam`, `k8s`

---

### `k8s-ingress-class-set`

**Ingresses should set ingressClassName explicitly** &middot; severity `low` &middot; service `network` &middot; resource `k8s.ingress`

Without `ingressClassName`, every ingress controller in the cluster may claim and serve the Ingress — leading to unpredictable routing on multi-controller clusters. Setting the class explicitly is unambiguous and the modern best practice.

_Remediation:_

> Set `spec.ingressClassName: <name>` (e.g. nginx, traefik, alb) on every Ingress. Remove the deprecated kubernetes.io/ingress.class annotation.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `hygiene`, `ingress`, `k8s`, `network`

---

### `k8s-ingress-dangerous-annotations`

**Ingresses should not use snippet annotations (RCE risk)** &middot; severity `high` &middot; service `network` &middot; resource `k8s.ingress`

ingress-nginx allows arbitrary nginx configuration via the `configuration-snippet`, `server-snippet`, `auth-snippet`, and `modsecurity-snippet` annotations. CVEs in this surface have repeatedly turned Ingress write access into cluster-wide RCE — most recently CVE-2025-1974 ('IngressNightmare'). Disable the snippet annotations cluster-wide (`--enable-snippets=false`) and audit any existing use.

_Remediation:_

> Remove the snippet annotations and reconfigure via ConfigMap settings or a dedicated module. Set `allow-snippet-annotations: false` on the ingress controller and `enable-snippets: false`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.5` | Centralize Network Authentication, Authorization, and Auditing (AAA) |
| `cis-v8` | `16.13` | Conduct Application Penetration Testing |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.32` | Change management |
| `iso27001` | `A.8.9` | Configuration management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |
| `soc2` | `CC6.8` | Prevention or Detection of Unauthorized or Malicious Software |

_Tags:_ `critical`, `ingress`, `k8s`, `network`, `rce`

---

### `k8s-ingress-default-backend`

**Ingresses should not declare a default backend** &middot; severity `low` &middot; service `network` &middot; resource `k8s.ingress`

A default backend catches every unmatched request and sends it to the named service. That makes the ingress reachable for arbitrary hostnames (path traversal, SSRF surface). Most production setups prefer explicit host+path rules and let unmatched traffic 404.

_Remediation:_

> Remove `spec.defaultBackend` and add explicit `rules`. If you genuinely need a catch-all, document the intent.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.5` | Centralize Network Authentication, Authorization, and Auditing (AAA) |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `ingress`, `k8s`, `network`

---

### `k8s-ingress-tls-missing`

**Ingresses should configure TLS** &middot; severity `medium` &middot; service `network` &middot; resource `k8s.ingress`

An Ingress without a `spec.tls` section terminates plain HTTP at the ingress controller. Outside of behind-a-LB setups where TLS terminates upstream, this exposes traffic in cleartext.

_Remediation:_

> Add a `spec.tls` entry referencing a Secret of type kubernetes.io/tls. cert-manager + Let's Encrypt is the standard automated path.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `ingress`, `k8s`, `network`, `tls`

---

### `k8s-job-backoff-limit`

**Jobs should set a sensible backoffLimit** &middot; severity `low` &middot; service `jobs` &middot; resource `k8s.job`

A Job with no `backoffLimit` (or an excessively large one) retries a failing pod indefinitely, often masking a real defect and consuming cluster capacity. The K8s default of 6 is a reasonable ceiling; anything materially higher should come with a documented reason.

_Remediation:_

> Set `spec.backoffLimit` to between 0 and 10 depending on whether the work is idempotent. Pair with `activeDeadlineSeconds` for a hard timeout.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `jobs`, `k8s`, `reliability`

---

### `k8s-limitrange-container-defaults`

**LimitRanges should set container default requests/limits** &middot; severity `low` &middot; service `cluster` &middot; resource `k8s.limitrange`

A LimitRange without `default` and `defaultRequest` for the Container type does not actually supply defaults to unannotated pods — it only enforces min/max if those are set. Defaults are the operational primitive that makes the pod-security resource-limit check pass for every pod.

_Remediation:_

> Add `default` and `defaultRequest` for `cpu` and `memory` to the LimitRange's container entry.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.1` | Capacity Management |

_Tags:_ `k8s`, `limitrange`

---

### `k8s-mutating-webhook-side-effects`

**Mutating webhooks should declare sideEffects: None or NoneOnDryRun** &middot; severity `low` &middot; service `admission` &middot; resource `k8s.mutatingwebhookconfig`

`sideEffects: Some` or unset means the webhook may call out to external systems during admission, which makes `kubectl --dry-run=server` unreliable and can stall admission under load. Declare side-effect semantics explicitly.

_Remediation:_

> Set `sideEffects: None` if the webhook is purely local, or `NoneOnDryRun` if it skips side effects on dry-run requests.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.32` | Change management |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `admission`, `k8s`, `webhook`

---

### `k8s-namespace-default-workload`

**Workloads should not run in the default namespace** &middot; severity `medium` &middot; service `cluster` &middot; resource `k8s.pod`

The `default` namespace exists as the no-op landing zone for new clusters. Workloads scheduled there inherit the namespace's `default` ServiceAccount (which has whatever bindings exist on it cluster-wide), share quota and policy with every other lazy deployment, and complicate audit. Real workloads belong in named namespaces.

_Remediation:_

> Create per-app namespaces and move workloads into them. Apply PSA labels, NetworkPolicies, ResourceQuotas, and LimitRanges to each.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `default`, `k8s`, `namespace`

---

### `k8s-namespace-limitrange-missing`

**Namespaces should have at least one LimitRange** &middot; severity `low` &middot; service `cluster` &middot; resource `k8s.namespace`

A LimitRange supplies default CPU/memory requests + limits to pods that don't declare them. Without one, the Pod Security checks for resource limits will keep failing for every workload an operator forgets to annotate.

_Remediation:_

> Apply a LimitRange to each namespace with sensible container defaults (e.g. 100m/128Mi requests, 1/1Gi limits).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `k8s`, `namespace`, `quota`

---

### `k8s-namespace-psa-label`

**Namespaces should set pod-security.kubernetes.io enforce label** &middot; severity `medium` &middot; service `cluster` &middot; resource `k8s.namespace`

Pod Security Admission (PSA, GA in K8s 1.25) uses namespace labels to enforce the baseline/restricted profiles. Without an `enforce` label, the namespace runs the cluster default — usually `privileged`, meaning no Pod Security gate is in place. Set `enforce: restricted` on workload namespaces.

_Remediation:_

> `kubectl label namespace <ns> pod-security.kubernetes.io/enforce=restricted`. Stage with `audit` or `warn` levels first if workloads might violate.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.9` | Configuration management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `k8s`, `namespace`, `psa`

---

### `k8s-namespace-resourcequota-missing`

**Namespaces should have at least one ResourceQuota** &middot; severity `medium` &middot; service `cluster` &middot; resource `k8s.namespace`

A namespace without a ResourceQuota has no cap on how much CPU, memory, pods, or storage it can consume. A buggy controller, a fork-bomb, or an OOM-storm in one namespace can starve the whole cluster. Quotas are the K8s primitive for namespace-level capacity guardrails.

_Remediation:_

> Create a `ResourceQuota` per namespace with hard caps on `pods`, `limits.cpu`, `limits.memory`, and `count/secrets`/`count/configmaps` at minimum.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `k8s`, `namespace`, `quota`

---

### `k8s-namespace-stuck-terminating`

**Namespaces should not stay in Terminating phase** &middot; severity `low` &middot; service `cluster` &middot; resource `k8s.namespace`

A namespace that stays in `Terminating` indicates a finalizer-stuck deletion — usually a CRD whose controller has been removed without cleaning up its custom resources. Until resolved, the namespace cannot be recreated and its resources are in limbo.

_Remediation:_

> `kubectl get namespace <name> -o json` reveals the blocking finalizer. Either restore the controller, manually clean its CRs, or (as a last resort) force-remove the finalizer.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `hygiene`, `k8s`, `namespace`

---

### `k8s-networkpolicy-allow-all-egress`

**NetworkPolicies should not have allow-all egress rules** &middot; severity `medium` &middot; service `network` &middot; resource `k8s.networkpolicy`

An empty `to` block in an egress rule allows traffic to anywhere — internal, external, the cloud control plane. The legitimate use cases are narrow; the dangerous ones are common.

_Remediation:_

> List the allowed destinations explicitly: `to: [{podSelector: {matchLabels: {...}}}]` for in-cluster, `to: [{ipBlock: {cidr: ..., except: ['169.254.169.254/32']}}]` for external (with the cloud IMDS excluded).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.4` | Establish and Maintain Architecture Diagram(s) |
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `egress`, `k8s`, `network`, `policy`

---

### `k8s-networkpolicy-allow-all-ingress`

**NetworkPolicies should not have allow-all ingress rules** &middot; severity `medium` &middot; service `network` &middot; resource `k8s.networkpolicy`

A NetworkPolicy with an empty `from` block (or a rule with no ingress fields beyond ports) allows traffic from anywhere in the cluster. This is rarely the intent — usually the operator meant 'from any pod in this namespace,' which requires an empty `podSelector` peer.

_Remediation:_

> Specify the source of allowed traffic explicitly: `from: [{podSelector: {}}]` for same-namespace, `from: [{namespaceSelector: {matchLabels: {...}}}]` for cross-namespace, `from: [{ipBlock: {cidr: ...}}]` for external.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.4` | Establish and Maintain Architecture Diagram(s) |
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `k8s`, `network`, `policy`

---

### `k8s-networkpolicy-default-deny-egress`

**Each namespace should have a default-deny egress NetworkPolicy** &middot; severity `medium` &middot; service `network` &middot; resource `k8s.namespace`

Default-deny egress is the second half of namespace isolation. Without it, a compromised workload can call out to any internal service plus any external endpoint, exfiltrating data or pivoting to the cloud control plane via the node's IMDS. Pair with explicit allow rules to in-cluster DNS, upstream APIs, and any external dependencies.

_Remediation:_

> Apply a default-deny egress NetworkPolicy (`podSelector: {}`, `policyTypes: [Egress]`, no egress rules) plus allow-list rules to kube-dns and required external endpoints.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.4` | Establish and Maintain Architecture Diagram(s) |
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `default-deny`, `egress`, `k8s`, `network`, `policy`

---

### `k8s-networkpolicy-default-deny-ingress`

**Each namespace should have a default-deny ingress NetworkPolicy** &middot; severity `high` &middot; service `network` &middot; resource `k8s.namespace`

Without a default-deny ingress NetworkPolicy, every pod in the namespace is reachable from every other pod in the cluster. A compromise of one pod becomes a lateral-movement primitive. The default-deny pattern is `podSelector: {}` + `policyTypes: [Ingress]` and no ingress rules — that baselines deny-all, and additive policies open specific flows.

_Remediation:_

> Apply the default-deny manifest to every workload namespace. Then add allow-list NetworkPolicies for the specific flows each workload needs.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.4` | Establish and Maintain Architecture Diagram(s) |
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `default-deny`, `k8s`, `network`, `policy`

---

### `k8s-networkpolicy-empty-selector`

**NetworkPolicies with empty podSelector apply to every pod** &middot; severity `low` &middot; service `network` &middot; resource `k8s.networkpolicy`

An empty `podSelector` matches every pod in the namespace. That is the right choice for default-deny baselines but the wrong choice for additive allow-list policies — every such allow rule applies to every pod. Mostly informational; verify intent.

_Remediation:_

> If this is a default-deny policy, ignore (or rename the policy `default-deny`). If it is an additive allow rule, add a `matchLabels` clause to restrict scope.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `informational`, `k8s`, `network`, `policy`

---

### `k8s-networkpolicy-from-all-namespaces`

**NetworkPolicies should not allow ingress from all namespaces** &middot; severity `medium` &middot; service `network` &middot; resource `k8s.networkpolicy`

An ingress peer with `namespaceSelector: {}` selects every namespace in the cluster. The intent is usually to allow traffic from a specific tier (e.g. all `monitoring` namespaces) — instead it grants every workload from every tenant. Always pair namespaceSelector with at least one matchLabels rule.

_Remediation:_

> Add labels to source namespaces and reference them: `namespaceSelector: {matchLabels: {tier: monitoring}}`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.4` | Establish and Maintain Architecture Diagram(s) |
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `k8s`, `network`, `policy`

---

### `k8s-networkpolicy-namespace-coverage`

**Workload namespaces should have at least one NetworkPolicy** &middot; severity `medium` &middot; service `network` &middot; resource `k8s.namespace`

A namespace with no NetworkPolicy resources has a flat allow-all network. The bar for posture compliance frameworks (SOC 2, ISO 27001, NIST) is that *some* network segmentation exists. Default-deny is preferred (see related checks); even an allow-list policy is better than none.

_Remediation:_

> Apply at least one NetworkPolicy. The default-deny baseline is the safest starting point.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.4` | Establish and Maintain Architecture Diagram(s) |
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `k8s`, `network`, `policy`

---

### `k8s-node-container-runtime`

**Nodes should use containerd or cri-o, not dockershim** &middot; severity `medium` &middot; service `nodes` &middot; resource `k8s.node`

Dockershim was removed in K8s 1.24 (2022). Any node still showing a `docker://` runtime is running an unsupported kubelet build. containerd is the modern default; cri-o is the Red Hat-blessed alternative.

_Remediation:_

> Upgrade the kubelet / node image to one shipping containerd. For managed K8s (EKS/GKE/AKS/DOKS), select a containerd node group / image type.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `cis-v8` | `7.4` | Perform Automated Application Patch Management |
| `iso27001` | `A.8.32` | Change management |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `k8s`, `nodes`, `runtime`

---

### `k8s-node-control-plane-taint`

**Control-plane nodes should carry NoSchedule taint** &middot; severity `medium` &middot; service `nodes` &middot; resource `k8s.node`

Without the standard `node-role.kubernetes.io/control-plane:NoSchedule` taint, application pods can land on master nodes alongside the API server, controllers, and etcd. A workload OOM-killing kube-apiserver is the textbook way to brick a cluster.

_Remediation:_

> `kubectl taint node <name> node-role.kubernetes.io/control-plane=:NoSchedule`. For managed clusters this is set automatically; only flag self-managed setups missing the taint.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `control-plane`, `k8s`, `nodes`

---

### `k8s-node-disk-pressure`

**Nodes should not report DiskPressure** &middot; severity `medium` &middot; service `nodes` &middot; resource `k8s.node`

DiskPressure indicates the node's image filesystem or root filesystem is filling up. Once eviction thresholds are crossed, the kubelet kills pods to reclaim space — typically hitting the largest-image workloads first.

_Remediation:_

> Clean unused images (`crictl rmi`), bump the node's disk size, or migrate workloads to a larger instance type.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `k8s`, `nodes`, `pressure`

---

### `k8s-node-memory-pressure`

**Nodes should not report MemoryPressure** &middot; severity `medium` &middot; service `nodes` &middot; resource `k8s.node`

MemoryPressure means the kubelet is about to start evicting pods to free memory. Persistent pressure indicates either overcommit or an OOM-prone workload.

_Remediation:_

> Lower pod memory requests, scale down per-node density, or move to a larger instance type.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `k8s`, `nodes`, `pressure`

---

### `k8s-node-not-ready`

**Nodes should be in Ready state** &middot; severity `high` &middot; service `nodes` &middot; resource `k8s.node`

A NotReady node still consumes cluster capacity (pods are scheduled to it before the condition flips) but cannot actually run workloads. Investigate: kubelet down, network partition, disk full, kernel deadlock.

_Remediation:_

> `kubectl describe node <name>` for the failing condition. Common fixes: restart kubelet, free disk space, reboot the node.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `k8s`, `nodes`, `reliability`

---

### `k8s-node-old-image`

**Nodes should be replaced within 1 year of creation** &middot; severity `medium` &middot; service `nodes` &middot; resource `k8s.node`

Long-lived nodes accumulate kernel CVEs and miss image-level improvements (containerd version, kubelet bug fixes). Best practice: rotate nodes through replacement on a schedule (managed K8s does this automatically when auto-upgrade is enabled).

_Remediation:_

> For managed K8s, enable node auto-upgrade. For self-managed, schedule periodic image rebuilds and rolling node replacement.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.4` | Perform Automated Application Patch Management |
| `iso27001` | `A.8.32` | Change management |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `k8s`, `nodes`, `patching`

---

### `k8s-node-pid-pressure`

**Nodes should not report PIDPressure** &middot; severity `medium` &middot; service `nodes` &middot; resource `k8s.node`

PIDPressure indicates the node is running out of process IDs. This is rare in modern setups but can be triggered by fork-bomb workloads or processes leaking threads.

_Remediation:_

> Identify the offending workload via `kubectl top pod --all-namespaces --sort-by=cpu` and the per-pod process count. Cap with `pids` ResourceQuota or scale.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `k8s`, `nodes`, `pressure`

---

### `k8s-node-region-label`

**Worker nodes should carry topology.kubernetes.io/region** &middot; severity `low` &middot; service `nodes` &middot; resource `k8s.node`

Multi-region clusters use the region label to scope workloads to specific cloud regions. Single-region clusters still benefit by being explicit; tooling that consumes topology labels (e.g. topology-aware service routing) requires it.

_Remediation:_

> Most cloud controllers set this automatically. `kubectl label node <name> topology.kubernetes.io/region=us-east-1`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.1` | Capacity Management |

_Tags:_ `k8s`, `nodes`, `topology`

---

### `k8s-node-unschedulable`

**Nodes should not stay cordoned indefinitely** &middot; severity `low` &middot; service `nodes` &middot; resource `k8s.node`

A node with `spec.unschedulable: true` (cordoned) is intentionally taken out of rotation — typical during draining for upgrades or hardware replacement. A node stuck cordoned is usually a forgotten maintenance window.

_Remediation:_

> `kubectl uncordon <name>` to put it back into rotation, or `kubectl delete node <name>` if it was truly removed.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `hygiene`, `k8s`, `nodes`

---

### `k8s-node-zone-label`

**Worker nodes should carry topology.kubernetes.io/zone** &middot; severity `low` &middot; service `nodes` &middot; resource `k8s.node`

Topology-aware scheduling (`topologyKey: topology.kubernetes.io/zone`) lets controllers spread replicas across availability zones. Without the standard label set, the primitive is unavailable and pod anti-affinity falls back to hostname-only spread.

_Remediation:_

> Most cloud-provider cluster controllers set this automatically. If self-managed, label nodes: `kubectl label node <name> topology.kubernetes.io/zone=us-east-1a`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |

_Tags:_ `k8s`, `nodes`, `topology`

---

### `k8s-pod-allow-privilege-escalation`

**Containers should not allow privilege escalation** &middot; severity `high` &middot; service `pod-security` &middot; resource `k8s.pod`

`allowPrivilegeEscalation: true` (or unset, which defaults to true) means the container's process can gain more privileges than its parent via setuid binaries or capabilities. The hardened baseline sets this to false on every container.

_Remediation:_

> Add `securityContext.allowPrivilegeEscalation: false` to every container spec. Enforce cluster-wide via the Pod Security Admission `restricted` profile.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `cis-v8` | `6.3` | Require MFA for Externally-Exposed Applications |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.9` | Configuration management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `k8s`, `pod-security`, `privilege-escalation`

---

### `k8s-pod-automount-sa-token`

**Pods that don't call the API should disable SA token mount** &middot; severity `medium` &middot; service `pod-security` &middot; resource `k8s.pod`

Every pod by default has the namespace's default ServiceAccount token mounted at /var/run/secrets/.../token. Pods that never call the Kubernetes API gain nothing from that token but expose it to any code-execution compromise. Setting `automountServiceAccountToken: false` is the safe baseline; opt back in per-workload that legitimately needs API access.

_Remediation:_

> Set `automountServiceAccountToken: false` at the pod level. For workloads that need API access, dedicate a ServiceAccount with the minimum required Role and set `automountServiceAccountToken: true` explicitly on the SA.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.7` | Centralize Access Control |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `k8s`, `pod-security`, `service-account`

---

### `k8s-pod-capabilities-drop-all`

**Containers should drop all Linux capabilities by default** &middot; severity `medium` &middot; service `pod-security` &middot; resource `k8s.pod`

Containers inherit a default Linux capability set from the runtime, including CHOWN, DAC_OVERRIDE, FSETID, KILL, SETUID, and others. Dropping ALL and then adding back only what is needed (the restricted PSA profile requires this) is the canonical hardening baseline.

_Remediation:_

> Add `securityContext.capabilities.drop: [ALL]` to every container. Then add the minimum needed back via `capabilities.add`; many web apps need none.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.9` | Configuration management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `capabilities`, `k8s`, `pod-security`

---

### `k8s-pod-dangerous-capabilities`

**Containers should not add high-risk Linux capabilities** &middot; severity `high` &middot; service `pod-security` &middot; resource `k8s.pod`

Capabilities like NET_ADMIN, SYS_ADMIN, SYS_PTRACE, SYS_MODULE, and BPF give the container near-root access to network state, kernel internals, or arbitrary processes on the node. Granting one of these is a legitimate but high-bar choice; a workload that adds them without justification is a posture failure.

_Remediation:_

> Audit `capabilities.add` on every container. Keep only NET_BIND_SERVICE (for binding to ports <1024) without further review; everything else requires a written justification.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `cis-v8` | `6.3` | Require MFA for Externally-Exposed Applications |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.9` | Configuration management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `capabilities`, `k8s`, `pod-security`

---

### `k8s-pod-host-ipc`

**Pods should not share the host IPC namespace** &middot; severity `high` &middot; service `pod-security` &middot; resource `k8s.pod`

`spec.hostIPC: true` shares the node's SysV IPC and POSIX shared memory with the pod. Almost no production workload needs this; it exists for legacy unix-IPC integrations.

_Remediation:_

> Remove `spec.hostIPC` (defaults to false).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `host-namespace`, `k8s`, `pod-security`

---

### `k8s-pod-host-network`

**Pods should not use the host network** &middot; severity `high` &middot; service `pod-security` &middot; resource `k8s.pod`

`spec.hostNetwork: true` puts the pod in the node's network namespace. It can bind to any node-local port, sniff traffic on any node interface, and bypass NetworkPolicy entirely. Only system add-ons (kube-proxy, CNI agents) need it.

_Remediation:_

> Remove `spec.hostNetwork` (defaults to false). For node-local services, use a `hostPort` declaration on a specific container port instead — narrower blast radius.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.5` | Centralize Network Authentication, Authorization, and Auditing (AAA) |
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `host-namespace`, `k8s`, `pod-security`

---

### `k8s-pod-host-path-volume`

**Pods should not mount sensitive hostPath volumes** &middot; severity `high` &middot; service `pod-security` &middot; resource `k8s.pod`

`hostPath` mounts give the pod direct read/write access to a path on the node's filesystem. A hostPath onto /, /etc, /var/run/docker.sock, or /proc is a container escape in slow motion. Even narrowly-scoped hostPath mounts are an audit liability — there is almost always a better K8s primitive.

_Remediation:_

> Replace hostPath with a CSI-provided PersistentVolume, a ConfigMap, or a Secret depending on the use case. The `local-path` CSI provisioner is the right substitute for node-local persistent data.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.13` | Information backup |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `host-fs`, `k8s`, `pod-security`

---

### `k8s-pod-host-pid`

**Pods should not share the host PID namespace** &middot; severity `high` &middot; service `pod-security` &middot; resource `k8s.pod`

`spec.hostPID: true` lets the pod see every process on the node — useful for debugging, dangerous for production. An attacker with code execution in a hostPID pod can read environment variables and /proc/<pid>/cmdline of every other process on the node.

_Remediation:_

> Remove `spec.hostPID` (defaults to false). For diagnostic workloads, use `kubectl debug` or an ephemeral debug container instead of a permanent hostPID-enabled pod.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `host-namespace`, `k8s`, `pod-security`

---

### `k8s-pod-host-port`

**Containers should not declare hostPort** &middot; severity `medium` &middot; service `pod-security` &middot; resource `k8s.pod`

A container with `hostPort` binds to a port on the underlying node, bypassing the Service abstraction and NetworkPolicy. Two hostPort pods cannot land on the same node. Only DaemonSets implementing node-local infrastructure (CNI agents, log forwarders) have a legitimate need.

_Remediation:_

> Remove `hostPort` from every container port. For externally-reachable workloads, use a Service of type NodePort or LoadBalancer.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.5` | Centralize Network Authentication, Authorization, and Auditing (AAA) |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `k8s`, `network`, `pod-security`

---

### `k8s-pod-image-pull-policy`

**Containers with mutable tags should set imagePullPolicy=Always** &middot; severity `low` &middot; service `pod-security` &middot; resource `k8s.pod`

When using a mutable tag (`:latest` or any non-pinned tag), the cached image on a node can drift from the registry. `imagePullPolicy: Always` forces the kubelet to consult the registry on every pod start, defeating cache poisoning and making rollouts deterministic. Pinned-digest images can use IfNotPresent safely.

_Remediation:_

> Either pin to a digest (preferred) or set `imagePullPolicy: Always` on every container using a tag that can mutate.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `16.4` | Establish and Manage an Inventory of Third-Party Software Components |
| `iso27001` | `A.8.30` | Outsourced development |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `image`, `k8s`, `pod-security`, `supply-chain`

---

### `k8s-pod-image-tag-latest`

**Container images should not use the :latest tag** &middot; severity `medium` &middot; service `pod-security` &middot; resource `k8s.pod`

`:latest` is a mutable, untracked tag — what runs on Tuesday may not be what runs on Wednesday. It breaks rollback, breaks reproducibility, and silently delivers supply-chain updates without operator review. A pinned tag or, better, an image digest is the only defensible choice in production.

_Remediation:_

> Pin every image to a specific tag (`v1.2.3`) or a digest (`@sha256:...`). Digests are tamper-proof; tags are not.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `16.4` | Establish and Manage an Inventory of Third-Party Software Components |
| `cis-v8` | `2.3` | Address Unauthorized Software |
| `iso27001` | `A.8.30` | Outsourced development |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `image`, `k8s`, `pod-security`, `supply-chain`

---

### `k8s-pod-liveness-probe`

**Containers should declare a liveness probe** &middot; severity `low` &middot; service `pod-security` &middot; resource `k8s.pod`

Without a livenessProbe, a container stuck in a deadlock or wedged on a downstream timeout will sit in 'Ready' forever — the kubelet has no signal to restart it. A simple HTTP /healthz probe is enough to catch most production wedges and is essentially free.

_Remediation:_

> Add `livenessProbe` (HTTP GET against a /healthz endpoint is the common pattern) to every long-running container. Init and short-lived job containers are exempt.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `k8s`, `pod-security`, `reliability`

---

### `k8s-pod-privileged`

**Pods should not run privileged containers** &middot; severity `critical` &middot; service `pod-security` &middot; resource `k8s.pod`

A container with `securityContext.privileged: true` runs with all Linux capabilities, full device access, and SELinux/AppArmor disabled by default. A break-out from a privileged pod gives the attacker root on the underlying node and across every pod scheduled on it.

_Remediation:_

> Set `securityContext.privileged: false` on every container. If a workload needs hardware access (GPU, raw disk), grant only the specific Linux capability it requires via `securityContext.capabilities.add: [...]`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.9` | Configuration management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |
| `soc2` | `CC6.8` | Prevention or Detection of Unauthorized or Malicious Software |

_Tags:_ `k8s`, `pod-security`, `privileged`

---

### `k8s-pod-readonly-root-fs`

**Containers should use a read-only root filesystem** &middot; severity `medium` &middot; service `pod-security` &middot; resource `k8s.pod`

A writable root filesystem lets a compromised process drop persistent malware, rewrite system binaries, or fill the disk. Setting `readOnlyRootFilesystem: true` forces apps to declare writable mounts explicitly via emptyDir or PVCs, which is also a clarity win at review time.

_Remediation:_

> Set `securityContext.readOnlyRootFilesystem: true`. Mount `emptyDir` volumes for paths the app actually writes to (typically /tmp, /var/run, sometimes /var/log).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.13` | Information backup |
| `iso27001` | `A.8.32` | Change management |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |
| `soc2` | `CC6.8` | Prevention or Detection of Unauthorized or Malicious Software |

_Tags:_ `immutable`, `k8s`, `pod-security`

---

### `k8s-pod-resource-limits`

**Containers should declare CPU and memory limits** &middot; severity `medium` &middot; service `pod-security` &middot; resource `k8s.pod`

A container without `resources.limits` can consume all CPU and all memory on the node, starving every other workload and frequently triggering OOM kills against neighbors. Limits are the K8s noisy-neighbor primitive; running without them is a denial-of-service hazard.

_Remediation:_

> Set `resources.limits.cpu` and `resources.limits.memory` on every container. Use a LimitRange on the namespace to give defaults to workloads that don't declare their own.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.32` | Change management |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `k8s`, `pod-security`, `resources`

---

### `k8s-pod-resource-requests`

**Containers should declare CPU and memory requests** &middot; severity `low` &middot; service `pod-security` &middot; resource `k8s.pod`

`resources.requests` informs the scheduler how much capacity to reserve for the pod. Without requests, the scheduler treats the pod as having zero footprint, which leads to over-subscribed nodes, evictions, and unpredictable performance.

_Remediation:_

> Set `resources.requests.cpu` and `resources.requests.memory` on every container based on observed steady-state usage. The Vertical Pod Autoscaler (recommender mode) is a good starting point.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `k8s`, `pod-security`, `resources`

---

### `k8s-pod-run-as-non-root`

**Containers should run as a non-root user** &middot; severity `high` &middot; service `pod-security` &middot; resource `k8s.pod`

Containers default to running as the image's USER, which for many community images is root. A root process compromised inside the container has more useful capabilities to chain into a node compromise. Setting `runAsNonRoot: true` makes the kubelet refuse to start the pod if the image's UID is 0.

_Remediation:_

> Set `securityContext.runAsNonRoot: true` at the pod or container level, and set `runAsUser` to a non-zero UID. Rebuild images with a non-root USER if needed.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `k8s`, `pod-security`, `root`

---

### `k8s-pod-seccomp-profile`

**Containers should set a non-default seccomp profile** &middot; severity `medium` &middot; service `pod-security` &middot; resource `k8s.pod`

Without `seccompProfile`, containers run with the container runtime's default seccomp policy, which on most distributions still permits a large attack surface (chmod, mount, unshare, keyctl, etc.). Setting type=RuntimeDefault applies a curated allowlist; type=Localhost lets you point at your own profile.

_Remediation:_

> Set `securityContext.seccompProfile.type: RuntimeDefault` at the pod level. Override per-container only when a specific workload needs more syscalls.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.32` | Change management |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `k8s`, `pod-security`, `seccomp`

---

### `k8s-pod-secret-via-env`

**Pods should mount Secrets as volumes rather than env vars** &middot; severity `medium` &middot; service `secrets` &middot; resource `k8s.pod`

Container `env.valueFrom.secretKeyRef` exposes the secret via the process's environment, which means any process in the container (including library calls, `/proc/<pid>/environ`, core dumps) can read it. Volume mounts are the safer pattern: only code that explicitly opens the file path sees the contents, and rotation via secret update propagates without restarting the pod.

_Remediation:_

> Replace `valueFrom.secretKeyRef` with a `volumeMount` that points at a Secret volume. Read the value from the file at runtime.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `cis-v8` | `6.7` | Centralize Access Control |
| `iso27001` | `A.8.10` | Information deletion |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `env`, `k8s`, `secrets`

---

### `k8s-policy-engine-present`

**Cluster should have a policy engine installed** &middot; severity `medium` &middot; service `cluster` &middot; resource `k8s.cluster`

Pod Security Admission covers the pod surface. For everything else (image-from-registry-allowlist, label requirements, RBAC restrictions, custom resource validation), a dedicated policy engine — Kyverno, OPA Gatekeeper, or jspolicy — is the modern primitive. Detection looks for the engine's ValidatingWebhookConfigurations.

_Remediation:_

> Install Kyverno (`helm install kyverno kyverno/kyverno`) or OPA Gatekeeper. Apply org policies as Kyverno ClusterPolicies or Gatekeeper ConstraintTemplates.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.32` | Change management |
| `iso27001` | `A.8.9` | Configuration management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `cluster`, `k8s`, `policy`

---

### `k8s-pv-encryption-hint`

**PersistentVolumes should carry an encryption hint** &middot; severity `medium` &middot; service `storage` &middot; resource `k8s.persistentvolume`

Compliancekit cannot guarantee a PV is encrypted (CSI drivers report differently) but can detect the canonical hints — `encrypted=true` in CSI volumeAttributes, KMS key references, or the `compliancekit.io/encrypted=true` label. A PV with none of these is most likely unencrypted.

_Remediation:_

> Apply the `compliancekit.io/encrypted: "true"` label to PVs you have verified out-of-band, or migrate the workload onto a StorageClass with encryption parameters configured.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.3` | Protect Recovery Data |
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `iso27001` | `A.8.10` | Information deletion |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `encryption`, `k8s`, `storage`

---

### `k8s-pv-orphan`

**Released PersistentVolumes should be cleaned up** &middot; severity `low` &middot; service `storage` &middot; resource `k8s.persistentvolume`

A PV in `Released` phase has lost its claim but still exists. Without manual intervention the underlying disk keeps billing. For Retain volumes this is by design; for Delete volumes it usually indicates a stuck reclaim — the volume plugin failed to clean up.

_Remediation:_

> Either rebind the PV to a new PVC or delete it. `kubectl delete pv <name>` removes the K8s object; the underlying disk is destroyed only if reclaimPolicy=Delete.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `cost`, `hygiene`, `k8s`, `storage`

---

### `k8s-pv-reclaim-retain`

**PersistentVolumes for stateful claims should set reclaimPolicy: Retain** &middot; severity `low` &middot; service `storage` &middot; resource `k8s.persistentvolume`

Same data-loss risk as the StorageClass check but flagged at the PV level so manually-provisioned volumes (no StorageClass) are still covered.

_Remediation:_

> `kubectl patch pv <name> -p '{"spec": {"persistentVolumeReclaimPolicy": "Retain"}}'`. For dynamically-provisioned volumes, fix the StorageClass instead so new PVs inherit Retain.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.8.13` | Information backup |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |

_Tags:_ `k8s`, `reclaim`, `storage`

---

### `k8s-pvc-not-bound`

**PersistentVolumeClaims should be Bound** &middot; severity `low` &middot; service `storage` &middot; resource `k8s.persistentvolumeclaim`

A PVC stuck in `Pending` phase indicates the cluster could not provision matching storage — either no StorageClass with the right capacity / access mode, or the CSI driver failed. Pods that mount the PVC stay Pending forever.

_Remediation:_

> `kubectl describe pvc <name>` shows the controller message. Common fixes: switch StorageClass, request a smaller size, ensure the CSI driver pod is healthy.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `A1.1` | Capacity Management |

_Tags:_ `k8s`, `reliability`, `storage`

---

### `k8s-pvc-orphan`

**Bound PersistentVolumeClaims should be mounted by at least one pod** &middot; severity `low` &middot; service `storage` &middot; resource `k8s.persistentvolumeclaim`

A PVC bound to a real PV but mounted by zero pods is paying for storage nobody uses. Common after a Deployment is deleted but PVCs were not — the storage class's reclaim policy keeps the disk around. Audit and delete.

_Remediation:_

> For PVCs you've confirmed are truly unused: `kubectl delete pvc <name> -n <ns>`. Make sure the underlying PV's reclaim policy matches your intent before deleting.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC9.1` | Identifies and Mitigates Business Disruptions |

_Tags:_ `cost`, `k8s`, `storage`

---

### `k8s-pvc-readwritemany`

**PVCs using ReadWriteMany should be documented** &middot; severity `low` &middot; service `storage` &middot; resource `k8s.persistentvolumeclaim`

ReadWriteMany access mode lets multiple pods write to the same volume concurrently. Few CSI drivers support it well (NFS, EFS, Azure Files, CephFS). Pods that use it must coordinate concurrent writes — a common source of subtle data-corruption bugs. Informational; flag for review.

_Remediation:_

> Confirm the workload's concurrency model handles RWX correctly. Where possible, prefer one-writer-many-readers (RWO + an internal sync) over RWX.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `informational`, `k8s`, `rwx`, `storage`

---

### `k8s-rbac-anonymous-bind`

**Bindings should not grant any role to system:anonymous** &middot; severity `critical` &middot; service `rbac` &middot; resource `k8s.clusterrolebinding`

A binding that includes the user `system:anonymous` or the group `system:unauthenticated` grants permissions to any caller with network access to the API server, regardless of authentication. This is a very common misconfiguration that turns into a critical incident the moment the API server is reachable from outside the cluster.

_Remediation:_

> `kubectl get clusterrolebindings,rolebindings -A -o yaml | grep -B5 -E 'system:(anonymous|unauthenticated)'`. Remove or replace every match.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.7` | Centralize Access Control |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.3` | Information access restriction |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.2` | User Identification and Registration |
| `soc2` | `CC6.8` | Prevention or Detection of Unauthorized or Malicious Software |

_Tags:_ `anonymous`, `critical`, `k8s`, `rbac`

---

### `k8s-rbac-bind`

**Roles should not grant the bind verb on roles** &middot; severity `high` &middot; service `rbac` &middot; resource `k8s.clusterrole`

`bind` on roles/clusterroles lets the subject create RoleBindings that reference roles broader than what the subject itself holds. Like escalate, it bypasses RBAC's privilege escalation prevention.

_Remediation:_

> Limit bind to admin roles. For namespace-scoped admin delegation, prefer dedicated admin ClusterRoles bound to specific groups.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `bind`, `k8s`, `rbac`

---

### `k8s-rbac-cluster-admin-non-system`

**ClusterRoleBindings to cluster-admin should target only system subjects** &middot; severity `critical` &middot; service `rbac` &middot; resource `k8s.clusterrolebinding`

A binding to the built-in `cluster-admin` ClusterRole grants total cluster control. The default bindings shipped with the kube-apiserver bind it to `system:masters` (the in-cluster trust chain) and to specific control-plane components — anything beyond that is a posture failure unless a written justification exists.

_Remediation:_

> Audit `kubectl get clusterrolebindings -o yaml | grep -B5 cluster-admin`. For human admins, prefer a named admin Group; bind that group to cluster-admin with explicit subjects. Revoke ad-hoc cluster-admin bindings to individual user accounts.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.3` | Information access restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |
| `soc2` | `CC6.8` | Prevention or Detection of Unauthorized or Malicious Software |

_Tags:_ `cluster-admin`, `critical`, `k8s`, `rbac`

---

### `k8s-rbac-create-pods`

**Roles should rarely grant create on pods** &middot; severity `medium` &middot; service `rbac` &middot; resource `k8s.clusterrole`

Direct create on pods (as opposed to controllers like Deployments) lets the subject schedule a pod with any ServiceAccount they can name — including a powerful one in the same namespace. It is a well-known privilege escalation primitive in multi-tenant clusters.

_Remediation:_

> Grant create on Deployments/StatefulSets instead and let the controllers create the pods. If you must allow direct pod creation (e.g. for a debug tool), pair the role with a narrow `pods/serviceAccountName` admission policy.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `k8s`, `pods`, `rbac`

---

### `k8s-rbac-csr-approve`

**Roles should not grant approval on CertificateSigningRequests** &middot; severity `high` &middot; service `rbac` &middot; resource `k8s.clusterrole`

The `update` verb on certificatesigningrequests/approval lets the subject issue cluster-trusted certificates for any identity. Combined with a kubelet bootstrap workflow, this can lead directly to a node compromise.

_Remediation:_

> Approval should be reserved for the controller-manager and a small operator group. Audit and remove any other binding to system:certificates.k8s.io:certificatesigningrequests/approval.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `certificates`, `k8s`, `rbac`

---

### `k8s-rbac-empty-subjects`

**Bindings should have at least one subject** &middot; severity `low` &middot; service `rbac` &middot; resource `k8s.rolebinding`

A binding with zero subjects is dead code — it cannot grant access to anyone. Most often it is a leftover from a removed account or group. Either delete it or document why it exists as a placeholder.

_Remediation:_

> `kubectl delete <kind> <name>` for any binding with no subjects. If kept intentionally as a placeholder, add a comment annotation explaining why.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.1` | Establish an Access Granting Process |
| `iso27001` | `A.5.15` | Access control |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `hygiene`, `k8s`, `rbac`

---

### `k8s-rbac-escalate`

**Roles should not grant the escalate verb on roles** &middot; severity `critical` &middot; service `rbac` &middot; resource `k8s.clusterrole`

`escalate` on roles/clusterroles lets the subject add rules to a role that exceed what the subject itself holds. It defeats the privilege-escalation prevention K8s applies to RBAC mutations.

_Remediation:_

> Remove the escalate verb entirely. The cluster-admin ClusterRole already has full RBAC privileges; no other role should need escalate.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |
| `soc2` | `CC6.8` | Prevention or Detection of Unauthorized or Malicious Software |

_Tags:_ `escalate`, `k8s`, `rbac`

---

### `k8s-rbac-full-wildcard`

**Roles should not grant * verbs * resources * api groups simultaneously** &middot; severity `critical` &middot; service `rbac` &middot; resource `k8s.clusterrole`

A single rule with `*` in verbs, resources, AND apiGroups is functionally identical to cluster-admin. It grants every action on every resource type in every group, present and future. This is the canonical privilege escalation surface and should exist only on `cluster-admin` itself.

_Remediation:_

> Replace the wildcard rule with explicit grants. If a workload genuinely needs cluster-admin, use the existing `cluster-admin` ClusterRole and bind it explicitly so audit trails make the intent visible.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.1` | Establish an Access Granting Process |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.3` | Information access restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |
| `soc2` | `CC6.8` | Prevention or Detection of Unauthorized or Malicious Software |

_Tags:_ `cluster-admin`, `critical`, `k8s`, `rbac`

---

### `k8s-rbac-impersonate`

**Roles should not grant the impersonate verb** &middot; severity `critical` &middot; service `rbac` &middot; resource `k8s.clusterrole`

`impersonate` lets the subject act as any user, group, or ServiceAccount. It exists for trusted gateway proxies like kubectl-as flows — any other role with this verb is a privilege escalation primitive.

_Remediation:_

> Strip the impersonate verb. If a controller genuinely needs it (auth proxy, dashboard), document the rationale and limit `resourceNames` to specific subjects.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |
| `soc2` | `CC6.8` | Prevention or Detection of Unauthorized or Malicious Software |

_Tags:_ `critical`, `impersonate`, `k8s`, `rbac`

---

### `k8s-rbac-pods-exec`

**Roles should not grant pods/exec** &middot; severity `high` &middot; service `rbac` &middot; resource `k8s.clusterrole`

`pods/exec` lets the subject open a shell inside any matching pod, bypassing every container-level security control. With this verb, the audit trail goes from `kubectl apply` events to interactive shell traffic the kube-apiserver does not record.

_Remediation:_

> Reserve pods/exec for break-glass roles bound only to a small set of named humans. CI/CD pipelines and applications should not have it.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.8.16` | Monitoring activities |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `exec`, `k8s`, `rbac`

---

### `k8s-rbac-pods-portforward`

**Roles should not grant pods/portforward** &middot; severity `high` &middot; service `rbac` &middot; resource `k8s.clusterrole`

`pods/portforward` opens a tunnel from kubectl to any port in a target pod, bypassing Services and NetworkPolicies. It is a debugging primitive and should not be a normal workload permission.

_Remediation:_

> Restrict pods/portforward to operator/SRE roles bound to named humans, not pipelines or applications.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.8.16` | Monitoring activities |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `k8s`, `portforward`, `rbac`

---

### `k8s-rbac-secrets-readable`

**Roles should not grant read access to secrets broadly** &middot; severity `high` &middot; service `rbac` &middot; resource `k8s.clusterrole`

`get/list/watch` on secrets exposes every credential in the namespace (or cluster, for ClusterRoles). Operators frequently grant this for the wrong reason — what they want is access to a single ConfigMap or one specific secret. Use `resourceNames` to narrow.

_Remediation:_

> If the role only needs to read one secret, set `resourceNames: [the-secret-name]`. Otherwise consider whether the secret could be a projected token, environment variable, or external secrets reference.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.7` | Centralize Access Control |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.10` | Information deletion |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `k8s`, `least-privilege`, `rbac`, `secrets`

---

### `k8s-rbac-secrets-writable`

**Roles should not grant write access to secrets** &middot; severity `critical` &middot; service `rbac` &middot; resource `k8s.clusterrole`

`create/update/patch/delete` on secrets lets the subject overwrite credentials used by other workloads — a direct privilege escalation. Almost no application has a legitimate need; if one does, it should be a ClusterOperator with a much narrower scope.

_Remediation:_

> Strip write verbs on secrets. For controllers that manage their own secrets, use `resourceNames` to lock the grant to a single named secret.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.7` | Centralize Access Control |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.10` | Information deletion |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |
| `soc2` | `CC6.8` | Prevention or Detection of Unauthorized or Malicious Software |

_Tags:_ `k8s`, `rbac`, `secrets`

---

### `k8s-rbac-stale-role-ref`

**Bindings should reference an existing role** &middot; severity `low` &middot; service `rbac` &middot; resource `k8s.rolebinding`

A binding with a roleRef that does not resolve grants no access — the API server silently drops it. The danger is that a future role recreation may reactivate an unintended grant. Delete or fix every stale binding.

_Remediation:_

> Either delete the binding or create the referenced role. `kubectl get rolebinding -A -o json | jq ...` filtering on roleRef.name is the quick audit.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.1` | Establish an Access Granting Process |
| `iso27001` | `A.5.15` | Access control |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `hygiene`, `k8s`, `rbac`

---

### `k8s-rbac-tokenrequest`

**Roles should not grant create on serviceaccounts/token broadly** &middot; severity `high` &middot; service `rbac` &middot; resource `k8s.clusterrole`

`create` on serviceaccounts/token lets the subject mint bound tokens for any ServiceAccount they can name, which is most of the way to becoming that SA. The kube-controller-manager needs this verb; almost nothing else does.

_Remediation:_

> Restrict via `resourceNames: [<specific-sa>]` or remove the verb entirely. Tools that need to issue tokens should use `audience`-bound TokenRequest projection on a workload SA rather than the create verb.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.7` | Centralize Access Control |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `k8s`, `rbac`, `tokens`

---

### `k8s-rbac-user-subject`

**Bindings should target ServiceAccounts or Groups, not Users** &middot; severity `low` &middot; service `rbac` &middot; resource `k8s.rolebinding`

Binding directly to a User makes lifecycle messy — if the user leaves the org, the binding lingers and the audit chain breaks. Groups are revocable centrally; ServiceAccounts are namespace-scoped and rotatable. User subjects exist for emergencies and one-offs.

_Remediation:_

> Bind to a Group instead and manage membership in the IdP. For automated callers, switch to a ServiceAccount.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.1` | Establish an Access Granting Process |
| `cis-v8` | `6.2` | Establish an Access Revoking Process |
| `iso27001` | `A.5.16` | Identity management |
| `iso27001` | `A.5.18` | Access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `hygiene`, `k8s`, `lifecycle`, `rbac`

---

### `k8s-rbac-wildcard-apigroups`

**Roles should not grant wildcard API groups** &middot; severity `medium` &middot; service `rbac` &middot; resource `k8s.clusterrole`

`apiGroups: ['*']` grants the rule's verbs across every API group at once, including custom resources. Combined with wildcard verbs or resources, this is effectively cluster-admin.

_Remediation:_

> Enumerate API groups: `['', 'apps', 'batch', 'networking.k8s.io']` etc.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.1` | Establish an Access Granting Process |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `k8s`, `rbac`, `wildcard`

---

### `k8s-rbac-wildcard-resources`

**Roles should not grant wildcard resources** &middot; severity `high` &middot; service `rbac` &middot; resource `k8s.clusterrole`

`resources: ['*']` grants the rule's verbs against every resource type, present or future. Adding a new CRD to the cluster silently extends the role's scope.

_Remediation:_

> List exact resource names: `[pods, configmaps, services]`. For CRDs, name them explicitly.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.1` | Establish an Access Granting Process |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `k8s`, `rbac`, `wildcard`

---

### `k8s-rbac-wildcard-verbs`

**Roles should not grant wildcard verbs** &middot; severity `high` &middot; service `rbac` &middot; resource `k8s.clusterrole`

A rule with `verbs: ['*']` grants every action — get, create, update, delete, patch, and watch — on the named resources. Even when scoped to one resource type, this is rarely the intent; usually one or two verbs are sufficient. Wildcards make least-privilege analysis impossible.

_Remediation:_

> Enumerate the verbs the role actually needs (get/list/watch for read-only; add create/update/delete only as required). Use `kubectl auth can-i --list --as=<sa>` to validate the minimum.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.1` | Establish an Access Granting Process |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `iso27001` | `A.8.3` | Information access restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `k8s`, `least-privilege`, `rbac`, `wildcard`

---

### `k8s-resourcequota-compute-limit`

**ResourceQuotas should cap CPU and memory** &middot; severity `low` &middot; service `cluster` &middot; resource `k8s.resourcequota`

Without compute caps, a single tenant can consume all of a cluster's CPU or memory headroom. `limits.cpu` + `limits.memory` plus the matching `requests.*` keep namespace consumption bounded.

_Remediation:_

> Add `hard.limits.cpu` and `hard.limits.memory` (and `hard.requests.cpu` / `hard.requests.memory`).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `k8s`, `quota`

---

### `k8s-resourcequota-object-counts`

**ResourceQuotas should cap object counts** &middot; severity `low` &middot; service `cluster` &middot; resource `k8s.resourcequota`

etcd has practical ceilings on object count. Without `count/configmaps`, `count/secrets`, `persistentvolumeclaims` caps, a chatty controller can fill etcd within a namespace.

_Remediation:_

> Add `hard.count/configmaps`, `hard.count/secrets`, and `hard.persistentvolumeclaims` to every ResourceQuota.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.1` | Capacity Management |

_Tags:_ `k8s`, `quota`

---

### `k8s-resourcequota-pod-limit`

**ResourceQuotas should cap pod counts** &middot; severity `low` &middot; service `cluster` &middot; resource `k8s.resourcequota`

A pod cap (`hard.pods: <n>`) prevents a runaway controller from spawning thousands of pods and exhausting node capacity. Pair with `count/secrets` and `count/configmaps` to bound etcd object count.

_Remediation:_

> Add `spec.hard.pods: 50` (or your operational ceiling) to every ResourceQuota.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.7` | Manage Default Accounts on Enterprise Assets and Software |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `A1.1` | Capacity Management |

_Tags:_ `k8s`, `quota`

---

### `k8s-sa-default-automount`

**Default ServiceAccounts should disable token automount** &middot; severity `medium` &middot; service `rbac` &middot; resource `k8s.serviceaccount`

Every namespace ships with a `default` ServiceAccount that by default has automountServiceAccountToken=true. Pods that do not opt out get the default SA's token mounted at /var/run/secrets/... — a credential they almost certainly do not need. Disabling automount on the default SA forces workloads to be explicit about API access.

_Remediation:_

> `kubectl patch sa default -n <ns> -p '{"automountServiceAccountToken": false}'` in every namespace. Workloads that legitimately need API access should declare a dedicated SA with automount=true.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.7` | Centralize Access Control |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `default-sa`, `k8s`, `rbac`, `service-account`

---

### `k8s-sa-default-used`

**Pods should not run as the default ServiceAccount** &middot; severity `medium` &middot; service `rbac` &middot; resource `k8s.pod`

Running as the namespace's default SA means inheriting whatever bindings exist on that SA — which is often more than the workload requires. Dedicated per-workload SAs make least-privilege analysis tractable and let you rotate one workload's credentials without affecting others.

_Remediation:_

> Create a per-workload ServiceAccount and reference it via `spec.serviceAccountName` in the pod template. Bind only the specific Roles the workload needs.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.7` | Centralize Access Control |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `k8s`, `rbac`, `service-account`

---

### `k8s-sa-imagepull-secrets-set`

**ServiceAccounts pulling from private registries should declare imagePullSecrets** &middot; severity `low` &middot; service `rbac` &middot; resource `k8s.serviceaccount`

When a pod's image lives in a private registry, the pull is authenticated either via the pod's imagePullSecrets or — more commonly — via secrets attached to the pod's ServiceAccount. A SA used by pods pulling from registries other than docker.io or public quay/ghcr.io should have imagePullSecrets attached.

_Remediation:_

> `kubectl patch sa <name> -n <ns> -p '{"imagePullSecrets": [{"name": "<docker-secret>"}]}'`. Maintain the dockerconfigjson Secret outside the cluster (or via external-secrets) so the value can rotate cleanly.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.8.30` | Outsourced development |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC8.1` | Change Management Process |

_Tags:_ `k8s`, `rbac`, `service-account`, `supply-chain`

---

### `k8s-sa-orphan`

**Custom ServiceAccounts should be used by at least one pod** &middot; severity `low` &middot; service `rbac` &middot; resource `k8s.serviceaccount`

An unused custom ServiceAccount is dead code — it often retains bindings from a previous workload generation. Leftover SAs with leftover Role/ClusterRoleBindings are a frequent privilege-escalation surface. Either delete the SA or repoint a workload at it.

_Remediation:_

> Audit with `kubectl get sa -A` cross-referenced against `kubectl get pods -A -o jsonpath='{.items[*].spec.serviceAccountName}'`. Delete orphans after confirming no workload reactivation is planned.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.1` | Establish an Access Granting Process |
| `cis-v8` | `6.2` | Establish an Access Revoking Process |
| `iso27001` | `A.5.15` | Access control |
| `iso27001` | `A.5.16` | Identity management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `hygiene`, `k8s`, `rbac`, `service-account`

---

### `k8s-secret-immutable`

**Long-lived Secrets should be marked immutable** &middot; severity `low` &middot; service `secrets` &middot; resource `k8s.secret`

Setting `immutable: true` on a Secret prevents accidental updates that would silently propagate to running pods, and lets the kubelet skip the periodic watch refresh on that Secret — a meaningful API-server load reduction at scale.

_Remediation:_

> For Secrets that should never change after creation (rotation via replacement), add `immutable: true`. For Secrets you do rotate in-place, leave mutable.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.2` | Establish an Access Revoking Process |
| `iso27001` | `A.8.10` | Information deletion |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `immutable`, `k8s`, `secrets`

---

### `k8s-secret-orphan`

**Secrets should be referenced by at least one pod or ServiceAccount** &middot; severity `low` &middot; service `secrets` &middot; resource `k8s.secret`

An unreferenced Secret often holds a stale credential that nobody knows to rotate. Leftover Secrets accumulate as deployments come and go. Periodic cleanup is the standard hygiene practice.

_Remediation:_

> Audit Secrets against actual references and delete those genuinely unused. Use `kubectl delete secret <name> -n <ns>`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `cis-v8` | `6.2` | Establish an Access Revoking Process |
| `iso27001` | `A.5.16` | Identity management |
| `iso27001` | `A.8.10` | Information deletion |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `hygiene`, `k8s`, `secrets`

---

### `k8s-secret-too-large`

**Secrets should be under 1 MiB** &middot; severity `low` &middot; service `secrets` &middot; resource `k8s.secret`

The K8s API hard-limits Secrets to 1 MiB. Very large Secrets often indicate misuse — a kubeconfig, a private CA bundle, an entire TLS chain, or accidentally stored binary data. Operationally large Secrets also stress etcd because every API write replicates the full value.

_Remediation:_

> For large bundles, store the contents in object storage and reference them with a small credentials Secret that lets the pod fetch at startup. For multi-file bundles, split into multiple Secrets.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `6.2` | Establish an Access Revoking Process |
| `iso27001` | `A.8.10` | Information deletion |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `k8s`, `secrets`, `size`

---

### `k8s-service-external-ips`

**Services should not set spec.externalIPs** &middot; severity `medium` &middot; service `network` &middot; resource `k8s.service`

`spec.externalIPs` lets an operator route arbitrary node IPs to a Service. It bypasses both LoadBalancer and Ingress paths and exists primarily for legacy bare-metal deployments. There is a well-known privilege escalation via externalIPs if a tenant can mutate Services (CVE-2020-8554).

_Remediation:_

> Use `type: LoadBalancer` with a real LB, or `type: NodePort`, or an Ingress. If externalIPs is genuinely needed, deploy an admission policy restricting which IPs are allowed.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.5` | Centralize Network Authentication, Authorization, and Auditing (AAA) |
| `cis-v8` | `13.6` | Collect Network Traffic Flow Logs |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `external-ips`, `k8s`, `network`

---

### `k8s-service-loadbalancer-no-tls`

**LoadBalancer Services should not expose plain HTTP only** &middot; severity `medium` &middot; service `network` &middot; resource `k8s.service`

A LoadBalancer service that only exposes port 80 ships every request and response in cleartext. K8s does not handle TLS termination at the Service level — operators typically front the service with an Ingress or terminate TLS in-pod. Expose 443 too (or 443-only) so traffic can be encrypted.

_Remediation:_

> Add a 443/TCP port to the Service definition and terminate TLS at the workload, or front the workload with an Ingress carrying a TLS section.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.5` | Centralize Network Authentication, Authorization, and Auditing (AAA) |
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `k8s`, `loadbalancer`, `network`, `tls`

---

### `k8s-service-loadbalancer-source-ranges`

**LoadBalancer Services should restrict source ranges** &middot; severity `high` &middot; service `network` &middot; resource `k8s.service`

A Service with `type: LoadBalancer` and no `loadBalancerSourceRanges` is reachable from the entire public internet. For an admin endpoint (Argo CD, Prometheus, Grafana, internal SaaS dashboards) this is often unintended. Set source ranges to the operator's office / VPN CIDR.

_Remediation:_

> Add `spec.loadBalancerSourceRanges: [<cidr1>, <cidr2>]`. For workloads that genuinely should be public, document the intent via an annotation or waiver.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.5` | Centralize Network Authentication, Authorization, and Auditing (AAA) |
| `cis-v8` | `13.6` | Collect Network Traffic Flow Logs |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `exposure`, `k8s`, `loadbalancer`, `network`

---

### `k8s-service-nodeport`

**Services should generally not use type: NodePort** &middot; severity `low` &middot; service `network` &middot; resource `k8s.service`

`type: NodePort` opens a port on every node — every node, even those not running the workload. Without a network policy to filter traffic, the service is reachable from any node-attached subnet. Most modern clusters should use LoadBalancer or Ingress instead and let NodePort exist only as the kube-proxy implementation detail under those.

_Remediation:_

> Switch to LoadBalancer (real cloud LB) or Ingress (routed via an in-cluster controller). Keep NodePort only for tightly scoped infra (kube-apiserver via metallb, etc.).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.5` | Centralize Network Authentication, Authorization, and Auditing (AAA) |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `k8s`, `network`, `nodeport`

---

### `k8s-service-public-without-network-policy`

**Public Services should run in a namespace with at least one NetworkPolicy** &middot; severity `medium` &middot; service `network` &middot; resource `k8s.service`

A namespace with a public-facing Service (LoadBalancer/NodePort) and no NetworkPolicy has no egress or ingress filtering — a compromise of the public-facing pod can talk to anything cluster-internal. Defense in depth requires at least one policy in the namespace, ideally a default-deny baseline.

_Remediation:_

> Apply a default-deny NetworkPolicy to the namespace (`podSelector: {}`, policyTypes: [Ingress, Egress]), then allow the specific flows the workload needs.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.4` | Establish and Maintain Architecture Diagram(s) |
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.22` | Segregation of networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `defense-in-depth`, `k8s`, `network`, `policy`

---

### `k8s-statefulset-pdb-missing`

**Multi-replica StatefulSets should have a PodDisruptionBudget** &middot; severity `medium` &middot; service `controllers` &middot; resource `k8s.statefulset`

StatefulSets carry persistent state, so simultaneous eviction is even more disruptive than for Deployments. A PDB with `minAvailable: <replicas-1>` keeps quorum across node drains and rolling cluster upgrades.

_Remediation:_

> Create a PDB selecting the StatefulSet's pods. For quorum-based services (etcd, ZooKeeper, Postgres replicas) set `minAvailable` to N-1 where N is replicas.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `cis-v8` | `12.5` | Centralize Network Authentication, Authorization, and Auditing (AAA) |
| `iso27001` | `A.5.30` | ICT readiness for business continuity |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.1` | Capacity Management |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |

_Tags:_ `controllers`, `ha`, `k8s`, `stateful`

---

### `k8s-storageclass-default-multiple`

**Only one StorageClass should be marked default** &middot; severity `medium` &middot; service `storage` &middot; resource `k8s.storageclass`

When multiple StorageClasses carry the `storageclass.kubernetes.io/is-default-class: true` annotation, the cluster's behavior on a PVC without `storageClassName` is undefined — it picks whichever the admission plugin sees first, which can change at upgrade time. Exactly one default is correct; zero defaults forces every PVC to declare its class.

_Remediation:_

> Set the annotation to `false` on every StorageClass except the intended default.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.6` | Capacity management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `hygiene`, `k8s`, `storage`

---

### `k8s-storageclass-encryption`

**StorageClasses should configure at-rest encryption** &middot; severity `medium` &middot; service `storage` &middot; resource `k8s.storageclass`

Disk encryption at rest is the baseline for any data-bearing workload. The CSI parameters that enable it vary by driver — AWS EBS uses `encrypted: true` (and optionally `kmsKeyId`), GCP PD uses `disk-encryption-kms-key`, Azure Disk uses `diskEncryptionSetID`. A StorageClass that omits all of these provisions unencrypted volumes.

_Remediation:_

> Add the driver-specific encryption parameter. For AWS EBS: `parameters.encrypted: "true"`. For GCP PD: `parameters.disk-encryption-kms-key: projects/.../keys/...`. For Azure: `parameters.diskEncryptionSetID: ...`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.3` | Protect Recovery Data |
| `cis-v8` | `3.11` | Encrypt Sensitive Data at Rest |
| `iso27001` | `A.8.10` | Information deletion |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `encryption`, `k8s`, `storage`

---

### `k8s-storageclass-reclaim-policy`

**StorageClasses for data-bearing workloads should set reclaimPolicy: Retain** &middot; severity `low` &middot; service `storage` &middot; resource `k8s.storageclass`

The default StorageClass reclaim policy is `Delete`, which destroys the underlying volume when its PVC is deleted. That is correct for ephemeral workloads (CI scratch, cache) but a data-loss hazard for databases and stateful apps. `Retain` keeps the volume around so an operator can rebind or backup before deletion.

_Remediation:_

> Define a separate StorageClass for stateful workloads with `reclaimPolicy: Retain`. Leave Delete for ephemeral classes.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.8.13` | Information backup |
| `iso27001` | `A.8.14` | Redundancy of information processing facilities |
| `soc2` | `A1.2` | Backup and Recovery Infrastructure |

_Tags:_ `k8s`, `reclaim`, `storage`

---

### `k8s-validating-webhook-failure-policy`

**Validating webhooks should set failurePolicy=Fail** &middot; severity `medium` &middot; service `admission` &middot; resource `k8s.validatingwebhookconfig`

`failurePolicy: Ignore` means a webhook outage silently bypasses policy. That is appropriate only for advisory checks; any security-critical webhook should fail closed (`Fail`) so an outage halts admission rather than letting unchecked resources through.

_Remediation:_

> Set `failurePolicy: Fail` on security-relevant webhooks. Pair with a `namespaceSelector` that exempts kube-system so a webhook outage cannot brick the control plane.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `cis-v8` | `8.11` | Conduct Audit Log Reviews |
| `iso27001` | `A.8.16` | Monitoring activities |
| `iso27001` | `A.8.32` | Change management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `admission`, `k8s`, `webhook`

---

### `k8s-webhook-namespace-selector`

**Cluster-wide webhooks should exempt kube-system via namespaceSelector** &middot; severity `medium` &middot; service `admission` &middot; resource `k8s.mutatingwebhookconfig`

A webhook with no `namespaceSelector` matches every namespace including kube-system. If the webhook backing pod goes down, the control plane components in kube-system cannot create their own helper resources, and the cluster can lock itself out of recovery. Exempt kube-system explicitly.

_Remediation:_

> Add `namespaceSelector: {matchExpressions: [{key: kubernetes.io/metadata.name, operator: NotIn, values: [kube-system, kube-public]}]}`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.16` | Monitoring activities |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `admission`, `control-plane`, `k8s`, `webhook`

---

## linux

### `linux-aslr-enabled`

**Address Space Layout Randomization must be fully enabled** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

ASLR randomizes the address space of running processes, raising the cost of memory-corruption exploits. kernel.randomize_va_space=2 is the full-strength setting (stack + heap + brk + vdso + mmap). 0 disables; 1 is a weakened subset. CIS Ubuntu 3.2.1.

_Remediation:_

> sysctl -w kernel.randomize_va_space=2 (runtime) and add the line to /etc/sysctl.conf or a drop-in under /etc/sysctl.d/ for persistence.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `4.1` | Establish and Maintain a Secure Configuration Process |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `exploit-mitigation`, `kernel`

---

### `linux-audit-rule-group`

**auditd must watch /etc/group** &middot; severity `medium` &middot; service `audit` &middot; resource `linux.host`

auditd watch rule for [/etc/group]; CIS Linux Server v8 §4.1.3.7. Watch group-membership changes — a privilege-escalation primitive (add user to wheel/sudo).

_Remediation:_

> Append to /etc/audit/rules.d/50-cis.rules:
  -w /etc/group -p wa -k cis_v8
Then `sudo augenrules --load` (RHEL family) or `sudo systemctl restart auditd` (Debian/Ubuntu).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `4.1.3.7` | Ensure MAC policy changes are collected |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit`, `identity`

---

### `linux-audit-rule-gshadow`

**auditd must watch /etc/gshadow** &middot; severity `medium` &middot; service `audit` &middot; resource `linux.host`

auditd watch rule for [/etc/gshadow]; CIS Linux Server v8 §4.1.3.7. Group-password file. Rarely edited; an unexpected write is high-signal.

_Remediation:_

> Append to /etc/audit/rules.d/50-cis.rules:
  -w /etc/gshadow -p wa -k cis_v8
Then `sudo augenrules --load` (RHEL family) or `sudo systemctl restart auditd` (Debian/Ubuntu).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `4.1.3.7` | Ensure MAC policy changes are collected |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit`, `identity`

---

### `linux-audit-rule-lastlog`

**auditd must watch /var/log/lastlog (login records)** &middot; severity `medium` &middot; service `audit` &middot; resource `linux.host`

auditd watch rule for [/var/log/lastlog]; CIS Linux Server v8 §4.1.3.6. lastlog tracks per-user last-login time; tampering is a forensic-evasion signal.

_Remediation:_

> Append to /etc/audit/rules.d/50-cis.rules:
  -w /var/log/lastlog -p wa -k cis_v8
Then `sudo augenrules --load` (RHEL family) or `sudo systemctl restart auditd` (Debian/Ubuntu).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `4.1.3.6` | Ensure events that modify identity (passwd/shadow/group) are collected |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit`, `login`

---

### `linux-audit-rule-localtime`

**auditd must watch /etc/localtime** &middot; severity `low` &middot; service `audit` &middot; resource `linux.host`

auditd watch rule for [/etc/localtime]; CIS Linux Server v8 §4.1.3.5. Timezone changes shift every log timestamp; a recorded change is essential for correlation.

_Remediation:_

> Append to /etc/audit/rules.d/50-cis.rules:
  -w /etc/localtime -p wa -k cis_v8
Then `sudo augenrules --load` (RHEL family) or `sudo systemctl restart auditd` (Debian/Ubuntu).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `4.1.3.5` | Ensure events that modify date and time are collected |
| `iso27001` | `A.8.17` | Clock synchronization |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit`, `time`

---

### `linux-audit-rule-mac-policy`

**auditd must watch /etc/apparmor/ (or /etc/apparmor.d/)** &middot; severity `medium` &middot; service `audit` &middot; resource `linux.host`

auditd watch rule for [/etc/apparmor]; CIS Linux Server v8 §4.1.3.14. AppArmor policy changes — same rationale as the SELinux watch but for the alternative MAC.

_Remediation:_

> Append to /etc/audit/rules.d/50-cis.rules:
  -w /etc/apparmor -p wa -k cis_v8
Then `sudo augenrules --load` (RHEL family) or `sudo systemctl restart auditd` (Debian/Ubuntu).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `4.1.3.14` | Ensure successful and unsuccessful logins are collected (lastlog) |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `apparmor`, `audit`

---

### `linux-audit-rule-passwd`

**auditd must watch /etc/passwd** &middot; severity `high` &middot; service `audit` &middot; resource `linux.host`

auditd watch rule for [/etc/passwd]; CIS Linux Server v8 §4.1.3.7. Watch writes to /etc/passwd; every legitimate user-add / user-mod produces a record.

_Remediation:_

> Append to /etc/audit/rules.d/50-cis.rules:
  -w /etc/passwd -p wa -k cis_v8
Then `sudo augenrules --load` (RHEL family) or `sudo systemctl restart auditd` (Debian/Ubuntu).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `4.1.3.7` | Ensure MAC policy changes are collected |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit`, `identity`

---

### `linux-audit-rule-selinux`

**auditd must watch /etc/selinux/ + /usr/share/selinux/** &middot; severity `medium` &middot; service `audit` &middot; resource `linux.host`

auditd watch rule for [/etc/selinux]; CIS Linux Server v8 §4.1.3.14. MAC policy changes (SELinux config) should be audit-trailed.

_Remediation:_

> Append to /etc/audit/rules.d/50-cis.rules:
  -w /etc/selinux -p wa -k cis_v8
Then `sudo augenrules --load` (RHEL family) or `sudo systemctl restart auditd` (Debian/Ubuntu).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `4.1.3.14` | Ensure successful and unsuccessful logins are collected (lastlog) |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `audit`, `selinux`

---

### `linux-audit-rule-shadow`

**auditd must watch /etc/shadow** &middot; severity `high` &middot; service `audit` &middot; resource `linux.host`

auditd watch rule for [/etc/shadow]; CIS Linux Server v8 §4.1.3.7. Direct edits to /etc/shadow bypass passwd/chpasswd; an audit record catches the attempt.

_Remediation:_

> Append to /etc/audit/rules.d/50-cis.rules:
  -w /etc/shadow -p wa -k cis_v8
Then `sudo augenrules --load` (RHEL family) or `sudo systemctl restart auditd` (Debian/Ubuntu).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `4.1.3.7` | Ensure MAC policy changes are collected |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit`, `identity`

---

### `linux-audit-rule-sudoers`

**auditd must watch /etc/sudoers + /etc/sudoers.d** &middot; severity `high` &middot; service `audit` &middot; resource `linux.host`

auditd watch rule for [/etc/sudoers]; CIS Linux Server v8 §4.1.3.20. Watch sudoers edits — most privileged-access drift starts here. /etc/sudoers.d should also be watched.

_Remediation:_

> Append to /etc/audit/rules.d/50-cis.rules:
  -w /etc/sudoers -p wa -k cis_v8
Then `sudo augenrules --load` (RHEL family) or `sudo systemctl restart auditd` (Debian/Ubuntu).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `4.1.3.20` | Ensure changes to system administration scope (sudoers) are collected |
| `iso27001` | `A.5.15` | Access control |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `audit`, `sudo`

---

### `linux-audit-rule-time-change`

**auditd must watch time-change syscalls** &middot; severity `medium` &middot; service `audit` &middot; resource `linux.host`

auditd watch rule for [adjtimex]; CIS Linux Server v8 §4.1.3.5. adjtimex / settimeofday / clock_settime calls — a backdoor for log-correlation evasion.

_Remediation:_

> Append to /etc/audit/rules.d/50-cis.rules:
  -w adjtimex -p wa -k cis_v8
Then `sudo augenrules --load` (RHEL family) or `sudo systemctl restart auditd` (Debian/Ubuntu).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `4.1.3.5` | Ensure events that modify date and time are collected |
| `iso27001` | `A.8.17` | Clock synchronization |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit`, `time`

---

### `linux-auditd-running`

**auditd must be running** &middot; severity `medium` &middot; service `audit` &middot; resource `linux.host`

auditd captures syscall-level audit events that satisfy 'log access to sensitive systems' controls. Without it, evidence for SOC 2 CC7.2, ISO 27001 A.8.15, and CIS Controls v8 8.5 is hard to produce.

_Remediation:_

> Install and enable auditd: 'sudo apt install auditd && sudo systemctl enable --now auditd' (Debian/Ubuntu) or the equivalent on your distro.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |
| `soc2` | `CC7.3` | Security Incident Evaluation |

_Tags:_ `audit`, `logging`

---

### `linux-distro-supported`

**/etc/os-release ID must be on the supported-distro allowlist** &middot; severity `medium` &middot; service `distro` &middot; resource `linux.host`

v0.20 introduces per-distro behavior in many Linux checks (package manager, init system, sysctl key names). The collector reads /etc/os-release at the top of every gather pass; if the ID isn't on the allowlist (debian, ubuntu, rhel, centos, rocky, almalinux, fedora, alpine, amzn) downstream checks fall through to generic defaults that may misclassify findings. Pin the host to a supported distro OR open a tracking issue to extend the allowlist.

_Remediation:_

> Either migrate the workload to a supported distro (Ubuntu LTS / Debian Stable / RHEL family / Alpine / Amazon Linux 2 or 2023), or open an issue at https://github.com/darpanzope/compliancekit/issues with the target distro + /etc/os-release contents so it can be added to `supportedDistros` in `internal/checks/linux/distro.go`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `7.3` | Perform Automated Operating System Patch Management |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |

_Tags:_ `distro`, `platform`

---

### `linux-firewall-active`

**A host firewall must be active** &middot; severity `high` &middot; service `firewall` &middot; resource `linux.host`

A host with no active firewall accepts every packet its NIC sees. ufw and nftables are the two modern Linux options; this check passes when either reports an active state. SOC 2 CC6.6, ISO 27001 A.8.20, and CIS Controls v8 4.4 all require network access controls on production hosts.

_Remediation:_

> Enable ufw ('sudo ufw enable' on Debian/Ubuntu) or nftables ('sudo systemctl enable --now nftables'). Verify with 'sudo ufw status' or 'sudo nft list ruleset'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `firewall`, `network`

---

### `linux-firewall-default-deny`

**Firewall default-incoming policy must be deny** &middot; severity `high` &middot; service `firewall` &middot; resource `linux.host`

An active firewall whose default policy is allow is only slightly safer than no firewall at all -- every port without an explicit deny rule is reachable. Default-deny with explicit allows is the only defensible posture. SOC 2 CC6.6, ISO 27001 A.8.20, and CIS Controls v8 4.4 require this.

_Remediation:_

> On ufw: 'sudo ufw default deny incoming'. On nftables, set the inet filter input chain policy to drop.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `cis-v8` | `4.4` | Implement and Manage a Firewall on Servers |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `default-policy`, `firewall`, `network`

---

### `linux-firewall-dns-egress-restricted`

**DNS egress must be restricted to known resolvers** &middot; severity `low` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §3.4.2.10. Unrestricted port 53 egress is a common DNS-tunneling exfil channel. Restrict to your resolver IPs.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `sudo iptables -L OUTPUT | grep 53` + cross-reference /etc/resolv.conf. + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.4.2.10` | Ensure DNS egress is restricted to known resolvers |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `dns`, `firewall`, `manual-verify`

---

### `linux-firewall-egress-policy-documented`

**Egress allow-list must be documented** &middot; severity `low` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §3.4.2.6. Default-deny egress requires a documented allow-list (which fqdns + ports + protocols are intentional). Without that list, every new outbound flow that fails is a guess.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via Document the allow-list in your runbook; the firewall rules should match. + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.4.2.6` | Ensure egress policy is documented |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `egress`, `firewall`, `manual-verify`

---

### `linux-firewall-icmp-input-restricted`

**ICMP INPUT must be rate-limited** &middot; severity `low` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §3.4.2.5. Unbounded ICMP echo replies are a ping-flood amplifier. Limit to ≤5/sec.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `sudo iptables -L INPUT | grep -i icmp` OR `sudo nft list ruleset | grep icmp` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.4.2.5` | Ensure ICMP INPUT is rate-limited |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `firewall`, `icmp`, `manual-verify`

---

### `linux-firewall-ipv6-rules-present`

**IPv6 firewall rules must mirror IPv4** &middot; severity `medium` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §3.4.2.7. An IPv4-only firewall on a dual-stack host leaves the IPv6 stack default-permit. Hosts with IPv6 enabled need ip6tables / inet6 rules to mirror IPv4.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `sudo ip6tables -L | head` OR `sudo nft list ruleset | grep ip6` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.4.2.7` | Ensure IPv6 firewall rules mirror IPv4 |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `firewall`, `ipv6`, `manual-verify`

---

### `linux-firewall-loopback-allowed`

**Firewall must allow loopback traffic** &middot; severity `medium` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §3.4.2.4. Localhost / 127.0.0.0/8 / ::1 traffic must be allowed. Most distros include this rule by default; explicit-deny INPUT policies sometimes drop it.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `sudo iptables -L INPUT | grep -i lo` OR `sudo nft list ruleset | grep iif lo` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.4.2.4` | Ensure loopback traffic is allowed |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `firewall`, `loopback`, `manual-verify`

---

### `linux-firewall-nftables-on-rhel`

**RHEL-family hosts should run nftables (modern replacement for iptables)** &middot; severity `low` &middot; service `firewall` &middot; resource `linux.host`

nftables is the upstream replacement for iptables; RHEL 8+ ships with firewalld backed by nftables. Hosts in the RHEL family running iptables-only miss the cleaner rule grammar + atomic rule replacement. Debian/Ubuntu still defaults to ufw — this check skips there.

_Remediation:_

> sudo systemctl enable --now nftables
Migrate iptables rules via `iptables-restore-translate -f /etc/sysconfig/iptables`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.4.2` | Configure firewall rules (Level 1 baseline) |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `firewall`, `nftables`, `rhel`

---

### `linux-firewall-rules-logged`

**Firewall drops should be logged** &middot; severity `low` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §3.4.2.8. Logged drops feed the SIEM with reconnaissance / scan signals. Most distros disable LOG by default to keep dmesg quiet.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `sudo iptables -L | grep LOG` OR `sudo nft list ruleset | grep log` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.4.2.8` | Ensure SSH inbound is rate-limited |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `firewall`, `logging`, `manual-verify`

---

### `linux-firewall-some-active`

**Some firewall must be active (ufw, nftables, or firewalld)** &middot; severity `high` &middot; service `firewall` &middot; resource `linux.host`

A host with NO active firewall trusts the upstream cloud provider's security groups entirely. Defense in depth wants both — at minimum a nftables default-deny INPUT table on RHEL-family or ufw active on Debian-family.

_Remediation:_

> Debian/Ubuntu: sudo ufw enable
RHEL family: sudo systemctl enable --now nftables firewalld

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.4.1` | Ensure a firewall package is installed and active |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `firewall`, `must-active`

---

### `linux-firewall-ssh-rate-limited`

**SSH ingress must be rate-limited** &middot; severity `medium` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §3.4.2.9. Rate-limiting SSH (e.g. ufw limit 22) blocks credential-stuffing without changing the auth posture.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `sudo ufw status verbose | grep -i limit` OR `sudo iptables -L | grep recent` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.4.2.9` | Ensure firewall rules are logged |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `firewall`, `manual-verify`, `ssh`

---

### `linux-firewall-ufw-default-deny-outgoing`

**ufw default policy: outgoing must be deny on egress-controlled hosts** &middot; severity `medium` &middot; service `firewall` &middot; resource `linux.host`

Default-deny egress is the modern way to constrain a compromised process from beacons / data-exfil. CIS Linux Server v8 §3.4.2.1 recommends explicit egress allow-lists with default deny. Waive on hosts that need broad outbound access (build runners, package mirrors).

_Remediation:_

> sudo ufw default deny outgoing
sudo ufw allow out 443/tcp comment 'HTTPS'
sudo ufw allow out 53      comment 'DNS'
sudo ufw reload

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.4.2.1` | Ensure default-deny egress policy |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `egress`, `firewall`, `ufw`

---

### `linux-journald-persistent`

**journald must use persistent storage** &middot; severity `low` &middot; service `audit` &middot; resource `linux.host`

systemd's journald default ('auto') writes to disk only if /var/log/journal exists, and falls back to a volatile ramdisk otherwise. A reboot wipes the latter and breaks the audit trail. Setting Storage=persistent forces disk storage and creates the directory if missing.

_Remediation:_

> Set 'Storage=persistent' in /etc/systemd/journald.conf and 'systemctl restart systemd-journald'. Confirm with 'journalctl --header | head'.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `8.10` | Retain Audit Logs |
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit`, `journald`, `logging`

---

### `linux-login-defs-encrypt-method`

**/etc/login.defs ENCRYPT_METHOD must be SHA512 or YESCRYPT** &middot; severity `high` &middot; service `auth` &middot; resource `linux.host`

ENCRYPT_METHOD controls the hash algorithm used to store new user passwords in /etc/shadow. SHA512 + YESCRYPT are the only acceptable choices in 2026 (DES + MD5 are trivially crackable; SHA256 is acceptable but SHA512 is the explicit CIS pick). CIS Linux Server v8 §5.5.1.4.

_Remediation:_

> /etc/login.defs:
  ENCRYPT_METHOD YESCRYPT   # or SHA512
Rehash existing accounts on next password change.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `auth`, `password-hashing`

---

### `linux-login-defs-pass-max-days`

**/etc/login.defs PASS_MAX_DAYS must be ≤ 365** &middot; severity `medium` &middot; service `auth` &middot; resource `linux.host`

PASS_MAX_DAYS bounds the maximum password lifetime for accounts created from /etc/login.defs defaults. CIS Linux Server v8 §5.5.1.1 requires ≤365 (NIST 800-63B aligned). Existing accounts may need `chage --maxdays` separately.

_Remediation:_

> Edit /etc/login.defs:
  PASS_MAX_DAYS   365
Apply to existing users:
  awk -F: '($3>=1000 && $3<60000) {print $1}' /etc/passwd | xargs -I{} chage --maxdays 365 {}

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `iso27001` | `A.5.17` | Authentication information |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `auth`, `password-age`

---

### `linux-login-defs-pass-min-days`

**/etc/login.defs PASS_MIN_DAYS must be ≥ 1** &middot; severity `medium` &middot; service `auth` &middot; resource `linux.host`

PASS_MIN_DAYS prevents a user from cycling through their password history in a single sitting (defeats reuse-prevention). CIS §5.5.1.2 requires ≥1.

_Remediation:_

> /etc/login.defs:
  PASS_MIN_DAYS   1

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `iso27001` | `A.5.17` | Authentication information |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `auth`, `password-age`

---

### `linux-login-defs-pass-warn-age`

**/etc/login.defs PASS_WARN_AGE must be ≥ 7** &middot; severity `low` &middot; service `auth` &middot; resource `linux.host`

PASS_WARN_AGE controls how many days ahead of expiry the user sees a warning at login. ≥7 days gives the user a meaningful chance to rotate before being locked out. CIS §5.5.1.3.

_Remediation:_

> /etc/login.defs:
  PASS_WARN_AGE   7

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `iso27001` | `A.5.17` | Authentication information |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `auth`, `password-age`

---

### `linux-login-defs-umask`

**/etc/login.defs UMASK must be 027 or stricter** &middot; severity `medium` &middot; service `auth` &middot; resource `linux.host`

Default UMASK 022 (group + world readable) is too permissive for shared / multi-tenant systems. 027 (no group write, no world access) is the CIS Linux Server v8 §5.5.5 recommendation.

_Remediation:_

> /etc/login.defs:
  UMASK   027
Also check /etc/profile.d/*.sh + /etc/bashrc for shell-level overrides.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `auth`, `umask`

---

### `linux-mac-apparmor-active`

**AppArmor must be active on Debian-family hosts** &middot; severity `high` &middot; service `mac` &middot; resource `linux.host`

AppArmor is the Debian/Ubuntu MAC layer. Active = kernel module loaded AND at least one profile loaded. CIS Linux Server v8 §1.7.2.

_Remediation:_

> sudo apt-get install -y apparmor apparmor-utils
sudo systemctl enable --now apparmor
sudo aa-enforce /etc/apparmor.d/*

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.7.2` | Ensure AppArmor is active |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `apparmor`, `mac`

---

### `linux-mac-apparmor-no-complain-mode`

**AppArmor profiles must not be in complain mode (production)** &middot; severity `medium` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §1.7.2.3. complain-mode profiles log violations but don't enforce. Per-profile knob; verify production profiles are in enforce.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `sudo aa-status | grep -A 100 'profiles are in complain mode'` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.7.2.3` | Ensure no AppArmor profiles are in complain mode |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `apparmor`, `mac`, `manual-verify`

---

### `linux-mac-selinux-enforcing`

**SELinux must be enforcing on RHEL-family hosts** &middot; severity `high` &middot; service `mac` &middot; resource `linux.host`

SELinux 'enforcing' is the production posture — 'permissive' logs violations without blocking them (useful only during policy tuning); 'disabled' removes the MAC layer entirely. CIS Linux Server v8 §1.7.1.4 requires enforcing on RHEL-family hosts.

_Remediation:_

> sudo setenforce 1                # live
sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config   # persist

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.7.1.4` | Ensure SELinux mode is enforcing |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `mac`, `selinux`

---

### `linux-mac-selinux-no-permissive-services`

**No SELinux services should be in permissive mode** &middot; severity `medium` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §1.7.1.5. Per-service permissive overrides (semanage permissive) are sometimes added during policy debug + forgotten. Audit periodically.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `sudo semanage permissive -l` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.7.1.5` | Ensure no SELinux services are in permissive mode |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `mac`, `manual-verify`, `selinux`

---

### `linux-mount-dev-shm-nodev`

**/dev/shm must be mounted with nodev** &middot; severity `medium` &middot; service `filesystem` &middot; resource `linux.host`

nodev mount option on /dev/shm; CIS Linux Server v8 §1.1.8.2. nodev on /dev/shm prevents the world-writable tmpfs from hosting device files.

_Remediation:_

> Edit /etc/fstab — append nodev to the options column for /dev/shm:

  UUID=... /dev/shm tmpfs defaults,rw,nodev 0 0

Apply live without reboot: `sudo mount -o remount,nodev /dev/shm`. Persistence requires the fstab edit.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.1.8.2` | Ensure nodev option set on /dev/shm |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `mount`, `nodev`

---

### `linux-mount-dev-shm-noexec`

**/dev/shm must be mounted with noexec** &middot; severity `medium` &middot; service `filesystem` &middot; resource `linux.host`

noexec mount option on /dev/shm; CIS Linux Server v8 §1.1.8.4. noexec on /dev/shm; same rationale as /tmp.

_Remediation:_

> Edit /etc/fstab — append noexec to the options column for /dev/shm:

  UUID=... /dev/shm tmpfs defaults,rw,noexec 0 0

Apply live without reboot: `sudo mount -o remount,noexec /dev/shm`. Persistence requires the fstab edit.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.1.8.4` | Ensure noexec option set on /dev/shm |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `mount`, `noexec`

---

### `linux-mount-dev-shm-nosuid`

**/dev/shm must be mounted with nosuid** &middot; severity `medium` &middot; service `filesystem` &middot; resource `linux.host`

nosuid mount option on /dev/shm; CIS Linux Server v8 §1.1.8.3. nosuid on /dev/shm; same rationale as /tmp.

_Remediation:_

> Edit /etc/fstab — append nosuid to the options column for /dev/shm:

  UUID=... /dev/shm tmpfs defaults,rw,nosuid 0 0

Apply live without reboot: `sudo mount -o remount,nosuid /dev/shm`. Persistence requires the fstab edit.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.1.8.3` | Ensure nosuid option set on /dev/shm |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `mount`, `nosuid`

---

### `linux-mount-home-nodev`

**/home must be mounted with nodev** &middot; severity `low` &middot; service `filesystem` &middot; resource `linux.host`

nodev mount option on /home; CIS Linux Server v8 §1.1.7.2. nodev on /home prevents user-created device files.

_Remediation:_

> Edit /etc/fstab — append nodev to the options column for /home:

  UUID=... /home tmpfs defaults,rw,nodev 0 0

Apply live without reboot: `sudo mount -o remount,nodev /home`. Persistence requires the fstab edit.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.1.7.2` | Ensure nodev option set on /home partition |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `mount`, `nodev`

---

### `linux-mount-home-nosuid`

**/home must be mounted with nosuid** &middot; severity `medium` &middot; service `filesystem` &middot; resource `linux.host`

nosuid mount option on /home; CIS Linux Server v8 §1.1.7.3. nosuid on /home stops users from staging setuid binaries in their own home directories.

_Remediation:_

> Edit /etc/fstab — append nosuid to the options column for /home:

  UUID=... /home tmpfs defaults,rw,nosuid 0 0

Apply live without reboot: `sudo mount -o remount,nosuid /home`. Persistence requires the fstab edit.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.1.7.3` | Ensure nosuid option set on /home partition |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `mount`, `nosuid`

---

### `linux-mount-home-separate`

**/home must be its own filesystem** &middot; severity `low` &middot; service `filesystem` &middot; resource `linux.host`

Separate mount for /home; CIS Linux Server v8 §1.1.7.1. Separate /home admits nodev/nosuid + lets user-data backups be filesystem-snapshot-driven independently of OS state.

_Remediation:_

> Plan downtime + repartition: create a dedicated partition / LVM volume + mount at /home. For new builds use a partition layout that breaks out /tmp /var /var/log /var/log/audit /home from /. systemd-mount(8) + /etc/fstab carry the persistent state.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.1.7.1` | Ensure /home is a separate partition |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `mount`, `separate-partition`

---

### `linux-mount-tmp-nodev`

**/tmp must be mounted with nodev** &middot; severity `medium` &middot; service `filesystem` &middot; resource `linux.host`

nodev mount option on /tmp; CIS Linux Server v8 §1.1.2.2. nodev prevents the creation of device files on /tmp, blocking a class of exploits where an attacker mknods their own /dev/sda.

_Remediation:_

> Edit /etc/fstab — append nodev to the options column for /tmp:

  UUID=... /tmp tmpfs defaults,rw,nodev 0 0

Apply live without reboot: `sudo mount -o remount,nodev /tmp`. Persistence requires the fstab edit.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.1.2.2` | Ensure nodev option set on /tmp partition |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `mount`, `nodev`

---

### `linux-mount-tmp-noexec`

**/tmp must be mounted with noexec** &middot; severity `medium` &middot; service `filesystem` &middot; resource `linux.host`

noexec mount option on /tmp; CIS Linux Server v8 §1.1.2.4. noexec prevents executing arbitrary files dropped in /tmp — blocks a common payload-execution staging area for fileless malware + exploit kits.

_Remediation:_

> Edit /etc/fstab — append noexec to the options column for /tmp:

  UUID=... /tmp tmpfs defaults,rw,noexec 0 0

Apply live without reboot: `sudo mount -o remount,noexec /tmp`. Persistence requires the fstab edit.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.1.2.4` | Ensure noexec option set on /tmp partition |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `mount`, `noexec`

---

### `linux-mount-tmp-nosuid`

**/tmp must be mounted with nosuid** &middot; severity `medium` &middot; service `filesystem` &middot; resource `linux.host`

nosuid mount option on /tmp; CIS Linux Server v8 §1.1.2.3. nosuid disables SUID bit honoring on /tmp — a copied-out setuid binary can't elevate privileges.

_Remediation:_

> Edit /etc/fstab — append nosuid to the options column for /tmp:

  UUID=... /tmp tmpfs defaults,rw,nosuid 0 0

Apply live without reboot: `sudo mount -o remount,nosuid /tmp`. Persistence requires the fstab edit.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.1.2.3` | Ensure nosuid option set on /tmp partition |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `mount`, `nosuid`

---

### `linux-mount-tmp-separate`

**/tmp must be its own filesystem** &middot; severity `medium` &middot; service `filesystem` &middot; resource `linux.host`

Separate mount for /tmp; CIS Linux Server v8 §1.1.2.1. Isolating /tmp lets the operator quota it, mount it with nodev/nosuid/noexec, and reset it on reboot — none of which work when /tmp is a directory in /.

_Remediation:_

> Plan downtime + repartition: create a dedicated partition / LVM volume + mount at /tmp. For new builds use a partition layout that breaks out /tmp /var /var/log /var/log/audit /home from /. systemd-mount(8) + /etc/fstab carry the persistent state.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.1.2.1` | Ensure /tmp is a separate partition |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `mount`, `separate-partition`

---

### `linux-mount-var-log-audit-separate`

**/var/log/audit must be its own filesystem** &middot; severity `high` &middot; service `filesystem` &middot; resource `linux.host`

Separate mount for /var/log/audit; CIS Linux Server v8 §1.1.6.1. auditd takes the host offline if /var/log/audit fills up (default behavior). Separate filesystem with a generous size prevents accidental DoS-by-log-overflow.

_Remediation:_

> Plan downtime + repartition: create a dedicated partition / LVM volume + mount at /var/log/audit. For new builds use a partition layout that breaks out /tmp /var /var/log /var/log/audit /home from /. systemd-mount(8) + /etc/fstab carry the persistent state.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.1.6.1` | Ensure /var/log/audit is a separate partition |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit`, `mount`, `separate-partition`

---

### `linux-mount-var-log-separate`

**/var/log must be its own filesystem** &middot; severity `medium` &middot; service `filesystem` &middot; resource `linux.host`

Separate mount for /var/log; CIS Linux Server v8 §1.1.5.1. Separate /var/log keeps log growth from breaking other /var consumers + admits per-mount quotas / forwarding.

_Remediation:_

> Plan downtime + repartition: create a dedicated partition / LVM volume + mount at /var/log. For new builds use a partition layout that breaks out /tmp /var /var/log /var/log/audit /home from /. systemd-mount(8) + /etc/fstab carry the persistent state.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.1.5.1` | Ensure /var/log is a separate partition |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `logging`, `mount`, `separate-partition`

---

### `linux-mount-var-separate`

**/var must be its own filesystem** &middot; severity `medium` &middot; service `filesystem` &middot; resource `linux.host`

Separate mount for /var; CIS Linux Server v8 §1.1.3.1. Isolating /var prevents log-file growth from filling root and lets the operator mount with nodev.

_Remediation:_

> Plan downtime + repartition: create a dedicated partition / LVM volume + mount at /var. For new builds use a partition layout that breaks out /tmp /var /var/log /var/log/audit /home from /. systemd-mount(8) + /etc/fstab carry the persistent state.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.1.3.1` | Ensure /var is a separate partition |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `mount`, `separate-partition`

---

### `linux-mount-var-tmp-noexec`

**/var/tmp must be mounted with noexec** &middot; severity `medium` &middot; service `filesystem` &middot; resource `linux.host`

noexec mount option on /var/tmp; CIS Linux Server v8 §1.1.4.4. noexec on /var/tmp; same rationale as /tmp.

_Remediation:_

> Edit /etc/fstab — append noexec to the options column for /var/tmp:

  UUID=... /var/tmp tmpfs defaults,rw,noexec 0 0

Apply live without reboot: `sudo mount -o remount,noexec /var/tmp`. Persistence requires the fstab edit.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.1.4.4` | Ensure noexec option set on /var/tmp partition |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `mount`, `noexec`

---

### `linux-mount-var-tmp-separate`

**/var/tmp must be its own filesystem** &middot; severity `low` &middot; service `filesystem` &middot; resource `linux.host`

Separate mount for /var/tmp; CIS Linux Server v8 §1.1.4.1. Separate /var/tmp prevents user-created files in /var/tmp from competing with /var space + admits separate noexec/nosuid/nodev.

_Remediation:_

> Plan downtime + repartition: create a dedicated partition / LVM volume + mount at /var/tmp. For new builds use a partition layout that breaks out /tmp /var /var/log /var/log/audit /home from /. systemd-mount(8) + /etc/fstab carry the persistent state.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.1.4.1` | Ensure /var/tmp is a separate partition |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `mount`, `separate-partition`

---

### `linux-no-empty-passwords`

**No account may have an empty password** &middot; severity `high` &middot; service `users` &middot; resource `linux.host`

An account whose /etc/shadow password field is literally empty can be logged in to with any password (or no password, depending on PAM config). CIS Ubuntu 7.2.4 requires that no entry have an empty hash; locked accounts use '!' or '*' instead.

_Remediation:_

> passwd -l <user> to lock the account, or set a strong password.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.2` | Use Unique Passwords |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `passwords`, `users`

---

### `linux-no-source-routing`

**Kernel must not accept source-routed packets** &middot; severity `low` &middot; service `kernel` &middot; resource `linux.host`

Source-routed packets let a sender dictate the path taken across the network, defeating egress filtering and enabling spoofing. Modern Linux defaults to 0 (drop); this check confirms the default has not been overridden. CIS Ubuntu 3.3.1.

_Remediation:_

> sysctl -w net.ipv4.conf.all.accept_source_route=0 and persist via /etc/sysctl.d/.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `12.2` | Establish and Maintain a Secure Network Architecture |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `kernel`, `network`

---

### `linux-pam-faillock-configured`

**PAM must enforce account lockout after failed attempts (faillock / tally2)** &middot; severity `high` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §5.4.2.1. faillock (RHEL family, Ubuntu 22.04+) or pam_tally2 (older) implements account lockout after N failed password attempts. PAM stack varies per distro; verify the appropriate module is present + configured (CIS recommends deny=5, unlock_time=900).

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `sudo grep -E 'pam_faillock|pam_tally2' /etc/pam.d/* | head` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.4.2.1` | Ensure sudo commands are logged (Defaults logfile) |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `manual-verify`, `pam`

---

### `linux-pam-pwquality-configured`

**PAM pwquality must enforce length + complexity** &middot; severity `medium` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §5.4.3.1. pam_pwquality (or pam_passwdqc) enforces minimum password length (≥14 per CIS) + complexity classes. /etc/security/pwquality.conf carries the knobs.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `sudo cat /etc/security/pwquality.conf | grep -v '^#'` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.4.3.1` | Ensure NOPASSWD sudo entries are reviewed |
| `iso27001` | `A.5.17` | Authentication information |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `manual-verify`, `pam`

---

### `linux-passwd-perms`

**/etc/passwd must be 0644 or stricter** &middot; severity `medium` &middot; service `filesystem` &middot; resource `linux.host`

/etc/passwd must be world-readable (login commands need it) but must not be writable by anyone but root. CIS Ubuntu 7.1.2 prescribes mode 0644 exactly; we accept 0644 or stricter (0640, 0600).

_Remediation:_

> chmod 0644 /etc/passwd && chown root:root /etc/passwd.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.8.3` | Information access restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `filesystem`, `passwd`

---

### `linux-pkg-aide-installed`

**AIDE (file integrity) should be installed** &middot; severity `medium` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §6.1.1. AIDE periodically hashes system files + reports drift. Pair with a cron entry that emails the report.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `which aide && systemctl is-active aidecheck.timer` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `6.1.1` | Ensure AIDE (Advanced Intrusion Detection Environment) is installed |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `aide`, `manual-verify`, `packages`

---

### `linux-pkg-cron-restricted-to-root`

**cron.allow + at.allow must restrict to root (or specific users)** &middot; severity `low` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §5.1.2. Default cron permits every user to schedule jobs. Restrict via /etc/cron.allow (whitelist) + ensure /etc/cron.deny is empty/absent.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `ls -la /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.1.2` | Ensure cron.allow / at.allow restrict who may schedule jobs |
| `iso27001` | `A.5.15` | Access control |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `cron`, `manual-verify`, `packages`

---

### `linux-pkg-gpg-keys-trusted-only`

**Package manager must trust only documented signing keys** &middot; severity `high` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §1.2.1.1. apt + dnf both maintain a keychain of repository signing keys. Periodic audit catches keys added during ad-hoc 'add-apt-repository' sessions that were never reviewed.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `apt-key list 2>/dev/null` or `dnf repolist --enablerepo='*'` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.2.1.1` | Ensure GPG keys are configured (signed-only package sources) |
| `iso27001` | `A.8.32` | Change management |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `gpg`, `manual-verify`, `packages`

---

### `linux-pkg-no-orphaned-packages`

**Orphaned packages should be removed** &middot; severity `low` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §1.9.2. Packages with no rdepends are removable. Reduces attack surface for CVEs in dependencies the host doesn't actually use.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via Debian: `apt-get autoremove --dry-run`. RHEL: `dnf autoremove` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.9.2` | Ensure orphaned packages are removed |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `hygiene`, `manual-verify`, `packages`

---

### `linux-pkg-no-unattended-upgrades`

**Auto-updates of security patches should be enabled** &middot; severity `medium` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §1.9. Debian/Ubuntu: unattended-upgrades package. RHEL: dnf-automatic.timer. Periodic kernel + library updates without operator intervention.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `systemctl is-active unattended-upgrades` OR `systemctl is-active dnf-automatic.timer` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.9` | Ensure updates and security patches are installed |
| `iso27001` | `A.8.8` | Management of technical vulnerabilities |
| `soc2` | `CC7.1` | Detection and Monitoring of Vulnerabilities |

_Tags:_ `manual-verify`, `packages`, `patching`

---

### `linux-pkg-prelink-absent`

**prelink must not be installed** &middot; severity `medium` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §1.6.4. prelink rewrites ELF binaries to speed up library resolution — defeats package integrity verification (rpm -V / dpkg --verify report every binary modified).

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `dpkg -l prelink 2>/dev/null` or `rpm -q prelink 2>/dev/null` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.6.4` | Ensure prelink absence on production hosts |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `manual-verify`, `packages`, `prelink`

---

### `linux-service-auditd-enabled`

**auditd must be enabled at boot** &middot; severity `high` &middot; service `services` &middot; resource `linux.host`

systemd unit auditd.service; CIS Linux Server v8 §4.1.1.1. auditd captures the syscall-level audit trail every CIS / STIG / PCI control depends on. Enable at boot so a missed start doesn't blind the auditor.

_Remediation:_

> systemctl enable --now auditd.service     # must-run
systemctl disable --now auditd.service  # must-not-run
systemctl mask auditd.service            # must-absent (mask prevents accidental re-enable)
apt-get remove --purge auditd.service    # Debian/Ubuntu absent
dnf remove auditd.service                # RHEL family absent

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `4.1.1.1` | Ensure auditd is installed and running |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `audit`, `must-run`, `services`

---

### `linux-service-avahi-disabled`

**avahi-daemon must be disabled** &middot; severity `medium` &middot; service `services` &middot; resource `linux.host`

systemd unit avahi-daemon.service; CIS Linux Server v8 §2.2.3. Avahi (mDNS / zeroconf) is for ad-hoc LANs. Servers don't need it; running broadcasts hostnames + capabilities to anyone on the segment.

_Remediation:_

> systemctl enable --now avahi-daemon.service     # must-run
systemctl disable --now avahi-daemon.service  # must-not-run
systemctl mask avahi-daemon.service            # must-absent (mask prevents accidental re-enable)
apt-get remove --purge avahi-daemon    # Debian/Ubuntu absent
dnf remove avahi-daemon                # RHEL family absent

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `2.2.3` | Ensure Avahi (mDNS) Server is not installed |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `mdns`, `must-not-run`, `services`

---

### `linux-service-cron-active`

**cron daemon must be running (cron or cronie)** &middot; severity `medium` &middot; service `services` &middot; resource `linux.host`

systemd unit cron.service; CIS Linux Server v8 §5.1.1. Many hardening tasks (log rotation, aide scan, certificate renewal) are scheduled via cron. A missing cron daemon silently breaks those.

_Remediation:_

> systemctl enable --now cron.service     # must-run
systemctl disable --now cron.service  # must-not-run
systemctl mask cron.service            # must-absent (mask prevents accidental re-enable)
apt-get remove --purge cron.service    # Debian/Ubuntu absent
dnf remove cron.service                # RHEL family absent

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.1.1` | Ensure cron daemon is enabled |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `must-run`, `services`

---

### `linux-service-cups-disabled`

**cups (print server) must be disabled** &middot; severity `low` &middot; service `services` &middot; resource `linux.host`

systemd unit cups.service; CIS Linux Server v8 §2.2.5. Print services on a cloud server are a CIS hardening miss + a CVE attack surface for nothing.

_Remediation:_

> systemctl enable --now cups.service     # must-run
systemctl disable --now cups.service  # must-not-run
systemctl mask cups.service            # must-absent (mask prevents accidental re-enable)
apt-get remove --purge cups    # Debian/Ubuntu absent
dnf remove cups                # RHEL family absent

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `2.2.5` | Ensure CUPS is not installed |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `must-not-run`, `print`, `services`

---

### `linux-service-dhcpd-disabled`

**DHCP server must be disabled on non-DHCP hosts** &middot; severity `medium` &middot; service `services` &middot; resource `linux.host`

systemd unit isc-dhcp-server.service; CIS Linux Server v8 §2.2.7. A rogue DHCP server poisons the LAN's gateway. Most cloud workloads aren't DHCP servers; disable if not used.

_Remediation:_

> systemctl enable --now isc-dhcp-server.service     # must-run
systemctl disable --now isc-dhcp-server.service  # must-not-run
systemctl mask isc-dhcp-server.service            # must-absent (mask prevents accidental re-enable)
apt-get remove --purge isc-dhcp-server.service    # Debian/Ubuntu absent
dnf remove isc-dhcp-server.service                # RHEL family absent

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `2.2.7` | Ensure DHCP Server is not installed |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `dhcp`, `must-not-run`, `services`

---

### `linux-service-rsh-absent`

**rsh / rlogin / rexec must not be installed** &middot; severity `high` &middot; service `services` &middot; resource `linux.host`

systemd unit rsh.service; CIS Linux Server v8 §2.2.17. Same as telnet — cleartext credential transmission with no upside.

_Remediation:_

> systemctl enable --now rsh.service     # must-run
systemctl disable --now rsh.service  # must-not-run
systemctl mask rsh.service            # must-absent (mask prevents accidental re-enable)
apt-get remove --purge rsh-server inetutils-rsh    # Debian/Ubuntu absent
dnf remove rsh-server inetutils-rsh                # RHEL family absent

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `2.2.17` | Ensure rsh client + server is not installed |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `cleartext`, `must-absent`, `services`

---

### `linux-service-rsyslog-active`

**rsyslog (or journald-forwarder) must be running** &middot; severity `high` &middot; service `services` &middot; resource `linux.host`

systemd unit rsyslog.service; CIS Linux Server v8 §4.2.1.1. rsyslog forwards local logs off-host (TCP/RFC5424 to a SIEM). journald-only setups can use systemd-journal-upload instead but the SOC2 evidence requirement is the same: ≥90d off-host retention.

_Remediation:_

> systemctl enable --now rsyslog.service     # must-run
systemctl disable --now rsyslog.service  # must-not-run
systemctl mask rsyslog.service            # must-absent (mask prevents accidental re-enable)
apt-get remove --purge rsyslog.service    # Debian/Ubuntu absent
dnf remove rsyslog.service                # RHEL family absent

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `4.2.1.1` | Ensure journald is configured for persistent storage |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `logging`, `must-run`, `services`

---

### `linux-service-telnet-absent`

**telnetd must not be installed** &middot; severity `high` &middot; service `services` &middot; resource `linux.host`

systemd unit telnetd.service; CIS Linux Server v8 §2.2.16. telnet sends credentials in cleartext. Has no legitimate place on a 2026 server — there's always an ssh alternative.

_Remediation:_

> systemctl enable --now telnetd.service     # must-run
systemctl disable --now telnetd.service  # must-not-run
systemctl mask telnetd.service            # must-absent (mask prevents accidental re-enable)
apt-get remove --purge telnetd inetutils-telnetd    # Debian/Ubuntu absent
dnf remove telnetd inetutils-telnetd                # RHEL family absent

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `2.2.16` | Ensure rsync service is not installed in a vulnerable state |
| `iso27001` | `A.8.24` | Use of cryptography |
| `soc2` | `CC6.7` | Transmission, Movement, and Disposal of Information |

_Tags:_ `cleartext`, `must-absent`, `services`

---

### `linux-service-tftp-absent`

**tftp server must not be installed** &middot; severity `high` &middot; service `services` &middot; resource `linux.host`

systemd unit tftp-server.service; CIS Linux Server v8 §2.2.18. TFTP has no authentication. Boot servers (PXE, switch firmware) sometimes need it; flag + waive in that case.

_Remediation:_

> systemctl enable --now tftp-server.service     # must-run
systemctl disable --now tftp-server.service  # must-not-run
systemctl mask tftp-server.service            # must-absent (mask prevents accidental re-enable)
apt-get remove --purge tftpd-hpa tftp-server    # Debian/Ubuntu absent
dnf remove tftpd-hpa tftp-server                # RHEL family absent

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `2.2.18` | Ensure telnet client + server is not installed |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `cleartext`, `must-absent`, `services`

---

### `linux-service-time-sync-active`

**Time-sync daemon must be running (chrony or systemd-timesyncd)** &middot; severity `high` &middot; service `services` &middot; resource `linux.host`

systemd unit chronyd.service; CIS Linux Server v8 §2.1.1. Accurate clocks are prerequisite for log correlation, TLS validity, Kerberos. chronyd is the modern default; systemd-timesyncd is acceptable on hosts that don't need server-grade chrony features.

_Remediation:_

> systemctl enable --now chronyd.service     # must-run
systemctl disable --now chronyd.service  # must-not-run
systemctl mask chronyd.service            # must-absent (mask prevents accidental re-enable)
apt-get remove --purge chronyd.service    # Debian/Ubuntu absent
dnf remove chronyd.service                # RHEL family absent

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `2.1.1` | Ensure time synchronization is in use |
| `iso27001` | `A.8.17` | Clock synchronization |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `must-run`, `services`, `time`

---

### `linux-shadow-perms`

**/etc/shadow must be 0640 root:shadow** &middot; severity `high` &middot; service `filesystem` &middot; resource `linux.host`

/etc/shadow holds the password hashes for every local account. Read access for non-root, non-shadow users enables offline cracking and is the textbook CIS Ubuntu 7.1.3 finding. Correct ownership is root:shadow with mode 0640.

_Remediation:_

> chmod 0640 /etc/shadow && chown root:shadow /etc/shadow.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `cis-v8` | `5.1` | Establish and Maintain an Inventory of Accounts |
| `iso27001` | `A.8.3` | Information access restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `filesystem`, `shadow`

---

### `linux-sshd-banner-set`

**sshd_config Banner must be set (typically /etc/issue.net)** &middot; severity `low` &middot; service `sshd` &middot; resource `linux.host`

banner; CIS Linux Server v8 §5.2.13. Login banner is the audit-evidence point for legal-notice display. /etc/issue.net is the CIS-conventional path.

_Remediation:_

> Edit /etc/ssh/sshd_config:
  banner /etc/issue.net
Then `sudo systemctl reload sshd`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.2.13` | Ensure SSH banner is configured |
| `iso27001` | `A.5.10` | Acceptable use of information and other associated assets |
| `soc2` | `CC1.4` | Commitment to Competence |

_Tags:_ `banner`, `sshd`

---

### `linux-sshd-client-alive-count-max`

**sshd_config ClientAliveCountMax must be ≤ 3** &middot; severity `low` &middot; service `sshd` &middot; resource `linux.host`

clientalivecountmax; CIS Linux Server v8 §5.2.15. ClientAliveCountMax × ClientAliveInterval is the idle ceiling. ≤3 (CIS recommended) keeps the total under ~15 min when paired with the recommended interval.

_Remediation:_

> Edit /etc/ssh/sshd_config:
  clientalivecountmax 3
Then `sudo systemctl reload sshd`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.2.15` | Ensure SSH ClientAliveCountMax is configured |
| `iso27001` | `A.5.16` | Identity management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `session`, `sshd`

---

### `linux-sshd-client-alive-interval`

**sshd_config ClientAliveInterval must be > 0 and ≤ 300** &middot; severity `low` &middot; service `sshd` &middot; resource `linux.host`

clientaliveinterval; CIS Linux Server v8 §5.2.14. Idle SSH sessions get reaped after ClientAliveInterval × ClientAliveCountMax seconds. ≤300s caps abandoned tmux/screen sessions.

_Remediation:_

> Edit /etc/ssh/sshd_config:
  clientaliveinterval 300
Then `sudo systemctl reload sshd`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.2.14` | Ensure SSH ClientAliveInterval is configured |
| `iso27001` | `A.5.16` | Identity management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `session`, `sshd`

---

### `linux-sshd-hostbased-auth-disabled`

**sshd_config HostbasedAuthentication must be no** &middot; severity `medium` &middot; service `sshd` &middot; resource `linux.host`

hostbasedauthentication; CIS Linux Server v8 §5.2.8. Host-based authentication trusts the client host's hostkey — a per-host trust model that's hard to revoke and easy to mismanage.

_Remediation:_

> Edit /etc/ssh/sshd_config:
  hostbasedauthentication no
Then `sudo systemctl reload sshd`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.2.8` | Ensure SSH HostbasedAuthentication is disabled |
| `iso27001` | `A.5.16` | Identity management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `sshd`

---

### `linux-sshd-ignore-rhosts`

**sshd_config IgnoreRhosts must be yes** &middot; severity `medium` &middot; service `sshd` &middot; resource `linux.host`

ignorerhosts; CIS Linux Server v8 §5.2.7. .rhosts is rsh-era trust; IgnoreRhosts=yes (the default) tells sshd not to honor the file.

_Remediation:_

> Edit /etc/ssh/sshd_config:
  ignorerhosts yes
Then `sudo systemctl reload sshd`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.2.7` | Ensure SSH IgnoreRhosts is enabled |
| `iso27001` | `A.5.16` | Identity management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `rhosts`, `sshd`

---

### `linux-sshd-login-grace-time`

**SSH LoginGraceTime should be 60 seconds or less** &middot; severity `low` &middot; service `sshd` &middot; resource `linux.host`

LoginGraceTime is the window between connection and authentication completion. A long window lets a misbehaving client (or attacker) hold a connection slot open, enabling slowloris-style resource exhaustion. OpenSSH default is 2 minutes; CIS recommends 60 seconds or less.

_Remediation:_

> Set 'LoginGraceTime 60' in /etc/ssh/sshd_config and reload sshd.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.2` | Use Unique Passwords |
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.20` | Networks security |
| `iso27001` | `A.8.21` | Security of network services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `resource-exhaustion`, `sshd`

---

### `linux-sshd-loglevel-info-or-verbose`

**sshd_config LogLevel must be INFO or VERBOSE** &middot; severity `medium` &middot; service `sshd` &middot; resource `linux.host`

loglevel; CIS Linux Server v8 §5.2.5. VERBOSE logs key fingerprints for every login (essential for audit). INFO is the upstream default and acceptable; QUIET drops too much detail.

_Remediation:_

> Edit /etc/ssh/sshd_config:
  loglevel VERBOSE
Then `sudo systemctl reload sshd`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.2.5` | Ensure SSH LogLevel is INFO or VERBOSE |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `logging`, `sshd`

---

### `linux-sshd-max-auth-tries`

**SSH MaxAuthTries should be 4 or less** &middot; severity `low` &middot; service `sshd` &middot; resource `linux.host`

MaxAuthTries caps the number of authentication attempts per connection; a low value frustrates online brute-force. The OpenSSH default is 6; CIS Controls v8 recommends 4 or less.

_Remediation:_

> Set 'MaxAuthTries 4' (or lower) in /etc/ssh/sshd_config and reload sshd.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.2` | Use Unique Passwords |
| `iso27001` | `A.8.21` | Security of network services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `brute-force`, `sshd`

---

### `linux-sshd-max-sessions`

**sshd_config MaxSessions must be ≤ 10** &middot; severity `low` &middot; service `sshd` &middot; resource `linux.host`

maxsessions; CIS Linux Server v8 §5.2.21. MaxSessions caps the concurrent sessions one auth'd user may open. ≤10 (CIS) constrains a compromised key's blast radius.

_Remediation:_

> Edit /etc/ssh/sshd_config:
  maxsessions 10
Then `sudo systemctl reload sshd`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.2.21` | Ensure SSH MaxSessions is configured |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `sshd`

---

### `linux-sshd-no-password-auth`

**SSH must not accept password authentication** &middot; severity `medium` &middot; service `sshd` &middot; resource `linux.host`

Password authentication exposes SSH to credential stuffing and online brute-force. Public-key authentication is the modern baseline. SOC 2 CC6.1 and CIS Controls v8 5.2 both require strong authentication for remote administrative access.

_Remediation:_

> Set 'PasswordAuthentication no' in /etc/ssh/sshd_config (and confirm operators have working public-key access first to avoid lockout). Reload sshd to apply.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.2` | Use Unique Passwords |
| `cis-v8` | `6.5` | Require MFA for Administrative Access |
| `iso27001` | `A.8.21` | Security of network services |
| `iso27001` | `A.8.5` | Secure authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `authentication`, `sshd`

---

### `linux-sshd-no-root-login`

**SSH must not permit root login** &middot; severity `high` &middot; service `sshd` &middot; resource `linux.host`

Direct root SSH logins bypass per-user auditability and remove the speed bump that catches automated brute-force. SOC 2 CC6.1 / CC6.6, ISO 27001 A.8.21, and CIS Controls v8 5.4 all require unique attribution for privileged access.

_Remediation:_

> Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd (systemctl reload sshd). Operators should use a named user + sudo instead.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `iso27001` | `A.8.21` | Security of network services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `access-control`, `sshd`

---

### `linux-sshd-permit-empty-passwords`

**sshd_config PermitEmptyPasswords must be no** &middot; severity `high` &middot; service `sshd` &middot; resource `linux.host`

permitemptypasswords; CIS Linux Server v8 §5.2.10. Empty passwords are an open door. The CIS default is no; verify even if you've never seen this misconfigured.

_Remediation:_

> Edit /etc/ssh/sshd_config:
  permitemptypasswords no
Then `sudo systemctl reload sshd`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.2.10` | Ensure SSH PermitEmptyPasswords is disabled |
| `iso27001` | `A.5.16` | Identity management |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `auth`, `sshd`

---

### `linux-sshd-permit-user-environment`

**sshd_config PermitUserEnvironment must be no** &middot; severity `medium` &middot; service `sshd` &middot; resource `linux.host`

permituserenvironment; CIS Linux Server v8 §5.2.11. PermitUserEnvironment=yes lets ~/.ssh/environment override LD_PRELOAD, PATH, etc. — sufficient for any local privilege escalation that needs an envvar.

_Remediation:_

> Edit /etc/ssh/sshd_config:
  permituserenvironment no
Then `sudo systemctl reload sshd`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.2.11` | Ensure SSH PermitUserEnvironment is disabled |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `sshd`

---

### `linux-sshd-protocol-2`

**SSH must use protocol version 2 only** &middot; severity `low` &middot; service `sshd` &middot; resource `linux.host`

SSH-1 was retired in 2017 and is cryptographically broken. Modern OpenSSH defaults to Protocol 2 and refuses to build SSH-1 without explicit flags; this check confirms the observed config has not been weakened. Mostly an audit-trail check at this point.

_Remediation:_

> Remove any 'Protocol 1' line from /etc/ssh/sshd_config (or set 'Protocol 2' explicitly). Reload sshd to apply.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `3.10` | Encrypt Sensitive Data in Transit |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `crypto`, `sshd`

---

### `linux-sshd-x11-forwarding-disabled`

**sshd_config X11Forwarding must be no** &middot; severity `medium` &middot; service `sshd` &middot; resource `linux.host`

x11forwarding; CIS Linux Server v8 §5.2.6. X11 forwarding exposes the local DISPLAY through the SSH tunnel — historically a vector for keystroke capture. Production servers don't need it.

_Remediation:_

> Edit /etc/ssh/sshd_config:
  x11forwarding no
Then `sudo systemctl reload sshd`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.2.6` | Ensure SSH X11 forwarding is disabled |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `sshd`, `x11`

---

### `linux-sudo-logging`

**sudo must log to syslog or a dedicated log file** &middot; severity `medium` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §5.4.5. sudo's default logging is via syslog. Verify the syslog target collects sudoers entries OR add a Defaults logfile= line.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `sudo grep -E '^Defaults.*(logfile|syslog)' /etc/sudoers` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.4.5` | Ensure sudo secure_path is set |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `manual-verify`, `sudo`

---

### `linux-sudo-nopasswd-audit`

**Audit /etc/sudoers + /etc/sudoers.d for NOPASSWD entries** &middot; severity `high` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §5.4.4. NOPASSWD entries let a compromised account elevate without re-auth. Every entry should be (a) auditable + (b) narrowly scoped (Cmnd_Alias) — not blanket. Per-distro PAM + sudoers parsing is deferred to a future milestone; verify manually.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `sudo grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.4.4` | Ensure sudo Defaults use_pty is enabled |
| `iso27001` | `A.5.15` | Access control |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `manual-verify`, `sudo`

---

### `linux-sudo-secure-path`

**/etc/sudoers must set secure_path (no user-controlled PATH)** &middot; severity `medium` &middot; service `auth` &middot; resource `linux.host`

Manual-verify check; CIS Linux Server v8 §5.4.3. secure_path strips the user's PATH and substitutes a hardcoded list — prevents trojan binaries in ~/bin from being run via sudo. Distro defaults differ; verify.

_Remediation:_

> Per-distro PAM + sudoers grammars are deferred; verify via `sudo grep ^Defaults.*secure_path /etc/sudoers` + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `5.4.3` | Ensure sudo authentication timeout is configured |
| `iso27001` | `A.5.15` | Access control |
| `soc2` | `CC6.3` | Authorization, Modification, and Removal |

_Tags:_ `manual-verify`, `sudo`

---

### `linux-sysctl-accept-redirects-all`

**ICMP redirects must be ignored (all)** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

ICMP redirects let any host on the LAN tell the kernel to route through a different gateway — an obvious MITM primitive. Always disabled on servers.

_Remediation:_

> /etc/sysctl.d/60-network-hardening.conf:
  net.ipv4.conf.all.accept_redirects = 0
  net.ipv4.conf.default.accept_redirects = 0

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.2` | Ensure packet redirect sending is disabled |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `icmp`, `network`, `sysctl`

---

### `linux-sysctl-accept-redirects-default`

**ICMP redirects must be ignored (default)** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

Paired with the 'all' counterpart; default applies to new interfaces.

_Remediation:_

> See linux-sysctl-accept-redirects-all.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.2` | Ensure packet redirect sending is disabled |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `icmp`, `network`, `sysctl`

---

### `linux-sysctl-accept-source-route-default`

**Source-routed packets must be dropped (default)** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

Source routing lets the sender dictate the path a packet takes — bypasses upstream firewalls + reverses NAT mappings. Always disabled on servers.

_Remediation:_

> /etc/sysctl.d/60-network-hardening.conf:
  net.ipv4.conf.all.accept_source_route = 0
  net.ipv4.conf.default.accept_source_route = 0

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.1` | Ensure IP forwarding is disabled (unless router) |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `network`, `sysctl`

---

### `linux-sysctl-bpf-jit-harden`

**net.core.bpf_jit_harden must be ≥1** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

BPF JIT hardening mitigates CPU speculative-execution side-channel attacks in JIT-compiled BPF programs. 1=privileged hardening; 2=all programs hardened.

_Remediation:_

> /etc/sysctl.d/60-kernel-hardening.conf:
  net.core.bpf_jit_harden = 2

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.5.5` | Ensure dmesg_restrict is set |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `bpf`, `kernel`, `sysctl`

---

### `linux-sysctl-dmesg-restrict`

**kernel.dmesg_restrict must be enabled** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

dmesg_restrict prevents unprivileged users from reading the kernel ring buffer (KASLR offsets, addresses of loaded modules, hardware MAC addresses). 1 = root-only; 0 = anyone.

_Remediation:_

> /etc/sysctl.d/60-kernel-hardening.conf:
  kernel.dmesg_restrict = 1

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.5.1` | Ensure address space layout randomization (ASLR) is enabled |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `info-leak`, `kernel`, `sysctl`

---

### `linux-sysctl-icmp-echo-ignore-broadcasts`

**Smurf-amplifier ICMP echo must be ignored** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

Ignoring broadcast ICMP echo blocks the classic Smurf DoS amplifier where attackers spoof a victim address and broadcast an echo request.

_Remediation:_

> /etc/sysctl.d/60-network-hardening.conf:
  net.ipv4.icmp_echo_ignore_broadcasts = 1

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.5` | Ensure bogus ICMP responses are ignored |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `icmp`, `network`, `sysctl`

---

### `linux-sysctl-icmp-ignore-bogus-error-responses`

**Bogus ICMP error responses must be ignored** &middot; severity `low` &middot; service `kernel` &middot; resource `linux.host`

Silently drops bogus ICMP error responses that some routers emit in violation of RFC 1122 — reduces kernel-log noise that masks real attacks.

_Remediation:_

> /etc/sysctl.d/60-network-hardening.conf:
  net.ipv4.icmp_ignore_bogus_error_responses = 1

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.6` | Ensure reverse-path filtering is enabled |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `icmp`, `network`, `sysctl`

---

### `linux-sysctl-ip-forward-disabled`

**IPv4 forwarding must be disabled on non-router hosts** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

ip_forward=1 turns the host into a router (forwards packets between interfaces). Container hosts running Docker/k8s flip this to 1 intentionally; non-router servers leave it at 0. Waive on Docker / k8s nodes via waivers.yaml.

_Remediation:_

> /etc/sysctl.d/60-network-hardening.conf:
  net.ipv4.ip_forward = 0
Waive when the host genuinely routes (k8s node, NAT gateway).

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.2.2` | Ensure ICMP redirects are not accepted (IPv4) |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `network`, `sysctl`

---

### `linux-sysctl-ipv6-accept-ra-all`

**IPv6 router advertisements must be ignored (all)** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

Router Advertisements let any host on the L2 segment set the default IPv6 gateway — Stateless Address Autoconfig (SLAAC) primitive. On managed cloud networks (static IPv6 from the provider) disabling RA blocks rogue-router attacks.

_Remediation:_

> /etc/sysctl.d/60-ipv6-hardening.conf:
  net.ipv6.conf.all.accept_ra = 0
  net.ipv6.conf.default.accept_ra = 0

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.9` | Ensure secure ICMP redirects are not accepted |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `ipv6`, `network`, `sysctl`

---

### `linux-sysctl-ipv6-accept-ra-default`

**IPv6 router advertisements must be ignored (default)** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

Default counterpart to the 'all' rule.

_Remediation:_

> See linux-sysctl-ipv6-accept-ra-all.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.9` | Ensure secure ICMP redirects are not accepted |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `ipv6`, `network`, `sysctl`

---

### `linux-sysctl-ipv6-accept-redirects-all`

**IPv6 ICMP redirects must be ignored (all)** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

Same MITM concern as IPv4 ICMP redirects, applied to the v6 stack.

_Remediation:_

> /etc/sysctl.d/60-ipv6-hardening.conf:
  net.ipv6.conf.all.accept_redirects = 0
  net.ipv6.conf.default.accept_redirects = 0

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.2` | Ensure packet redirect sending is disabled |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `ipv6`, `network`, `sysctl`

---

### `linux-sysctl-ipv6-accept-redirects-default`

**IPv6 ICMP redirects must be ignored (default)** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

Default counterpart to the 'all' rule.

_Remediation:_

> See linux-sysctl-ipv6-accept-redirects-all.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.2` | Ensure packet redirect sending is disabled |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `ipv6`, `network`, `sysctl`

---

### `linux-sysctl-ipv6-source-route-all`

**IPv6 source routing must be disabled (all)** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

Same path-spoofing concern as IPv4 source routing, applied to the v6 stack.

_Remediation:_

> /etc/sysctl.d/60-ipv6-hardening.conf:
  net.ipv6.conf.all.accept_source_route = 0
  net.ipv6.conf.default.accept_source_route = 0

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.1` | Ensure IP forwarding is disabled (unless router) |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `ipv6`, `network`, `sysctl`

---

### `linux-sysctl-ipv6-source-route-default`

**IPv6 source routing must be disabled (default)** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

Default counterpart to the 'all' rule.

_Remediation:_

> See linux-sysctl-ipv6-source-route-all.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.1` | Ensure IP forwarding is disabled (unless router) |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `ipv6`, `network`, `sysctl`

---

### `linux-sysctl-kptr-restrict`

**kernel.kptr_restrict must be ≥1 (CIS: 2)** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

kptr_restrict hides kernel pointer values from /proc — defeats KASLR-defeat exploits that scrape /proc/kallsyms etc. 1 redacts for unprivileged; 2 redacts for everyone.

_Remediation:_

> /etc/sysctl.d/60-kernel-hardening.conf:
  kernel.kptr_restrict = 2

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.5.2` | Ensure ptrace_scope is restricted |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `info-leak`, `kernel`, `sysctl`

---

### `linux-sysctl-log-martians-all`

**Martian packets must be logged (all)** &middot; severity `low` &middot; service `kernel` &middot; resource `linux.host`

Martian packets (impossible source addresses) are logged when this knob is enabled — a useful signal that something is either spoofing or seriously misconfigured upstream.

_Remediation:_

> /etc/sysctl.d/60-network-hardening.conf:
  net.ipv4.conf.all.log_martians = 1
  net.ipv4.conf.default.log_martians = 1

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.8` | Ensure IPv6 router advertisements are not accepted |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `logging`, `network`, `sysctl`

---

### `linux-sysctl-log-martians-default`

**Martian packets must be logged (default)** &middot; severity `low` &middot; service `kernel` &middot; resource `linux.host`

Default counterpart to the 'all' rule.

_Remediation:_

> See linux-sysctl-log-martians-all.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.8` | Ensure IPv6 router advertisements are not accepted |
| `iso27001` | `A.8.15` | Logging |
| `soc2` | `CC7.2` | System Component Monitoring |

_Tags:_ `logging`, `network`, `sysctl`

---

### `linux-sysctl-protected-hardlinks`

**fs.protected_hardlinks must be enabled** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

protected_hardlinks blocks unprivileged users from creating hardlinks to files they don't own — a classic prelude to /etc/passwd race exploits.

_Remediation:_

> /etc/sysctl.d/60-fs-hardening.conf:
  fs.protected_hardlinks = 1

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.6.2` | Ensure unprivileged BPF is disabled |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `filesystem`, `sysctl`

---

### `linux-sysctl-protected-symlinks`

**fs.protected_symlinks must be enabled** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

protected_symlinks restricts symlink-following in world-writable directories — kills TOCTOU race exploits via /tmp symlinks.

_Remediation:_

> /etc/sysctl.d/60-fs-hardening.conf:
  fs.protected_symlinks = 1

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.6.3` | Ensure BPF JIT hardening is enabled |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `filesystem`, `sysctl`

---

### `linux-sysctl-rp-filter-all`

**net.ipv4.conf.all.rp_filter must be strict (1)** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

Reverse Path filtering rejects packets arriving on an interface that wouldn't be used to reply (IP spoofing mitigation). Strict mode (1) matches the RFC 3704 recommendation.

_Remediation:_

> /etc/sysctl.d/60-network-hardening.conf:
  net.ipv4.conf.all.rp_filter = 1
  net.ipv4.conf.default.rp_filter = 1
Then `sysctl --system`.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.7` | Ensure TCP SYN cookies are enabled |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `network`, `rp-filter`, `sysctl`

---

### `linux-sysctl-rp-filter-default`

**net.ipv4.conf.default.rp_filter must be strict (1)** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

The 'default' value is applied to any new interface created after sysctl is set; pair with the 'all' counterpart so currently-attached + future interfaces both filter.

_Remediation:_

> See linux-sysctl-rp-filter-all — set both keys together.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.7` | Ensure TCP SYN cookies are enabled |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `network`, `rp-filter`, `sysctl`

---

### `linux-sysctl-secure-redirects-all`

**Secure ICMP redirects must be disabled (all)** &middot; severity `low` &middot; service `kernel` &middot; resource `linux.host`

secure_redirects accepts redirects from gateways in the default route — slightly safer than accept_redirects but still rejected by CIS for servers.

_Remediation:_

> /etc/sysctl.d/60-network-hardening.conf:
  net.ipv4.conf.all.secure_redirects = 0
  net.ipv4.conf.default.secure_redirects = 0

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.3` | Ensure martian packets are logged |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `icmp`, `network`, `sysctl`

---

### `linux-sysctl-secure-redirects-default`

**Secure ICMP redirects must be disabled (default)** &middot; severity `low` &middot; service `kernel` &middot; resource `linux.host`

Default counterpart to the 'all' rule.

_Remediation:_

> See linux-sysctl-secure-redirects-all.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.3` | Ensure martian packets are logged |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `icmp`, `network`, `sysctl`

---

### `linux-sysctl-send-redirects-default`

**Kernel must not send ICMP redirects (default)** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

Only routers should emit ICMP redirects. End-user servers + cloud workloads disable both 'all' and 'default'.

_Remediation:_

> /etc/sysctl.d/60-network-hardening.conf:
  net.ipv4.conf.all.send_redirects = 0
  net.ipv4.conf.default.send_redirects = 0

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.2.1` | Ensure source-routed packets are not accepted (IPv4) |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `network`, `sysctl`

---

### `linux-sysctl-suid-dumpable`

**fs.suid_dumpable must be 0 (no core dumps from SUID)** &middot; severity `high` &middot; service `kernel` &middot; resource `linux.host`

SUID programs that core dump can leak privileged memory (cached secrets, fd contents). Per CIS, 0 = SUID processes never core dump; 1 = always; 2 = root-readable only.

_Remediation:_

> /etc/sysctl.d/60-fs-hardening.conf:
  fs.suid_dumpable = 0

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.6.1` | Ensure kernel.kptr_restrict is set (kernel address hiding) |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `filesystem`, `suid`, `sysctl`

---

### `linux-sysctl-tcp-syncookies`

**net.ipv4.tcp_syncookies must be enabled** &middot; severity `high` &middot; service `kernel` &middot; resource `linux.host`

SYN cookies allow the kernel to handle the SYN queue without reserving state until the three-way handshake completes — the primary defense against SYN flood denial-of-service. Disabled-by-default on some older builds; enable by setting net.ipv4.tcp_syncookies=1.

_Remediation:_

> Persist via /etc/sysctl.d/60-tcp-syncookies.conf:
  net.ipv4.tcp_syncookies = 1
Then `sysctl --system` to apply.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `3.3.4` | Ensure broadcast ICMP requests are ignored |
| `cis-v8` | `9.2` | Use DNS Filtering Services |
| `iso27001` | `A.8.20` | Networks security |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `network`, `syn-flood`, `sysctl`

---

### `linux-sysctl-unprivileged-bpf-disabled`

**kernel.unprivileged_bpf_disabled must be 1** &middot; severity `high` &middot; service `kernel` &middot; resource `linux.host`

Unprivileged eBPF has been a recurring source of LPE CVEs (CVE-2021-3490, CVE-2022-23222, CVE-2023-2236). Disable unless a specific workload (Cilium, Falco) needs it; even then, prefer CAP_BPF over universal access.

_Remediation:_

> /etc/sysctl.d/60-kernel-hardening.conf:
  kernel.unprivileged_bpf_disabled = 1
Waive on hosts running Cilium / Falco / eBPF observability.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.5.4` | Ensure prelink is not installed |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `bpf`, `kernel`, `sysctl`

---

### `linux-sysctl-yama-ptrace-scope`

**kernel.yama.ptrace_scope must be ≥1** &middot; severity `medium` &middot; service `kernel` &middot; resource `linux.host`

Yama restricts ptrace() across processes the caller didn't fork — kills the LD_PRELOAD-then-attach style credential extraction. 0=permissive, 1=restricted (recommended), 2=admin-only, 3=disabled.

_Remediation:_

> /etc/sysctl.d/60-kernel-hardening.conf:
  kernel.yama.ptrace_scope = 1

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-linux-server` | `1.5.3` | Ensure core dumps are restricted (suid_dumpable) |
| `iso27001` | `A.8.7` | Protection against malware |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `kernel`, `sysctl`

---

### `linux-uid-zero-only-root`

**Only the root account may have UID 0** &middot; severity `high` &middot; service `users` &middot; resource `linux.host`

A second account with UID 0 is a stealth backdoor: sudo / auditd see the username but every privilege check resolves to root. CIS Ubuntu 5.4.3 requires that only the literal 'root' user holds UID 0.

_Remediation:_

> userdel <hidden-root-account> or change its UID to a non-zero value with usermod -u <uid> <name>.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Administrator Accounts |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.8.2` | Privileged access rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security Boundaries |

_Tags:_ `privilege`, `users`

---

