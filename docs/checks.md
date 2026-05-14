# Check catalog

<!--
  AUTO-GENERATED FILE -- DO NOT EDIT BY HAND.
  Regenerate with: make docs
  Source of truth: internal/checks/**/*.go (the core.Check vars).
-->

This catalog is generated from the live registry on each release. At the current revision, compliancekit ships **70 checks** across the providers below.

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
| `digitalocean` | 5 |
| `gcp` | 20 |
| `linux` | 15 |
| **total** | **70** |

## By severity

| Severity | Checks |
|---|---:|
| `critical` | 4 |
| `high` | 30 |
| `medium` | 26 |
| `low` | 10 |

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
| `iso27001` | `A.8.16` | Monitoring Activities |
| `soc2` | `CC7.2` | System Operations - Monitoring |
| `soc2` | `CC7.3` | System Operations - Incident Evaluation |

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
| `soc2` | `CC7.2` | System Operations - Monitoring |
| `soc2` | `CC7.3` | System Operations - Incident Evaluation |

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
| `soc2` | `CC7.2` | System Operations - Monitoring |

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
| `soc2` | `CC7.2` | System Operations - Monitoring |

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
| `iso27001` | `A.8.16` | Monitoring Activities |
| `soc2` | `CC7.2` | System Operations - Monitoring |
| `soc2` | `CC7.3` | System Operations - Incident Evaluation |

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
| `iso27001` | `A.8.24` | Use of Cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

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
| `iso27001` | `A.8.20` | Networks Security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `iso27001` | `A.8.20` | Networks Security |
| `iso27001` | `A.8.22` | Segregation of Networks |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `iso27001` | `A.8.12` | Data Leakage Prevention |
| `iso27001` | `A.8.3` | Information Access Restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `iso27001` | `A.8.20` | Networks Security |
| `iso27001` | `A.8.21` | Security of Network Services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `cis-v8` | `8.5` | Collect Detailed Audit Logs |
| `iso27001` | `A.8.16` | Monitoring Activities |
| `soc2` | `CC7.2` | System Operations - Monitoring |
| `soc2` | `CC7.3` | System Operations - Incident Evaluation |

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
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Accounts |
| `iso27001` | `A.8.2` | Privileged Access Rights |
| `iso27001` | `A.8.5` | Secure Authentication |
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
| `cis-v8` | `6.5` | Require MFA for Administrative Access |
| `iso27001` | `A.8.5` | Secure Authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Accounts |
| `iso27001` | `A.5.15` | Access Control |
| `iso27001` | `A.8.2` | Privileged Access Rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

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
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Accounts |
| `iso27001` | `A.5.15` | Access Control |
| `iso27001` | `A.8.2` | Privileged Access Rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

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
| `iso27001` | `A.8.5` | Secure Authentication |
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
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Accounts |
| `cis-v8` | `6.5` | Require MFA for Administrative Access |
| `iso27001` | `A.8.2` | Privileged Access Rights |
| `iso27001` | `A.8.5` | Secure Authentication |
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
| `cis-v8` | `6.5` | Require MFA for Administrative Access |
| `iso27001` | `A.8.5` | Secure Authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `iso27001` | `A.8.2` | Privileged Access Rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

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
| `iso27001` | `A.8.24` | Use of Cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

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
| `iso27001` | `A.8.13` | Information Backup |
| `iso27001` | `A.8.24` | Use of Cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `iso27001` | `A.8.13` | Information Backup |
| `soc2` | `A1.2` | Availability - Backup and Recovery |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Accounts |
| `iso27001` | `A.8.13` | Information Backup |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `iso27001` | `A.8.24` | Use of Cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

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
| `iso27001` | `A.8.20` | Networks Security |
| `iso27001` | `A.8.21` | Security of Network Services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `iso27001` | `A.8.24` | Use of Cryptography |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

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
| `soc2` | `CC7.2` | System Operations - Monitoring |

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
| `iso27001` | `A.8.20` | Networks Security |
| `iso27001` | `A.8.3` | Information Access Restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.8.20` | Networks Security |
| `iso27001` | `A.8.3` | Information Access Restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `iso27001` | `A.8.13` | Information Backup |
| `iso27001` | `A.8.14` | Redundancy of Information Processing Facilities |
| `soc2` | `A1.2` | Availability - Backup and Recovery |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `backup`, `recovery`, `s3`

---

## digitalocean

### `do-droplet-backups-disabled`

**Droplet backups must be enabled** &middot; severity `medium` &middot; service `droplets` &middot; resource `digitalocean.droplet`

DigitalOcean droplet backups take a weekly snapshot used to recover from incidents, ransomware, or accidental deletion. SOC 2 CC6.6 and CIS Controls v8 11.2 both require some form of backup capability for production data.

_Remediation:_

> Enable backups for the droplet via 'doctl compute droplet-action enable-backups <id>' or set 'backups: true' in your Terraform digitalocean_droplet resource.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `11.2` | Perform Automated Backups |
| `iso27001` | `A.5.30` | ICT Readiness for Business Continuity |
| `iso27001` | `A.8.13` | Information Backup |
| `soc2` | `A1.2` | Availability - Backup and Recovery |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `backup`, `recovery`

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
| `iso27001` | `A.8.21` | Security of Network Services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `iso27001` | `A.5.9` | Inventory of Information and Other Associated Assets |
| `soc2` | `CC1.4` | Commitment to Competence |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `attribution`, `inventory`

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
| `iso27001` | `A.8.19` | Installation of Software on Operational Systems |
| `iso27001` | `A.8.8` | Management of Technical Vulnerabilities |
| `soc2` | `CC7.1` | System Operations - Vulnerabilities |
| `soc2` | `CC7.2` | System Operations - Monitoring |

_Tags:_ `patching`, `vulnerability`

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
| `iso27001` | `A.8.21` | Security of Network Services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `exposure`, `network`, `ssh`

---

## gcp

### `gcp-compute-no-broad-scopes`

**GCE instances must not run with cloud-platform service-account scope** &middot; severity `high` &middot; service `compute` &middot; resource `gcp.compute.instance`

The cloud-platform OAuth scope grants the attached service account access to every GCP API the SA has IAM permissions for. Combined with the default Compute Engine SA (which has roles/editor by default), this gives any process on the instance project-wide write access. CIS GCP 4.1 + 4.2 prescribe narrower scopes (specific service-level scopes) or IAM-only access control with no scopes.

_Remediation:_

> Stop the instance, change its scopes to specific service scopes only (e.g. logging-write, monitoring-write): 'gcloud compute instances set-service-account <name> --scopes=logging-write,monitoring-write,storage-ro'. Better: rely on IAM permissions and remove the cloud-platform scope.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Accounts |
| `iso27001` | `A.5.15` | Access Control |
| `iso27001` | `A.8.2` | Privileged Access Rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

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
| `iso27001` | `A.8.20` | Networks Security |
| `iso27001` | `A.8.22` | Segregation of Networks |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `iso27001` | `A.8.20` | Networks Security |
| `iso27001` | `A.8.21` | Security of Network Services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Accounts |
| `cis-v8` | `6.5` | Require MFA for Administrative Access |
| `iso27001` | `A.8.2` | Privileged Access Rights |
| `iso27001` | `A.8.5` | Secure Authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `iso27001` | `A.8.7` | Protection Against Malware |
| `iso27001` | `A.8.8` | Management of Technical Vulnerabilities |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |
| `soc2` | `CC7.1` | System Operations - Vulnerabilities |

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
| `iso27001` | `A.8.16` | Monitoring Activities |
| `soc2` | `CC7.2` | System Operations - Monitoring |
| `soc2` | `CC7.3` | System Operations - Incident Evaluation |

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
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Accounts |
| `iso27001` | `A.5.15` | Access Control |
| `iso27001` | `A.8.2` | Privileged Access Rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

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
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Accounts |
| `iso27001` | `A.5.15` | Access Control |
| `iso27001` | `A.8.2` | Privileged Access Rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

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
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Accounts |
| `iso27001` | `A.5.15` | Access Control |
| `iso27001` | `A.8.2` | Privileged Access Rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

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
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Accounts |
| `iso27001` | `A.8.5` | Secure Authentication |
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
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Accounts |
| `iso27001` | `A.8.2` | Privileged Access Rights |
| `iso27001` | `A.8.5` | Secure Authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `credentials`, `iam`, `rotation`, `service-account`

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
| `soc2` | `CC7.2` | System Operations - Monitoring |
| `soc2` | `CC7.3` | System Operations - Incident Evaluation |

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
| `iso27001` | `A.8.15` | Logging |
| `iso27001` | `A.8.16` | Monitoring Activities |
| `soc2` | `CC7.2` | System Operations - Monitoring |
| `soc2` | `CC7.3` | System Operations - Incident Evaluation |

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
| `iso27001` | `A.8.13` | Information Backup |
| `iso27001` | `A.8.14` | Redundancy of Information Processing Facilities |
| `soc2` | `A1.2` | Availability - Backup and Recovery |

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
| `iso27001` | `A.8.13` | Information Backup |
| `soc2` | `A1.2` | Availability - Backup and Recovery |

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
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.8.20` | Networks Security |
| `iso27001` | `A.8.22` | Segregation of Networks |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `soc2` | `CC7.2` | System Operations - Monitoring |

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
| `cis-v8` | `3.3` | Configure Data Access Control Lists |
| `iso27001` | `A.8.20` | Networks Security |
| `iso27001` | `A.8.3` | Information Access Restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `iso27001` | `A.8.20` | Networks Security |
| `iso27001` | `A.8.3` | Information Access Restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `iso27001` | `A.8.13` | Information Backup |
| `iso27001` | `A.8.14` | Redundancy of Information Processing Facilities |
| `soc2` | `A1.2` | Availability - Backup and Recovery |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `backup`, `recovery`, `storage`

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
| `iso27001` | `A.8.8` | Management of Technical Vulnerabilities |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `exploit-mitigation`, `kernel`

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
| `soc2` | `CC7.2` | System Operations - Monitoring |
| `soc2` | `CC7.3` | System Operations - Incident Evaluation |

_Tags:_ `audit`, `logging`

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
| `iso27001` | `A.8.20` | Networks Security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `iso27001` | `A.8.20` | Networks Security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `default-policy`, `firewall`, `network`

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
| `soc2` | `CC7.2` | System Operations - Monitoring |

_Tags:_ `audit`, `journald`, `logging`

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
| `iso27001` | `A.8.5` | Secure Authentication |
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
| `iso27001` | `A.8.20` | Networks Security |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `kernel`, `network`

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
| `iso27001` | `A.8.3` | Information Access Restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `filesystem`, `passwd`

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
| `iso27001` | `A.8.3` | Information Access Restriction |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `filesystem`, `shadow`

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
| `iso27001` | `A.8.20` | Networks Security |
| `iso27001` | `A.8.21` | Security of Network Services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `resource-exhaustion`, `sshd`

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
| `iso27001` | `A.8.21` | Security of Network Services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `brute-force`, `sshd`

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
| `iso27001` | `A.8.21` | Security of Network Services |
| `iso27001` | `A.8.5` | Secure Authentication |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

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
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Accounts |
| `iso27001` | `A.8.21` | Security of Network Services |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `access-control`, `sshd`

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
| `iso27001` | `A.8.20` | Networks Security |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |

_Tags:_ `crypto`, `sshd`

---

### `linux-uid-zero-only-root`

**Only the root account may have UID 0** &middot; severity `high` &middot; service `users` &middot; resource `linux.host`

A second account with UID 0 is a stealth backdoor: sudo / auditd see the username but every privilege check resolves to root. CIS Ubuntu 5.4.3 requires that only the literal 'root' user holds UID 0.

_Remediation:_

> userdel <hidden-root-account> or change its UID to a non-zero value with usermod -u <uid> <name>.

_Maps to:_

| Framework | Control | Title |
|---|---|---|
| `cis-v8` | `5.4` | Restrict Administrator Privileges to Dedicated Accounts |
| `cis-v8` | `6.8` | Define and Maintain Role-Based Access Control |
| `iso27001` | `A.8.2` | Privileged Access Rights |
| `soc2` | `CC6.1` | Logical and Physical Access Controls |
| `soc2` | `CC6.6` | Logical Access Security - Boundaries |

_Tags:_ `privilege`, `users`

---

