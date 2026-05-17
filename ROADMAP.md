# Roadmap

Five-weekend path from empty repo to public launch. Each milestone is shippable on its own; we never carry broken state forward.

The phases are sized to ~10–15 hours of focused work. Each ends with a concrete demo you could screenshot for Twitter.

---

## v0.1 — Foundation (weekend 1) ✅ shipped
**Goal:** scan a DigitalOcean account, get useful JSON back.

### Deliverables
- Project scaffold: `cmd/compliancekit`, cobra CLI, viper config, golangci-lint, Make targets, basic CI.
- `core` types: `Finding`, `Resource`, `Check`, `Collector`, `Evaluator`, `Severity`, `ControlMapping`.
- **Resource graph from day 1:** `Collector` fetches → typed `[]Resource`; `Evaluator` runs checks against the graph. Even with one provider, the split prevents a painful v0.6 refactor. See ARCHITECTURE §3.
- **Daemon-aware interfaces:** no package-level globals; every long-lived path takes `context.Context`. Pays off at v1.1 when `serve` lands.
- `engine` orchestrator: parallel check execution per provider with bounded concurrency.
- DigitalOcean collector via `godo`: **10 high-value checks** (see ARCHITECTURE §8 for the prioritized list).
- JSON output only.
- `compliancekit doctor` for smoke testing.
- README scaffold (placeholder, no marketing yet).

### Demo
```
$ export DO_API_TOKEN=...
$ compliancekit scan digitalocean
Scanning DigitalOcean (10 checks)...
✓ Account: 2FA enforced
✗ Droplet web-01: no firewall attached (high)
✗ Spaces bucket assets: public ACL (high)
...
24 findings (3 high, 8 medium, 13 low) in 4.2s
$ compliancekit scan digitalocean --output=json --out=findings.json
```

### Definition of done
- `go install ./...` works on a clean machine.
- CI passes on push.
- `compliancekit scan digitalocean` returns a non-zero exit if any high-severity finding exists.
- 10 checks have unit tests against recorded godo fixtures.

---

## v0.2 — Linux (weekend 2) ✅ shipped
**Goal:** scan a fleet of Linux droplets over SSH.

### Deliverables
- `linux` provider with pooled SSH connections (`x/crypto/ssh`).
- `inventory.yaml` parser: hosts, groups, SSH overrides, optional bastion.
- **15 CIS-aligned Linux checks** (see ARCHITECTURE §9).
- Agentless: snippets run remotely, parsed locally.
- Configurable parallelism (`max_parallel`, default 16).
- Graceful host-unreachable handling — one bad host doesn't kill the run.

### Demo
```
$ compliancekit scan linux --inventory=inventory.yaml
Scanning 12 hosts (15 checks each)...
web-01 ✓ sshd-no-root-login
web-01 ✗ sshd-password-auth (medium)
web-01 ✗ ufw-default-deny (high)
db-01  ⚠ unreachable: i/o timeout
...
12 hosts, 180 checks, 18 findings, 1 host unreachable
```

### Definition of done
- Docker Compose harness in `test/` with Ubuntu 22.04 + Debian 12 containers; CI runs the checks against them.
- SSH connections respect `~/.ssh/config` and SSH agent.
- Secrets never appear in logs or evidence output.

---

## v0.3 — Reports and frameworks (weekend 3) ✅ shipped
**Goal:** a scan turns into something a human (or an auditor) can actually read.

### Deliverables
- HTML report: single-file, no JS framework, embedded via `go:embed`. Search, filter by severity/framework, per-finding drill-down.
- Markdown summary suitable for posting in a PR.
- SARIF output for GitHub Code Scanning ingestion.
- **JSON-OCSF output** (Open Cybersecurity Schema Framework) for downstream SIEM ingestion. Aligns with Prowler's output story; cheap to add now, painful to retrofit.
- Framework definitions and mappings: SOC 2 TSC, CIS Controls v8 (with CIS Ubuntu/Debian Benchmark).
- `compliancekit checks list --framework=soc2` and `--framework=cis-v8`.

### Demo
- A real `report.html` you can open in a browser, dark mode, filterable.
- A real Markdown summary posted by a sample GitHub Action run.

### Definition of done
- HTML report renders correctly on 1920×1080 and 375×667 (mobile).
- SARIF passes [GitHub's validator](https://sarifweb.azurewebsites.net/Validation).
- Every check in v0.1+v0.2 has at least one SOC 2 CC mapping and one CIS v8 mapping.

---

## v0.4 — Evidence pack (weekend 4) ✅ shipped
**Goal:** turn a scan into a folder that an actual auditor would accept.

### Deliverables
- `compliancekit evidence` subcommand. ✅
- Folder structure per ARCHITECTURE §10 — controls grouped by framework, every artifact dated. ✅
- `MANIFEST.sha256` over the whole pack, sha256sum(1)-format and byte-stable across re-runs. ✅
- `control-mapping.csv` in a format Drata/Vanta/AuditBoard can import. ✅
- ISO 27001:2022 Annex A catalog added (`internal/frameworks/iso27001.yaml`), 100% of v0.3 checks mapped. ✅
- Per-control human-readable Markdown summaries auto-generated. ✅
- `summary.html` auditor index (self-contained, dark mode, navigable). ✅
- Redaction by default (AWS keys, GitHub PATs, Slack tokens, bearer headers, emails); `--include-raw` opt-in. ✅

### Demo (actual v0.4 output)
```
$ compliancekit evidence --in findings.json --out evidence/2026-Q2/
Generating evidence pack from findings.json (2 findings)...
SOC 2 Trust Services Criteria: 2 controls covered, 2 with open findings
ISO/IEC 27001:2022 Annex A:    1 controls covered, 1 with open findings
CIS Controls v8:               3 controls covered, 3 with open findings
Output: /abs/evidence/2026-Q2 (15 files, MANIFEST.sha256 written)
Auditor index: /abs/evidence/2026-Q2/summary.html
Control mapping: /abs/evidence/2026-Q2/control-mapping.csv
```

### Definition of done
- A tarball of an evidence pack passes a manual review against a SOC 2 readiness checklist. ⏳ (manual gate, pre-v0.5)
- `control-mapping.csv` imports cleanly into a sample Drata/Vanta sheet (validated against published schemas). ⏳ (manual gate, pre-v0.5)
- `sha256sum -c MANIFEST.sha256` succeeds for every file emitted. ✅ (smoke verified)

---

## v0.5 — Public launch (weekend 5) 🟡 code complete, awaiting launch
**Goal:** ship to the public and earn the first 500 stars.

### Deliverables
- README: hero asciinema (placeholder until recorded), install one-liner, the audience pitch ("Prowler for the people Prowler forgot"), framework table, sample evidence pack, FAQ. ✅
- `goreleaser` for cross-compiled binaries + Homebrew tap + Docker image (`ghcr.io/darpanzope/compliancekit`). ✅
- GitHub Action `darpanzope/compliancekit-action@v1` (source-of-truth under `action/`, copy-to-dedicated-repo at release time). ✅
- Cosign-signed releases (keyless via GitHub OIDC) + SBOM via goreleaser. ✅
- `CONTRIBUTING.md`, `SECURITY.md`, issue templates, PR template. ✅
- Auto-generated check catalog at `docs/checks.md` (CI gate enforces freshness). ✅
- Companion blog post on `darpan.cloud`. ⏳ (drafted as part of LAUNCH.md, not yet posted)

### Launch sequence (single day)
See [LAUNCH.md](LAUNCH.md) for the full playbook (pre-flight checklist,
pre-written posts, rollback plan). Summary:

1. Tag `v0.5.0`. Goreleaser publishes Homebrew formula, Docker image, GitHub Release with binaries.
2. Post on Hacker News: *"Show HN: compliancekit — SOC 2 evidence packs for DigitalOcean and Linux."*
3. Cross-post: r/devops, r/sysadmin, r/cybersecurity, r/digitalocean, r/SaaS, lobste.rs.
4. Email DigitalOcean's community-tutorials team — they actively promote OSS that helps their users.
5. Submit to `tldr.sec` newsletter.
6. LinkedIn + Twitter post with the demo gif.

### Definition of done
- One-line install works on macOS and Linux. ⏳ (verified in pre-flight)
- `compliancekit-action` runs successfully on a public test repo. ⏳ (verified in pre-flight)
- README is the kind of README we'd star. ✅

---

## Post-launch: v0.6 and beyond

Sequenced for compounding value. Each minor is one to two weekends. Reality
will reorder this once launch feedback arrives — the value is in having the
shape locked, not the order.

The cloud sequence was reshuffled from the pre-launch plan: **AWS, GCP, and
DigitalOcean deepening come before Hetzner**. Rationale recorded in
[DECISIONS.md ADR-007](DECISIONS.md). The TL;DR: AWS unlocks the enterprise
audience and the SOC-2-readiness use case at much larger scale than Hetzner;
GCP pairs with AWS for the cloud-portable SaaS shops; deepening DO is owed
to the v0.1-v0.5 audience that put compliancekit on the map.

| Version | Theme | Headline |
|---|---|---|
| **v0.6** ✅ | **Drift + baseline + 0-100 hardening score** | "Your score went from 78 to 73 since Friday" |
| **v0.7** ✅ | **AWS** | First-class AWS hardening, 30 checks across IAM/EC2/S3/RDS/CloudTrail/KMS/Config/GuardDuty |
| **v0.8** ✅ | **GCP** | First-class GCP hardening, 25 checks across IAM/Compute/GCS/Cloud SQL/Logging/KMS/BigQuery |
| **v0.9** ✅ | **DigitalOcean depth pass — everything except DOKS** | 5 → 74 checks across 20 services; the most comprehensive OSS DigitalOcean scanner |
| **v0.10** ✅ | **Hetzner Cloud** | 15 checks across servers/firewalls/networks/LBs/volumes/floating IPs |
| **v0.11** ✅ | **Kubernetes + EKS / GKE / DOKS-deep** | 139 checks across pods, controllers, RBAC, network, storage, namespaces/admission, nodes + EKS/GKE/DOKS enrichment — production-grade K8s posture across the four clouds we ship |
| **v0.12** ✅ | **Framework expansion (NIST 800-53 r5, HIPAA, PCI-DSS v4, MITRE ATT&CK) + tailoring + evidence-pack depth** | 7 frameworks × 548 controls; existing 3 expanded to full catalogs; ATT&CK as the first kill-chain threat-model lens; tailoring lets operators scope controls out with justifications |
| **v0.13** ✅ | IaC / OCSF / OSCAL ingest + emit + OSCAL AR/Profile emit + mapping CLI | 3 ingest formats (SARIF / OCSF / OSCAL Catalog) covering 7 tools; 2 OSCAL emits (Assessment Results + Profile); 106 starter rule mappings; lossless OCSF round-trip; runtime framework registration |
| **v0.14** ✅ | Vuln / secret / SCA ingest (Trivy, Grype, Checkov, gitleaks) + image-SHA graph join + vulnerabilities.csv + ADR-010 secret-redaction | 4 native-JSON adapters, every CVE tied to its running cloud resource, fingerprint-only secret handling |
| ~~v0.15~~ ✅ | Remediation generators (Bash, Terraform, kubectl, Helm, Ansible, aws/gcloud/az/doctl/hcloud + POA&M + Jira/Linear) | Copy-paste this Terraform to fix |
| ~~v0.16~~ ✅ | Rego policy DSL (via OPA) + 4 custom built-ins + `policy test/validate/fmt` CLI + 15 reimplementations | Write a check in 10 lines of Rego |
| ~~v0.17~~ ✅ | Notifications — 8 sinks (Slack, Discord, Teams, Email, Webhook, GitHub PR, Jira, PagerDuty) + dedup + only-new mode + per-sink severity floor | Slack alert on every new high finding |
| ~~v0.18~~ ✅ | Waivers + in-code skip annotations — 4 CLI subcommands + 6 file types + evidence-pack `waivers.json` + 4 control-mapping columns + ADR-013 | Mute findings the right way |
| ~~v0.19~~ ✅ | DigitalOcean deepening — 74 → 144 checks across 21 services; every DO check ships with bespoke Terraform + doctl + bash remediation (432 strategies); checks-package coverage 96.1% | Production-grade DO posture |
| ~~v0.20~~ ✅ | Linux hardening — production grade — 15 → 119 checks across 9 spec frameworks; CIS Linux Server Benchmark v8 catalog (90+ sections, L1/L2 tagged); per-distro detection (Debian, RHEL, Alpine, AL2/AL2023); every check ships bespoke bash + Ansible (238 strategies, parity gate at 0/0); checks-package coverage 90.6% | Linux hardening at OpenSCAP/Lynis depth |
| ~~v0.21~~ ✅ | Kubernetes + DOKS deepening — production grade — 149 → 241 checks (+92 / +61%) across 12 phases; NSA/CISA Kubernetes Hardening Guide v1.2 framework yaml; every K8s check ships bespoke kubectl (102 backfilled, strict-equality parity gate at 0); checks-package coverage 52.4% | Production-grade K8s posture across CIS + NSA/CISA |
| ~~v0.22~~ ✅ | Internal refactor + toolchain refresh + action-repo polish — 600-LoC check-file CI gate (internal/repocheck); 9 oversize files split (rbac/pods/network/cluster/reliability/eks/aws-iam/pods_extra/tail.go) into 11 new per-category siblings; Ubuntu 24.04 explicit pin in all 3 workflows; godo + k8s.io v0.34→0.36 + cobra + viper + opa dep sweep; compliancekit-action multi-provider input loop + jq-merged findings + opt-in evidence-pack workflow-artifact upload. **No new user-facing checks; sets up v1.0 API freeze.** Spec-pattern lifts + fake-API-server coverage + lint v2 + deep cookbook deferred to v0.22.x. | Structure debt paid down |
| **v1.0** | API stability — `pkg/compliancekit` frozen | Embed compliancekit in your own tools |
| v1.1 | `serve` mode + SQLite/Postgres backend + REST API + webhook receivers | Continuous monitoring without the SaaS bill |
| v1.2 | Multi-tenant / organizations | MSP-friendly: one binary, many clients |
| v1.3 | Trust Center generator | Your public security page, generated |
| v1.4 | GRC layer — risk register, vendor register, CAIQ/SIG templates, training tracking | Risk + vendors + questionnaires in repo |
| v1.5 | Auditor portal (auth-gated, time-boxed, watermarked exports) | Give your auditor read-only access |
| v1.6 | macOS + Windows + BSD hardening | Hardening for every machine you own |
| v1.7 | Tail clouds — Cloudflare, GitHub, Google Workspace, Vercel, Linode, Vultr | Every SaaS surface your SaaS touches |
| v1.8 | OSCAL ecosystem (catalogs in, assessment results out) + SCAP DataStream import | FedRAMP-curious? OSCAL in, OSCAL out |
| v1.9 | Risk score + executive PDF + time-series dashboard | One number for your board |
| v2.0 | Plugin marketplace — subprocess gRPC + WASM (wazero), cosign-signed | Install a check pack with one command |
| v2.x | K8s operator — CRDs (`ComplianceScan`, `ComplianceProfile`, `ComplianceWaiver`) | Reconcile compliance from a CRD |
| v2.x | Auto-remediation (opt-in, dry-run default, full audit log) | Fix it for me — if you really want |

The full table is the high-level view; v0.6 through v1.0 are expanded
below, in order. Versions past v1.0 stay in table form here because
real-world feedback after launch is the right input to plan them in
detail — pinning them now means re-planning them in six months.

---

### v0.6 — Drift + baseline + hardening score ✅ shipped

**Goal:** turn compliancekit from "list of findings" into "trendable
state of your fleet."

**Deliverables**

- `compliancekit baseline` subcommand: snapshot the current findings
  set as the accepted baseline. Stored under `.compliancekit/baseline.json`
  (gitignored by default; opt-in commit for "fail PR if drift"). ✅
- `compliancekit diff <old> <new>` subcommand: classify findings as
  `new` / `existing` / `resolved` via the existing `Finding.Fingerprint()`
  hash. Severity-aware exit codes so CI can gate on "any new high since
  last scan" instead of "any finding ever." ✅ (`--fail-on=new-high`)
- **Hardening score** — a 0-100 integer rolled up from the resource
  graph. Weighting formula locked in DECISIONS.md ADR-008 (50/20/8/3/1
  by severity, skips excluded). Score sits next to the count in `scan`
  output, in the HTML reporter, and in the evidence pack's
  `summary.html`. ✅
- **Profiles**: named subsets of the catalog (`ci-fast`, `pre-audit`,
  `cis-only`) declared in `compliancekit.yaml`. Same binary, different
  scope per environment. ✅
- **Engine: `graph.Query()` filter expressions** — small DSL with
  `=` / `!=` / `CONTAINS` / `AND` / `OR` / `NOT` / parens; identifiers
  resolve to Resource fields or attributes. ✅

**Demo**

```
$ compliancekit baseline
Captured 24 findings as baseline in .compliancekit/baseline.json
Hardening score: 76/100

$ # ... a week and three PRs later ...
$ compliancekit diff .compliancekit/baseline.json out/findings.json
+ 2 new   (1 high, 1 medium)
- 1 resolved
= 23 existing
Hardening score: 76 → 73 (-3)
fail-on=new-high: exit 2

$ compliancekit scan --profile ci-fast    # 8 checks instead of 35
```

**Definition of done**

- Score is deterministic: two runs over identical input produce identical numbers. ✅ (pinned by `TestCompute_Deterministic`)
- Score is monotonic: pass-up never decreases, fail-down never increases. ✅ (pinned by `TestCompute_Monotonic_*`)
- `diff` exit codes documented in CLI.md; CI integration recipe in the docs. ✅
- Baseline schema is versioned (`schema: compliancekit.baseline.v1`) so v0.7 cannot accidentally invalidate v0.6 baselines. ✅
- `graph.Query()` parses every expression in CHECKS.md's example block. ✅

---

### v0.7 — AWS (weekend 7) ✅ shipped

**rc1 → final:** v0.7.0-rc1 cut at end of weekend 1 with 18 checks
(IAM + S3 + EC2). v0.7.0 final shipped all 30 (added RDS + CloudTrail
+ KMS + Config + GuardDuty).


**Goal:** first-class AWS hardening. Stop the "would love to use this
but we're on AWS" replies on the launch HN thread.

This is the largest single milestone in the post-launch sequence and
the one most likely to slip its weekend budget. AWS is the most-used
cloud and the most-scrutinized one; shipping it half-baked is worse
than not shipping it. Plan for two weekends with a v0.7.0-rc1 cut at
end of weekend 1.

**Scope: the 30 highest-leverage AWS checks**

Not Prowler-parity. We pick the 30 that map cleanly to the three
frameworks we already ship (SOC 2, ISO 27001:2022, CIS v8) and that
land the most operational value per check. The full enumeration lives
in `internal/checks/aws/` as the work lands; the shape:

| Service | Checks |
|---|---|
| IAM | 8 (root key, MFA on root, password policy, access-key age, unused users, attached-managed-policy review, console-MFA, no `*:*` in inline policies) |
| EC2 | 5 (security-group 0.0.0.0/0 ingress, default-VPC usage, IMDSv2 required, EBS encrypted, no public AMIs) |
| S3 | 5 (block-public-access, default encryption, versioning, logging enabled, no public ACLs) |
| RDS | 4 (encryption, public-access off, backup retention, deletion protection) |
| CloudTrail | 3 (trail enabled, multi-region, log-file validation) |
| KMS | 2 (key rotation, CMK vs AWS-managed for sensitive services) |
| Config + GuardDuty | 3 (Config recorder on, GuardDuty enabled, S3 public-access via Config rule) |

**Plumbing**

- New collector at `internal/collectors/aws/` using the official
  AWS SDK for Go v2. SDK clients are pooled per region; default
  scope is "all regions the credentials can see" with explicit
  `--regions` filter in `compliancekit.yaml`.
- **Authentication: same chain the AWS CLI uses** — explicit
  `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`, `AWS_PROFILE`,
  `AWS_ROLE_ARN` (assume-role for the cross-account case),
  IMDSv2 instance role when running on EC2, GitHub Actions OIDC
  when running in the Action. No new auth surface for the user
  to learn.
- Per-service rate limiting using the SDK's adaptive throttle mode
  so a 50-account fleet does not get throttled into the next year.
- **Account / region resource scope** added to `core.Resource`:
  every AWS resource carries `account_id` and `region` attributes
  so cross-account fleets render in the evidence pack with
  unambiguous identity.

**Framework mappings**

Every AWS check ships with all three of {soc2, iso27001, cis-v8}
populated, same bar as v0.5. The CIS AWS Foundations Benchmark
v3.0 is the source of truth for the CIS mappings; SOC 2 / ISO use
the same control catalog as the existing checks.

**Demo**

```
$ AWS_PROFILE=prod compliancekit scan aws
Scanning AWS account 123456789012 (us-east-1, us-west-2; 30 checks)...
✗ root user has active access keys                   (critical, soc2/CC6.1)
✗ S3 bucket 'company-uploads' has no default encryption (high, iso27001/A.8.24)
✗ EC2 sg-0abc... allows 0.0.0.0/0 on port 22         (high, cis-v8/4.4)
✓ CloudTrail is multi-region                         (medium)
...
46 findings (2 critical, 9 high, 17 medium, 18 low) in 38s
Hardening score: 64/100
```

**Definition of done**

- 30 AWS checks, all with framework mappings, all with fixture-backed tests.
- End-to-end run against a real AWS test account (`darpanzope-test`)
  completes in <60s for a single-region account, <5m for all
  enabled regions on a 100-resource account.
- IMDSv2 and OIDC paths verified by running the GitHub Action against
  a public sandbox repo.
- The evidence pack groups AWS findings under
  `<framework>/<control>/aws-<service>-<rule>/` correctly; the
  `control-mapping.csv` includes the `account_id`/`region` columns so
  Drata/Vanta imports stay unambiguous on a multi-account fleet.
- Docs: `CONFIGURATION.md` adds the AWS section (regions, profile,
  role-ARN); `docs/checks.md` regenerates without manual edits.

**Out of scope at v0.7**

- AWS Organizations multi-account traversal (lands at v1.2 with
  multi-tenant).
- Inspector / Macie / Security Hub *ingest* (lands at v0.13 alongside
  OCSF).
- EKS-specific checks (land at v0.11 with the K8s arc).

---

### v0.8 — GCP ✅ shipped

**Goal:** GCP at the same depth as AWS at v0.7. The SDK pattern is
identical so the second cloud is much cheaper than the first.

**Scope: 25 GCP checks**

| Service | Checks |
|---|---|
| IAM | 6 (no primitive roles, no broad token-creator, audit logging, SA-key age, no user-managed SA keys, no default SA in use) |
| Compute Engine | 5 (no default network, no SSH from 0.0.0.0/0, OS Login enforced, shielded-VM, no broad SA scopes) |
| GCS | 4 (uniform bucket-level access, public-access prevention, versioning, access logging) |
| Cloud SQL | 3 (no public IPv4, automated backups, deletion protection) |
| Cloud Logging | 2 (long-term sink exists per project, log bucket retention ≥365d) |
| KMS | 2 (encrypt/decrypt key rotation ≤90d, admin/user role separation) |
| BigQuery | 3 (no public datasets, no allAuthenticatedUsers, default CMEK) |

**Plumbing**

- New collector at `internal/collectors/gcp/` using
  `cloud.google.com/go`. Per-API client pooled per project.
- Authentication: `gcloud` ADC, explicit service-account JSON,
  Workload Identity Federation when running in the Action. Same
  shape as AWS — env-first, file fallback, federated for CI.
- Resource scope adds `project_id` to `core.Resource`. Fleet-wide
  scans against an organization happen via the `--projects` filter
  (defaults to "all visible to the credential"), not a special
  org-traversal mode (which lands at v1.2).
- **Shared cloud abstractions**: the AWS work at v0.7 produced a
  thin `internal/collectors/cloudcommon/` for region/account
  resource attribution; GCP plugs in.

**Framework mappings**

CIS GCP Foundations v2.0 for the CIS side; SOC 2 / ISO 27001
mappings reuse the existing catalog. Every check, all three
frameworks.

**Demo**

```
$ gcloud auth application-default login
$ compliancekit scan gcp --projects my-prod,my-staging
Scanning GCP projects my-prod, my-staging (25 checks)...
✗ project 'my-prod': default network exists           (high, cis-v8/4.5)
✗ project 'my-prod': GCS bucket 'uploads' allows allUsers (critical, soc2/CC6.1)
✓ project 'my-staging': Cloud SQL instance has automated backups (medium)
...
31 findings (1 critical, 6 high, ...) in 22s
Hardening score: 71/100
```

**Definition of done**

- 25 GCP checks, all with framework mappings, all fixture-backed.
- Workload Identity Federation auth path verified end-to-end via
  the Action against a sandbox project.
- `--projects` filter respects "all visible" default and explicit
  list.
- Evidence pack column for `project_id` makes it onto
  `control-mapping.csv` next to `account_id` and `region`.

**Out of scope at v0.8**

- Organization-policy ingestion (v1.2).
- GKE-specific checks (v0.11).
- Security Command Center ingest (v0.13).

---

### v0.9 — DigitalOcean depth pass ✅ shipped

**Goal:** the most comprehensive OSS DigitalOcean security scanner.
Cover every DO surface except DOKS (which lands as part of the v0.11
K8s arc to ride one shared codebase across AWS / GCP / DO Kubernetes).
No current OSS tool ships first-class DigitalOcean hardening —
Prowler / ScoutSuite / CloudSploit all skip DO entirely; v0.9 fills
the gap. ADR-007 set the slot at "DO deepening, 25 checks"; the
scope was expanded to ~75 during the v0.8 → v0.9 transition because
the cloudcommon abstractions from v0.7-v0.8 mean each additional DO
check costs ~50-60% of what it would have at v0.7.

**At v0.5 (launch):** 5 DO checks — droplets-no-firewall, ssh-from-any,
backups-disabled, no-tags, old-image. **Shipped at v0.9: 74 DO checks
across 20 service families.**

| Surface | New | Notes |
|---|---:|---|
| **Account / team hardening** | 3 | MFA, recovery email, billing alerts |
| **Droplets** (deepening) | +4 | monitoring + droplet agents, VPC membership, public-IP discipline |
| **Firewalls** (deepening) | +5 | RDP, ANY/ANY ingress, default-deny outbound, broad port ranges, orphans |
| **VPCs / peering / NAT gateways** | 4 | no default VPC, orphan, cross-region peering, NAT presence |
| **Load Balancers** | 5 | HTTPS redirect, TLS ≥1.2, healthchecks, sticky-session security, allowlist |
| **Domains / DNS** | 4 | DNSSEC, CAA, SPF, DMARC |
| **Certificates** | 2 | expiry threshold, deprecated key types |
| **Managed Databases** | 8 | public access, trusted sources, TLS required, backups, version EOL, eviction policy, replicas, private network |
| **Spaces** (S3-compatible object storage; aws-sdk-go-v2/s3 with DO endpoint) | 6 | public ACL, versioning, lifecycle, CORS wildcard, default encryption, access logging |
| **Spaces access keys** | 2 | age, scope |
| **Container Registry** | 3 | private visibility, garbage collection enabled, quota |
| **App Platform** (PaaS) | 5 | env vars marked secret, custom-domain TLS, source repo visibility, alerts, deployment history |
| **Functions** (serverless) | 3 | namespace region, public trigger surface, env-var secrets |
| **CDN endpoints** | 2 | custom cert, TLS version |
| **Block volumes** | 2 | orphan, snapshot recency |
| **Snapshots** (droplet + volume) | 2 | age, public visibility |
| **Reserved + floating IPs** | 2 | orphan IPv4, orphan IPv6 |
| **Account-level SSH keys** | 2 | age, deprecated algorithm |
| **Custom images** | 2 | public visibility, age |
| **Monitoring + uptime checks** | 2 | basic alerts present, uptime checks on public droplets |
| **Projects + tagging** | 2 | default project not used for prod, untagged resources |

Plus existing v0.5 checks: 5. **Total shipped: 74.**

**Plumbing**

- Collector restructure (phase 1): per-service files in
  `internal/collectors/digitalocean/`, per-service errors emit
  `digitalocean.collect_error` placeholders rather than aborting
  the entire scan. Same pattern AWS / GCP use today.
- `cloudcommon.Stamp` applied to every DO resource:
  `AccountID = team-uuid`, `Region = region-slug`. Brings DO
  parity with the AWS / GCP attribution.
- godo SDK client reused (no new dep). Spaces is the one outlier:
  no godo bucket API — uses `aws-sdk-go-v2/s3` (already in dep
  tree at v0.7) with a custom endpoint resolver pointing at
  `<region>.digitaloceanspaces.com`. Auth via `SPACES_KEY` /
  `SPACES_SECRET` env-var pair, mirroring the `DO_API_TOKEN`
  pattern.
- godo pagination already in place from v0.1; reused everywhere.

**Framework mappings**

The CIS Controls v8 + SOC 2 TSC + ISO 27001:2022 Annex A catalogs
already absorb 74 DO checks without expansion. Each check maps to
all three frameworks. No new framework yaml needed.

**Definition of done**

- 74 DO checks, every check framework-mapped, every check
  fixture-backed (graph-test pattern from v0.7/v0.8).
- `cloudcommon.Stamp` on every DO resource; account_id + region
  populated in the evidence pack `control-mapping.csv`.
- Smoke run against a real DO test account with droplets, a LB,
  a managed DB, a Spaces bucket, an App Platform app, and a
  registry, all in a non-default project under a non-default VPC.
- README provider table updated to "DigitalOcean | v0.9 ✅ | 75".
- Companion blog post pitched to the DO community team —
  "the OSS DO posture scanner the ecosystem was missing."

---

### v0.10 — Hetzner Cloud ✅ shipped

**Goal:** the indie-cloud completion. Hetzner is the cheapest
serious-cloud option for the audience; pairing DO + Hetzner gives a
real choice within the same indie-SaaS demographic.

**Shipped at v0.10: 15 Hetzner checks**

| Surface | Checks |
|---|---|
| Servers | 5 (no-backups, rescue-enabled, old-image, not-running, locked) |
| Firewalls | 3 (ssh-from-any, any-port-from-any, orphan) |
| Networks | 2 (orphan, non-RFC1918 IP range) |
| Load Balancers | 2 (no-https-listener, http-not-redirected) |
| Volumes | 2 (orphan, unformatted-orphan) |
| Floating IPs | 1 (orphan) |

**Plumbing**

- New collector at `internal/collectors/hetzner/` using
  `github.com/hetznercloud/hcloud-go/v2` v2.40.0 (+2 MB binary).
- Hetzner has no multi-project surface in the cloud API; one
  token = one project. The collector emits a singleton
  `hetzner.project` anchor with a token-fingerprint AccountID so
  the evidence pack's `control-mapping.csv` stays consistent
  without leaking the full token.
- Per-service-error placeholders (`hetzner.collect_error`) match
  the AWS/GCP/DO pattern; one failing service doesn't lose the
  others.

**Definition of done (delivered)**

- ✅ 15 Hetzner checks, all framework-mapped (SOC 2 + ISO 27001 + CIS v8).
- ✅ Doctor probe verified; smoke-tested in CI.
- ✅ README "Providers" table flipped Hetzner from planned to ✅.

---

### v0.11 ✅ — Kubernetes + EKS / GKE / DOKS-deep (shipped 2026-05-14)

**Goal:** Kubernetes posture across the four clouds we ship — generic
K8s (works on any cluster) plus EKS/GKE/DOKS enrichment so each
cluster's cloud-side configuration is in scope.

**Scope expansion:** the original ~35-check target was expanded to
**139 checks** during implementation — production-grade depth
comparable to kubescape + Trivy K8s combined. No new ADR; the
expansion matches the inline-in-ROADMAP precedent of v0.7-v0.10.

**Shipped (139 checks across 11 phases):**

| Phase | Theme | Checks |
|---|---|---:|
| 0 | Foundations — kubeconfig fanout + cluster anchor + collect_error pattern | 0 |
| 1 | Pod Security (privileged, host-ns, capabilities, run-as-root, RO-rootfs, seccomp, resource limits, image-tag pin, automount-sa-token, hostPath, hostPort, liveness probe) | 18 |
| 2 | Controllers + Jobs (Deployment min-replicas / RollingUpdate / PDB / anti-affinity, StatefulSet PDB, DaemonSet control-plane, Job backoffLimit, CronJob concurrency / history / startingDeadline) | 10 |
| 3 | RBAC + ServiceAccounts (wildcard verbs/resources/apiGroups, full-wildcard, secrets read/write, pods/exec + pods/portforward, impersonate/escalate/bind, create pods, CSR approve, tokenrequest, cluster-admin bindings, anonymous bind, stale role-ref, empty subjects, User subject, default SA automount/used/orphan, image-pull-secrets) | 23 |
| 4 | Network + Ingress + NetworkPolicies (LB source-ranges, no-TLS, externalIPs, NodePort, public-no-NP, Ingress TLS / default-backend / class / dangerous annotations, default-deny ingress + egress, namespace coverage, allow-all ingress/egress, from-all-namespaces, empty selector) | 16 |
| 5 | Secrets + Storage (Secret-via-env, orphan, too-large, immutable, ConfigMap secret-shaped keys, ConfigMap too-large, StorageClass default-multiple / encryption / reclaim, PV reclaim / encryption / orphan, PVC not-bound / orphan / RWX) | 15 |
| 6 | Namespaces + Cluster + Admission (default-workload, ResourceQuota / LimitRange missing, PSA label, stuck terminating, policy-engine present, ValidatingWebhook failurePolicy, MutatingWebhook side-effects, webhook namespace-selector, RQ pod-limit / compute-limit / object-counts, LimitRange container-defaults) | 13 |
| 7 | Nodes (Ready, Disk/Memory/PID pressure, unschedulable, container runtime, OS image age, zone / region labels, control-plane taint) | 10 |
| 8 | EKS enrichment (public endpoint open, private endpoint, secrets KMS, control-plane logging, IRSA OIDC, auth mode, status, version, NG amiType / SSH / version-skew / launch-template) | 12 |
| 9 | GKE enrichment (private cluster, master authorized networks, Workload Identity, Binary Authorization, network policy, shielded nodes, release channel, legacy ABAC, logging + monitoring, NP auto-upgrade / auto-repair / COS / default-SA) | 13 |
| 10 | DOKS enrichment (HA control plane, auto-upgrade, surge-upgrade, maintenance window, VPC attached, registry integration, cluster running, NP autoscale / min-nodes) | 9 |

**Plumbing delivered:**

- New collector at `internal/collectors/k8s/` using `k8s.io/client-go`
  v0.32.1. Kubeconfig-driven discovery — explicit path or KUBECONFIG
  env or `~/.kube/config`. Per-context fanout; `k8s.cluster` anchor
  per context with cloudcommon AccountID = context name, Region =
  parsed API server host. Per-service `k8s.collect_error` placeholders
  on partial failures, matching the v0.7-v0.10 pattern in
  [[reference-collector-patterns]].
- Cloud enrichment via the existing AWS / GCP / DO collectors —
  `aws.eks.*`, `gcp.gke.*`, `digitalocean.doks.*` resources land
  alongside their cloud's other resources. DOKS specifically was held
  back from v0.9 to land here.
- `internal/cli/scan.go` `buildKubernetesCollector` + `doctor` probe.
- `internal/config/config.go` — KubernetesConfig with `kubeconfig`,
  `contexts`, `namespaces`, `exclude_namespaces`.

**Dependencies added (sized in BINARY.md):**

- `k8s.io/client-go v0.32.1` (+ `k8s.io/api`, `k8s.io/apimachinery`)
- `github.com/aws/aws-sdk-go-v2/service/eks v1.83.0`
- `cloud.google.com/go/container v1.51.0`
- godo already shipped DOKS support; no new DO dep.

**Final catalog:** 159 (v0.10) → **298 (v0.11)** = +139 K8s checks.

**Definition of done:**

- ✅ 139 K8s checks total (vs ~35 target); every check framework-
  mapped (SOC 2 + ISO 27001 + CIS Controls v8). CIS Kubernetes
  Benchmark v1.x mappings land at v0.12 (framework expansion).
- ✅ Per-service-file pattern preserved; collector + check files
  named by area (workloads, controllers, rbac, network, storage,
  cluster, nodes, eks, gke, doks).
- ✅ buildXCollector slice pattern reused — kubernetes is one more
  entry in the scan.go buildCollectors slice.
- Pending: end-to-end demos against real EKS / GKE / DOKS / kind
  clusters land in the launch broadcast workflow.

---

### v0.12 ✅ — Framework expansion + tailoring + evidence-pack depth (shipped 2026-05-15)

**Goal:** seven shipping frameworks (up from three) plus auditor-
honest tailoring plus deeper evidence-pack rendering. The original
ROADMAP target was four new frameworks; the implementation expanded
the existing three to their full catalogs as well, and the evidence
pack now surfaces every framework's family/tag metadata in the
summary HTML and control-mapping CSV.

**Shipped (10 phases):**

| Phase | Theme | Output |
|---|---|---|
| 0 | Schema scaffolding | Framework.Category/Source/Tactics; Control.Family/Tags/References; frameworks.TailoringRule + Tailoring; Config.Tailoring |
| 1 | SOC 2 TSC full | 60 controls (CC1-CC9 + A1 + C1 + PI1 + P1-P8) |
| 2 | ISO 27001:2022 Annex A full | 93 controls across 4 themes |
| 3 | CIS Controls v8 full + IG taxonomy | 153 safeguards × IG1/IG2/IG3 |
| 4 | NIST SP 800-53 r5 cloud subset | 131 controls × 14 families |
| 5 | HIPAA Security Rule | 50 implementation specs (required/addressable) |
| 6 | PCI DSS v4.0 cloud subset | 61 sub-requirements × 12 themes |
| 7 | MITRE ATT&CK Enterprise | 12 tactics + 50 techniques (first `category=threat_model`) |
| 8 + 9 | Evidence-pack enrichment + tailoring wiring | tailoring.json; control-mapping.csv +5 columns (framework_name, control_family, control_tags, tailored, tailoring_justification); summary.html re-templated with tailoring section + threat-model split + per-row family/tag/tailored chips |
| 10 | Wrap (this section) | ROADMAP / README / CONFIGURATION / examples / memory sweep |

**Aggregate:** 548 controls across 7 frameworks. No SDK pulls, no
binary size impact (~+30 KB of embedded YAML).

**Tailoring deliverable:**

```yaml
# compliancekit.yaml
tailoring:
  - framework: pci-dss-v4
    control: "10.6.1"
    justification: |
      Out of scope — no PAN data. All payments tokenized via Stripe.
```

  `compliancekit evidence --config compliancekit.yaml --out pack/`
loads + validates rules, writes `tailoring.json` to the pack root,
adds `tailored` + `tailoring_justification` columns to the
control-mapping CSV, and surfaces the operator's full record in
the auditor's summary HTML.

**Definition of done — met:**

- ✅ 4 new framework YAMLs land with sourced + attributed catalogs.
- ✅ Existing 3 frameworks expanded to full catalogs.
- ✅ Loader handles 7 frameworks at 548 controls; all existing check
  mappings continue to resolve (no breakage).
- ✅ ATT&CK renders as a kill-chain "Technique" view via
  Framework.IsThreatModel() routing in the evidence pack.
- ✅ Tailoring round-trips end-to-end: config → validation →
  evidence pack JSON + CSV column + summary chip + justification.
- ✅ `docs/checks.md` regenerated; per-control framework tables now
  show every applicable framework with family + tags.

---

### v0.13 ✅ — IaC / OCSF / OSCAL ingest + emit (shipped 2026-05-15)

**Goal:** compose with the rest of the security stack instead of
competing with it. v0.12 left compliancekit with breadth (7
frameworks × 548 controls); v0.13 lets every external scanner's
findings land in the same evidence pack with framework attribution
applied uniformly. The composition story: native scan + Trivy +
Checkov + AWS Security Hub all merge into one findings.json, one
evidence pack, one OSCAL Assessment Results document — no SaaS
shuttle layer, no per-tool integration glue.

**Shipped (10 phases + audit):**

| Phase | Theme | Output |
|---|---|---|
| 0 | Ingest scaffolding | `internal/ingest/` package, `Ingester` interface, concurrent-safe registry, `compliancekit ingest` CLI, `core.Finding.Source` provenance field, `config.Ingest[]` block |
| 1 | SARIF 2.1.0 | Adapter + 4 embedded mapping tables (Trivy / Checkov / KICS / Terrascan); 62 starter rule mappings; tool auto-detection; CVSS-to-severity |
| 2 | OCSF 1.x | Adapter + 3 embedded mapping tables (AWS Security Hub / GCP SCC / Defender for Cloud); 39 starter rule mappings; auto-detect array/JSONL/single-object shape; ARN-to-graph projection |
| 3 | OCSF emit polish + round-trip | Reporter enriched with `finding_info`, `compliance.standards/requirements`, `cloud.account`, `unmapped.compliancekit_source`; ingest → emit → ingest is lossless on CheckID / Severity / Status / Resource / Source / Fingerprint |
| 4 | OSCAL Catalog ingest | Hand-rolled JSON + YAML + XML parser; group hierarchy collapses to Control.Family; runtime framework registration via new `frameworks.Register` API; embedded + runtime frameworks coexist via merged-map `All()` |
| 5 | OSCAL Assessment Results emit | `assessment-results.oscal.json` in the evidence pack; deterministic v5-shaped UUIDs; one finding per (control, finding) pair; tailoring carries through as findings with `compliancekit-tailored="true"` props |
| 6 | OSCAL Profile emit | `profile.oscal.json` alongside AR; one Import per assessed-or-tailored framework with `include-all` + per-framework `exclude-controls` reflecting operator scope-outs |
| 7 | Mapping CLI | `compliancekit mapping list / show / validate / diff`; cross-registry validation (framework + control existence); unified MappingProvider registry across SARIF + OCSF subpackages |
| 8 | Provenance + config-driven ingest | `control-mapping.csv` gains `finding_source` + `finding_tool` columns; `scan --config=...` runs every `ingest:` entry after the native pipeline and merges findings + phantom resources into the live graph |
| 9 | Integration tests | End-to-end coverage of `runIngestSources` — multi-format merge, unknown-format errors, file-not-found errors, empty-config no-op |
| 10 | Wrap (this section) | ROADMAP / README / ADR-003 (Resolved) / ADR-018 (composition principle) / memory updates |

**Aggregate:** 3 ingest formats, 2 OSCAL emit shapes, 1 OCSF emit
upgrade, **106 starter rule mappings** spanning 7 external tools,
**1 new CLI surface** (`mapping`). No new external dependencies —
the OSCAL parser is hand-rolled, every adapter ships with embedded
mapping tables, every SARIF / OCSF / OSCAL document type uses the
standard library `encoding/{json,xml}` + `go.yaml.in/yaml/v3`
already in the module.

**Composition recipe:**

```yaml
# compliancekit.yaml
project: acme-saas
providers:
  digitalocean: { enabled: true, token_env: DO_API_TOKEN }
  kubernetes:   { enabled: true }

ingest:
  - format: sarif
    file: ./out/trivy.sarif
    tool: trivy
  - format: ocsf
    file: ./out/security-hub.json
    tool: aws-security-hub
  - format: oscal-catalog
    file: ./catalogs/acme-baseline.oscal.json
```

`compliancekit scan --config=compliancekit.yaml --evidence true`
runs the native DigitalOcean + Kubernetes scan, then merges in
Trivy's container-image findings and AWS Security Hub's compliance
findings, then registers the operator's custom OSCAL Catalog as a
runtime framework — and the evidence pack produced contains an
OSCAL Assessment Results document, an OSCAL Profile, the tailored
control-mapping.csv with provenance columns, and per-control
folders that mix native + ingested findings under the same framework
attribution.

**Definition of done — met:**

- ✅ All three ingest formats (`sarif`, `ocsf`, `oscal-catalog`)
  round-trip vendor fixtures.
- ✅ OSCAL Assessment Results emit is byte-stable across re-runs
  (UUID determinism via SHA256-of-content).
- ✅ OCSF emit → ingest → re-emit is lossless on every load-bearing
  Finding field (including Source provenance).
- ✅ README + CONFIGURATION + memory all sync'd in the wrap commit.
- ✅ ADR-003 (OCSF) closed as Resolved.
- ✅ ADR-018 (vulnerability composition principle) authored.

---

### v0.14 ✅ — Vuln / secret / SCA ingest (shipped 2026-05-15)

**Goal:** every CVE tied to a real resource in the graph. v0.14 layers
on top of v0.13's generic SARIF/OCSF ingest paths with four
purpose-built native-JSON adapters, typed Vulnerability + Secret
metadata blocks on core.Finding, and an image-SHA correlation pass
that maps a CVE-on-an-image onto every running K8s Deployment / DO
App Platform service / ECS task that references the same SHA.

**Shipped (11 phases):**

| Phase | Theme | Output |
|---|---|---|
| 0 | Schema scaffolding | `core.Finding.Vulnerability` + `Secret` typed blocks; default CVE/GHSA → vuln-mgmt framework mapping (SOC 2 CC7.1 / NIST SI-2 / ISO A.8.8 / PCI 6.3 / CIS 7.1) retroactively lights up the v0.13 SARIF path for advisory-shaped rules |
| 1 | Trivy native JSON | `--format=trivy-json` — per-package CVE / PURL / fixed-version / CVSS vector / image SHA. NVD-preferred CVSS scoring; auto-redacted secret detector output |
| 2 | Grype ingest | `--format=grype-json` — sibling tool, distinct schema, same Vulnerability shape |
| 3 | Checkov native JSON | `--format=checkov-json` — richer than SARIF (per-resource graph projection, file_line_range, guideline URL) |
| 4 | gitleaks ingest | `--format=gitleaks-json` — Secret block with auto-redacted Fingerprint, commit+author metadata for revocation routing |
| 5 | Image-SHA graph join | `internal/ingest/correlate.go` — when a Trivy image scan reports CVE on `container-image://<sha>` and a K8s/DO/ECS resource in the live graph references that SHA, clone the finding onto the running instance with a "running-on" tag. Bidirectional. |
| 6 | `vulnerabilities.csv` | New evidence-pack artifact — one row per (CVE, resource, framework) with cve_id / cvss / package_purl / fixed_version / source_tool columns. Directly importable into vuln-mgmt tools |
| 7 | Reporter updates | Markdown emits per-finding CVE subbullets + Secret lines; SARIF result.properties gains cve_id + GitHub-recognized security-severity; OCSF emit routes Vulnerability + Secret through `unmapped.compliancekit_{vulnerability,secret}` |
| 8 | ADR-010 secret-redaction | `ingest.RedactSecret` is the single canonical helper; per-adapter copies aliased to it. ADR-010 codifies the "raw secret value never enters the data plane" policy with the algorithm + threshold rationale + rejected alternatives |
| 9 | Integration tests | End-to-end pipeline test — Trivy fixture + K8s deployment in graph → correlated finding lands on the deployment with all metadata preserved + Trivy+Grype dual-source additivity test |
| 10 | Wrap (this section) | ROADMAP / README / examples / memory sweep |

**Aggregate:** 4 new ingest formats (`trivy-json`, `grype-json`,
`checkov-json`, `gitleaks-json`), 2 typed metadata blocks on
`core.Finding`, 1 new evidence-pack artifact, 1 new graph-correlation
pass, 1 new ADR (ADR-010 secret redaction). Zero new external
dependencies — every parser hand-rolled against `encoding/json`.

**Composition recipe:**

```yaml
# compliancekit.yaml
providers:
  kubernetes: { enabled: true }

ingest:
  - format: trivy-json
    file: ./out/trivy-image.json
    tool: trivy
  - format: grype-json
    file: ./out/grype-image.json
    tool: grype
  - format: gitleaks-json
    file: ./out/gitleaks.json
    tool: gitleaks
```

`compliancekit scan --config=... --evidence true` runs the native
K8s scan, ingests Trivy + Grype + gitleaks output, runs the image-
SHA join (Trivy's CVE on image X cross-references every Pod /
Deployment in the K8s graph referencing X), and writes an evidence
pack containing `vulnerabilities.csv` plus the existing
`control-mapping.csv` + per-control folders mixing native + ingested
findings.

**Definition of done — met:**

- ✅ One ingest fixture per tool (Trivy / Grype / Checkov / gitleaks).
- ✅ A CVE found by Trivy on a container image used by a K8s
  Deployment appears in `findings.json` linked to both the image
  AND the Deployment (tested in `internal/cli/vuln_pipeline_test.go`).
- ✅ Vulnerability blocks expose CVE-ID + CVSS + PURL + fixed-version
  + image identifier in every reporter format.
- ✅ Secret blocks carry redacted-only fingerprints (ADR-010); test
  fixtures verify "AKIAIOSFODNN7EXAMPLE" never substring-matches output.
- ✅ Evidence pack ships `vulnerabilities.csv` whenever CVE findings
  exist (skip when zero).
- ✅ ADR-010 codifies the redaction policy with algorithm rationale.

---

### v0.15 ✅ — Remediation generators (shipped 2026-05-15)

**Scope expanded from the original ROADMAP:** ten output formats
(not four), per-format strategy packages (not per-check methods),
RiskClass-gated bulk apply, OSCAL POA&M emit, and Jira + Linear
ticket integration for manual items. Architectural shape codified
in ADR-011.

**What shipped (13 phases, 35 files, ~10k LOC)**

- **Strategy registry + 10 Formats.** `internal/remediate` defines
  the `Strategy` interface, `Snippet` shape, and `Format` /
  `RiskClass` enums. Each format gets a subpackage that registers
  strategies in `init()`:
    - `terraform` (35 strategies — AWS, GCP, DigitalOcean, Hetzner)
    - `kubectl` (30+ — pod security context, NetworkPolicy, RBAC,
      PSA, PDB, Ingress, Service)
    - `awscli`, `gcloud`, `azcli`, `doctl`, `hcloud` — one-liner
      cloud-CLI commands paired with the IaC strategies
    - `helm` — values.yaml overlays for Helm-deployed K8s workloads
    - `ansible` — playbook tasks for Linux/CIS findings
    - `bash` — POSIX-sh fallbacks + the WILDCARD ("*") strategy that
      catches every CheckID with no specific renderer
- **140 strategies covering 127 CheckIDs.** Each declares:
  - RiskClass (safe / review / manual)
  - Idempotent flag
  - VerifyCmd (run after apply to confirm)
  - RollbackCmd (where the inverse is a single command)
  - Notes (operator-facing caveats)
  - Refs (authoritative doc URLs)
- **`compliancekit remediate` subcommand.** Reads findings JSON
  (envelope or bare-array), runs the registry, emits:
    - `remediation.md` — runbook grouped by risk class with TOC +
      catalog-resolved titles + per-format code fences + inline
      Verify / Rollback
    - `remediate.sh` — single bash script bundling RiskSafe snippets
      (cloud-CLI + bash flavors only — IaC formats need their own
      apply step)
    - `remediate-<format>/` — one directory per Format with raw
      snippet files per resource
    - `poam.oscal.json` — OSCAL v1.1.2 POA&M; one item per manual
      or unmatched finding with deterministic UUIDs (via the same
      SHA-256-prefix algorithm as the AR + Profile emitters)
- **Jira + Linear ticketing (optional).** Env-driven (JIRA_HOST /
  JIRA_EMAIL / JIRA_TOKEN / JIRA_PROJECT, LINEAR_API_KEY /
  LINEAR_TEAM_ID). Missing creds → that provider is skipped silently.
  Per-provider failure doesn't block the others.

**Architectural decisions (ADR-011)**

- Per-format Go strategy packages, hand-written, generate-only.
- Risk classified at strategy authorship time so v2.x's `--apply-fix`
  cannot accidentally promote a manual fix.
- Findings without a strategy never silently drop — they flow to
  the POA&M emitter via the wildcard fallback strategy.

**Definition of done — what was actually shipped**

- ✅ Terraform, kubectl, awscli, gcloud, azcli, doctl, hcloud, helm,
  ansible, bash generators — 10 formats, not 4.
- ✅ `compliancekit remediate --in=findings.json --out=./remediation`
  emits the runbook + bulk script + per-format directories + POA&M.
- ✅ Determinism: re-rendering the same findings produces byte-
  identical artifacts (no timestamps in snippet bodies; sort orders
  stable on (Risk, CheckID, Resource.ID, Format)).
- ✅ Wildcard fallback strategy in `internal/remediate/bash` ensures
  every finding produces at least one Snippet — auditor-visible.
- ✅ OSCAL POA&M emit completes the evidence-pack story (alongside
  AR + Profile from v0.13).
- ✅ Jira + Linear integration; both ship with httptest-backed
  contract tests.

---

### v0.16 ✅ — Rego policy DSL (shipped 2026-05-17)

**Scope expanded from the original ROADMAP:** ten Format names is
the cloud-CLI plumbing; for Rego the expansion was three-fold —
custom built-ins (originally "wait for community demand"), the
`policy test/validate/fmt` CLI surface for a local authoring
workflow, and **15** side-by-side reimplementations (3× the
original "5" floor). Architectural shape codified in
[ADR-012](DECISIONS.md#adr-012--rego-is-embedded-via-opas-go-library-not-shelled-out).
[ADR-002](DECISIONS.md#adr-002--policy-dsl-is-rego-landing-at-v016)
is now Resolved.

**What shipped (7 phases, 7 commits, ~3.5k LOC)**

- **`internal/policy/policy.go` + loader.** Rego evaluator that wraps
  `rego.New(...).Eval` into the existing `core.CheckFunc` signature.
  Modules parse + compile at load time (syntax errors surface at
  startup, not at first scan). Per-rule `metadata := {...}` constant
  lifts onto a typed `core.Check` with required-field guarding.
- **OPA embedded** via `github.com/open-policy-agent/opa/v1/rego`
  v1.16.2. ~15MB binary cost accepted because (a) Rego is
  pure-functional with no I/O — sandboxing is free; (b) byte-
  identical Findings without serialization round-trips; (c) one
  distribution story instead of "install OPA separately."
- **4 custom built-ins** under the `compliancekit.` prefix:
  `has_tag(resource, name)`, `attr_str(resource, key)`,
  `attr_bool(resource, key)`, `cvss_band(score)` — eliminate the
  boilerplate every policy would otherwise repeat. Stable surface
  per ADR-012; adding a fifth is a SemVer 2.0 change.
- **Registry mirror.** Rego modules register into the same
  `core.DefaultRegistry` as Go checks via `policy.RegisterModule`;
  mutual-exclusion enforced at registration (duplicate IDs are
  programmer errors caught at startup, not silent overwrites).
- **`compliancekit checks list/show` annotation.** New SOURCE column
  ("go" or "rego"); `checks show <id>` prints the Rego source file
  path + body inline so operators audit without digging.
- **`compliancekit policy test/validate/fmt` subcommand.** Closes
  the authoring loop: `policy test fixture.json policy.rego` for
  instant pass/fail; `policy validate dir/` as a CI gate;
  `policy fmt` (with `--check`) wraps OPA's canonical formatter.
- **15 side-by-side Rego reimplementations** under
  `examples/policies/<provider>/`, three per provider lane
  (AWS / GCP / DigitalOcean / Kubernetes / Linux). Every shipped
  policy exercises at least one custom built-in.
- **Semantic validation test** (Phase 6) — table-driven, one row
  per shipped policy, asserts the produced findings flag exactly
  the expected resources against a fixture matching the policy's
  declared shape.

**Definition of done — what was actually shipped**

- ✅ `internal/policy/` package with evaluator + loader + builtins
  + registry mirror.
- ✅ 15 reimplementations (vs the issue's 5-check floor).
- ✅ `compliancekit policy test/validate/fmt` for local authoring.
- ✅ `checks list/show` surface Rego-backed checks with source.
- ✅ All 15 policies pass `policy validate` + the per-policy
  semantic test.
- ✅ ADR-012 codifies embedded OPA. ADR-002 flipped to Resolved.

**Deferred to a future milestone**

- Embedding policies under `internal/policies/` and auto-loading
  at startup. Phase 5 ships demonstration twins in `examples/` so
  the contribution path is clear without polluting the user's
  scan output with duplicate findings.
- Byte-identical Go ↔ Rego parity. The Go checks read collector-
  native shapes (container slices, nested config blobs); the Rego
  reimplementations declare a simpler resource schema. True parity
  needs a canonical JSON-stable resource shape both sides target —
  a collector-side refactor for a later milestone.

---

### v0.17 ✅ — Notifications (shipped 2026-05-17)

**Scope expanded from the original ROADMAP:** 8 sinks instead of 7
(PagerDuty Events v2 added because operational escalation is the
"production-grade" story the indie-SaaS audience needs). Mirrors
the v0.13 ingest + v0.15 remediate architecture: one Notifier
interface, one Default registry, per-sink env-driven configuration,
no telemetry / no phone-home.

**What shipped (11 phases, 11 commits, ~3k LOC)**

- **`internal/notify/notify.go` — foundation.** Notifier interface
  (Name / Configured / Threshold / Send), Notification struct
  (Finding + pre-rendered Title + CommonMark Body + deep-link URL +
  Tags + dedup Fingerprint), Result accumulator, Registry +
  Default + Register pattern.
- **`BuildNotifications + Dispatch`.** Builder filters non-actionable
  findings + renders the canonical title/body once; dispatcher fans
  out to every Configured sink whose Threshold permits the
  notification. Per-sink errors wrap with the sink name and DON'T
  block siblings — one failing channel never silences the rest.
- **8 sinks**, each in `internal/notify/<sink>.go` with an httptest
  contract test:
  - **slack** — Block Kit payload, both incoming-webhook + bot-token
    paths supported in one type; parses both Slack response shapes
    (webhook plain-text "ok", API `{"ok": true/false}`).
  - **discord** — embed payload with severity-mapped 24-bit color.
  - **teams** — MessageCard payload (legacy connector); bullets
    converted to "•" glyph for mobile/desktop consistency.
  - **webhook** — generic JSON POST with `compliancekit.
    notification.v1` schema + optional `X-CompliancekitSignature:
    sha256=<hex(HMAC-SHA256(secret, body))>` header.
  - **email** — SMTP with auto-selected TLS mode (port 465 → tls,
    587 → starttls, 25 → none); PLAIN auth optional; multipart
    MIME with text/plain only (HTML deferred).
  - **github-pr** — single summary comment per dispatch (not per
    finding — avoids PR-comment spam) as a Markdown table.
  - **jira** — thin adapter over the v0.15 `tickets.Jira` client;
    `JIRA_NOTIFY_*` env falls back to `JIRA_*`.
  - **pagerduty** — Events v2 enqueue with `dedup_key` =
    notification.Fingerprint so re-firing findings update existing
    incidents. Defaults to critical-only threshold (don't wake on-
    call on noise).
- **`compliancekit notify` CLI.** `--in` findings JSON, `--baseline`
  for only-new-findings mode (subtracts by Finding.Fingerprint),
  `--severity` global floor (stacks with per-sink threshold;
  strictest wins), `--project` + `--url-prefix` for body rendering,
  `--dry-run` for the per-sink plan, `--list` for the
  Configured/Threshold table.
- **`compliancekit doctor` integration.** New "notify:" line prints
  `N sink(s) registered, M configured` plus a per-sink Configured +
  Threshold breakdown. Runs unconditionally (no provider config
  required) so operators can verify sink credentials independently
  of scan config.

**Definition of done — what was actually shipped**

- ✅ 8 sinks, each ≤300 LOC including tests.
- ✅ Per-sink severity threshold + global `--severity` floor.
- ✅ Only-new-findings mode reads `compliancekit baseline` output.
- ✅ Rate-limit + dedup via Finding.Fingerprint (PagerDuty `dedup_key`
  + only-new subtraction; finer rate-limit deferred until a sink
  reports the need).
- ✅ Doctor reports per-sink configuration status.
- ✅ No telemetry / no phone-home — every target is operator-
  configured via env vars.

**Deferred to a future milestone**

- Mattermost / Rocket.Chat — Slack-webhook-compatible, add when
  someone asks.
- Adaptive Card Teams payload — wait for the October 2026 MessageCard
  retirement deadline.
- HTML email — overkill until someone reports plain-text rendering
  is a problem.
- Per-sink rate limit — only PagerDuty has a real rate concern today,
  and its `dedup_key` covers that. Add when a sink complains.

---

### v0.18 ✅ — Waivers + in-code skip annotations (shipped 2026-05-17)

**Scope expanded from the original ROADMAP:** glob matching on both
CheckID + ResourceID (originally exact-only), 6 file types for
in-code annotations (.tf .tfvars .yaml .yml .sh .bash .py .go +
Dockerfile/*.dockerfile), CLI surface with 4 subcommands (list /
show / validate / check), evidence-pack `waivers.json` artifact
plus 4 additive control-mapping.csv columns, full doctor
integration. Architectural shape codified in
[ADR-013](DECISIONS.md#adr-013--waivers-vs-baselines-distinct-concerns-distinct-mechanisms).

**What shipped (8 phases, 8 commits, ~3k LOC)**

- **`internal/waivers/` foundation** — Waiver struct + WaiverList +
  validating loader. Per ADR-013: every waiver REQUIRES expiry (no
  permanent waivers — they degrade into hidden ignore-lists);
  reason floor of 16 non-whitespace chars (catches "OK" / "see
  ticket" without rejecting real prose); duplicate (CheckID,
  ResourceID) rejected because it hides which approver authorized.
- **`core.WaiverRef`** typed metadata block on `core.Finding`
  (joins Vulnerability + Secret from v0.14). Auditor-visible by
  design — a waived finding flows through every reporter as
  StatusSkip with WaiverRef populated, NOT hidden.
- **Loader + Matcher**: glob-based matching on both CheckID and
  ResourceID via `filepath.Match` (operators waiving a whole check
  family use `aws-s3-*`; a whole resource family uses
  `digitalocean.droplet.*`). First-match-wins; deterministic
  ordering across runs.
- **Apply + expired-waiver synthesis**: mutates findings in place
  (StatusSkip + WaiverRef + `waived` tag), AND synthesizes one
  info-level `compliancekit-waiver-expired` finding per lapsed
  waiver so the auditor sees the lapse as an explicit finding.
- **In-code annotation scanner** for 6 file types:
  `# compliancekit:waive <check-id> <resource-id> [reason="..."]
  [approver=...] [expires=YYYY-MM-DD]` (and `//` form for Go +
  HCL). Languages: Terraform/HCL, YAML, Bash, Python, Dockerfile,
  Go. Default expiry = now + 90 days (forces re-review); default
  approver = `@annotation`; default reason references the file +
  line so the auditor knows where to look. Skips .git / vendor /
  node_modules / .terraform / dist / build / .cache.
- **Scan engine integration**: `applyWaivers` hook in `runScan`
  loads + applies waivers right after ingest merge. Synthesized
  expired findings appended to result.Findings so reporters see
  them. Summary line "waivers: N active, M expired, K expiring
  within 30d — muted P finding(s)".
- **Evidence pack additions** (additive — v0.4+ CSV consumers
  reading by column name keep working):
  - 4 new columns on `control-mapping.csv`: `waiver_active`,
    `waiver_reason`, `waiver_approver`, `waiver_expires`.
  - New `waivers.json` artifact at the pack root with one entry
    per muted finding (cross-references the full `core.Finding`
    so an auditor can pivot from waiver → original finding).
- **`compliancekit waivers` CLI** — 4 subcommands:
  - `list` — tabulate active + expired with expiring-within-30d
    flagged; counts header.
  - `show <check-id> <resource-id>` — full detail for one waiver
    including multi-line reason + source path.
  - `validate` — schema + duplicate check; non-zero exit on errors
    (CI gate).
  - `check --in=findings.json` — non-zero exit if any actionable
    finding lacks a matching waiver (CI gate for "every fail-on=
    high finding must have a documented acceptance").
- **Doctor integration**: prints "waivers: <path> — N active, M
  expired, K expiring within 30d" line, with ⚠ icon when any
  waivers are expired or expiring-soon.

**Definition of done — what shipped**

- ✅ `waivers.yaml` schema with required {check_id, resource_id,
  reason ≥16 chars, approver, expires}.
- ✅ In-code annotations across 6 file types + auto-defaulting for
  reason/approver/expires when not specified.
- ✅ Expired waivers emit `compliancekit-waiver-expired` info
  findings so lapses are explicit, not silent.
- ✅ Evidence pack visibility: waivers.json + 4 new
  control-mapping.csv columns. Per ADR-013, waived findings stay
  visible to auditors with full justification + approver context.
- ✅ `compliancekit waivers list/show/validate/check` CLI surface.
- ✅ `compliancekit doctor` reports waivers health.
- ✅ ADR-013 codifies the waivers-vs-baselines boundary.

**Deferred to a future milestone**

- Broader scopes (per-framework / per-tag waivers) — narrow
  (CheckID, ResourceID) is the v0.18 unit. Add when narrow proves
  insufficient.
- Multi-approver chains for high-severity waivers — out of v0.18
  scope; the audit-log-via-evidence-pack covers basic accountability.
- Waiver application via Web UI / workflow integration — that's
  v1.4 GRC layer + v1.5 auditor portal.

---

### v0.19 ✅ — DigitalOcean deepening (production grade) (shipped 2026-05-17)

**Shipped:** the most comprehensive open-source DigitalOcean security
scanner that exists. DO is the indie-SaaS audience the project was
built around; everything else is depth in service of that. v0.9
shipped 74 checks across 20 services; v0.19 took it to **144 checks
across 21 services** and turned every check into a fully-remediated,
fully-tested artifact (**432 bespoke remediation strategies** total —
Terraform + doctl + bash, one of each per check).

**Phases (each commit was its own gate-passing phase):**

- Phase 0 — DO parity ratchet test infrastructure (gates new
  checks; flips red on any DO check landing without all three
  formats).
- Phase 1 — Account/team governance deepening (+10 checks).
- Phase 2 — Spaces lifecycle/replication/object-lock (+10 checks +
  collector extension for lifecycle/logging/policy attributes).
- Phase 3 — DNS DMARC/SPF/DKIM/CAA/DNSSEC depth (+10 checks +
  collector extension for spf_records / dkim_selectors / ns_records).
- Phase 4 — DOKS add-on coverage (+10 checks under provider="kubernetes").
- Phase 5 — App Platform observability + deploy hygiene (+10 checks +
  collector extension for service / database summaries).
- Phase 6 — Functions runtime + env hygiene (+10 checks).
- Phase 7 — Network depth (VPC peering, firewall dedup, reserved-IP,
  LB SSL) (+10 checks).
- Phase 8 — Billing + project orphan/untagged sweep (+10 checks).
- Phase 9 — Remediation parity backfill — drove ratchet from 68/68/74
  to 0/0/0 by adding bespoke TF + doctl + bash for every v0.9-vintage
  check.
- Phase 10 — Test coverage push (checks: 93.4% → 96.1%; collectors:
  pure-helper layer fully covered).
- Phase 11 — Docs polish + `examples/quickstart-digitalocean-deep.yaml`.

**Deliverables (all shipped)**

- **74 → 144 checks** across every DO surface. New depth:
  - Account / team: MFA enforcement audit, named-team usage,
    API-key rotation tracking, billing-alert presence, owner+
    delegation review, audit-log retention.
  - Spaces: lifecycle policies (expiration / noncurrent versions),
    transfer acceleration, replication, server-access-logging,
    object-lock + retention modes.
  - DNS: complete DMARC dimensions (p=, sp=, pct=, rua/ruf), SPF
    record correctness, DKIM selector presence, CAA per-CA pinning,
    DNSSEC enablement.
  - DOKS: full add-on coverage (DO Container Registry integration
    depth, metrics-server, cert-manager presence, cluster-autoscaler
    config), control-plane logging destinations, node-pool
    upgrade-strategy validation, image-pull-secret governance.
  - App Platform: alert policy completeness, observability stack
    (logs forward / metrics forward), build-time secret scanning,
    deploy-on-push branch protection, custom-domain cert hygiene.
  - Functions: namespace tenancy, runtime EOL audit, env-var
    secrets-vs-plain audit, log-policy presence.
  - Network: VPC peering pair correctness, firewall rule
    deduplication, reserved-IP orphan audit, load-balancer SSL
    cipher / proto floor enforcement.
  - Billing + project: orphaned resources across all 20 services,
    untagged resources (cost-attribution hygiene), per-project
    resource caps.
- **Every check ships with three remediations:** Terraform block,
  doctl one-liner, bash fallback. Per ADR-011 + ADR-006, generation
  only. RiskClass classified at strategy authorship.
- **Per-check unit tests** with collector-shaped fixtures
  (`internal/checks/digitalocean/<service>_test.go`); integration
  tests in `internal/cli/scan_do_integration_test.go` against
  multi-service synthetic graphs.
- **Optional live-DO smoke** gated on `DO_API_TOKEN` env var:
  scan a known account, assert ≥N findings, no collector errors.
- **Final phase: docs polish + CLI help cleanup** for every new
  surface — `--help` strings precise, `compliancekit checks show`
  shows full prose for every shipped DO check, new
  `examples/quickstart-digitalocean-deep.yaml` walking through the
  comprehensive scan path.

**Definition of done — what actually shipped**

- ✅ 144 DO checks registered (planned 150+; the eight unshipped
  scope ideas were either folded into the existing surface or
  consciously deferred — see "Deferred" below).
- ✅ Every DO check carries Terraform + doctl + bash remediation
  strategies. CI gate: `TestParity_DigitalOcean` in
  `internal/remediate/parity_do_test.go` strict-equality enforces
  0 missing strategies across all three formats.
- ✅ Test coverage: `internal/checks/digitalocean/` reaches 96.1%.
  `internal/collectors/digitalocean/` pure-helper layer fully
  covered; the live-API integration paths sit at fixture-driven
  ~52% — pushing those to ≥85% requires significantly more fixture
  JSON and was deferred.
- ✅ `examples/quickstart-digitalocean-deep.yaml` walks through the
  end-to-end scan with every flag operators need.

**Deferred from the original v0.19 scope**

- ≥150 check count (shipped 144). Remaining 6 ideas either consolidated
  into existing manual-verify families or held back for v0.21 (DOKS
  + K8s deepening will own further DOKS-side checks).
- Per-file 85% coverage on the collectors package — collectors live-
  API path coverage requires fixture-server JSON for every godo
  endpoint we touch; a meaningful additional investment to ship
  separately.
- Live-DO smoke test in CI gated on `DO_API_TOKEN` — deferred to
  v0.21 alongside the DOKS smoke-test work.

---

### v0.20 ✅ — Linux hardening (production grade) (shipped 2026-05-17)

v0.5 shipped 15 Linux checks as a foundation; v0.20 took it to
**119 checks** spanning the CIS Linux Server Benchmark v8 surface
(kernel sysctl + filesystem + services + sshd + auditd + login.defs
+ PAM/sudo + packages/MAC + firewall depth), with **bespoke bash +
Ansible remediation for every check** (238 strategies total) and a
**parity ratchet gate** (`TestParity_Linux`) at strict 0/0 to keep
future Linux work compliant.

**Shipped**

- ✅ **119 Linux checks** (15 → 119, +693%) organized into 9
  data-driven spec frameworks: `sysctlSpec`, `mountSeparateSpec` +
  `mountOptionSpec`, `serviceMustRunSpec` + `serviceMustNotRunSpec`
  + `serviceMustAbsentSpec`, `sshdSpec`, `auditRuleSpec`,
  `manualVerifySpec`. Each spec is a struct literal; init() loops
  the slice + registers via per-shape closure — adding a new check
  is one struct literal.
- ✅ **Per-distro detection** via `internal/collectors/linux/
  osrelease.go` + 5 canonical fixtures (ubuntu 22.04, debian 12,
  rhel 9, alpine 3.19, amzn 2023). Family predicates
  (`IsDebianFamily`, `IsRHELFamily`, `IsAlpine`, `IsAmazonLinux`)
  drive per-distro gating — SELinux check fires only on RHEL,
  AppArmor only on Debian, nftables-on-RHEL only on RHEL.
- ✅ **Bespoke bash + Ansible for every check.** Parity ratchet
  `TestParity_Linux` (internal/remediate/linux_parity_test.go) at
  strict equality 0/0 — a single Linux check shipped without both
  formats fails pre-commit. 238 strategies total (119 × 2).
- ✅ **Bash strategies** use idempotent sed/grep/printf one-liners.
  sshd_config edits run `sshd -t` validate BEFORE reload so a
  broken edit cannot lock operators out. Firewall remediations are
  distro-aware (ufw / firewalld / nftables switch on /etc/os-release).
- ✅ **Ansible strategies** use lineinfile + ansible.posix.sysctl +
  ansible.builtin.systemd modules with `become: true`. sshd edits
  carry `validate: 'sshd -t -f %s'` for the same lockout protection.
- ✅ **CIS Linux Server Benchmark v8 framework catalog**
  (`internal/frameworks/cis-linux-server.yaml`) — 90+ sections
  organized into 6 families (initial-setup, services, network,
  logging-auditing, access-auth, system-maintenance) with Level 1
  / Level 2 tags. Wired into every v0.20 spec constructor — checks
  emit `cis-linux-server` alongside `cis-v8` in their framework map.
- ✅ **Test coverage** — `internal/checks/linux/` at **90.6%** (≥85%
  DoD target). Per-spec table-driven tests cover every cmp branch
  + skip-on-missing-attr + unreachable-host paths.
- ✅ **`examples/quickstart-linux-hardening.yaml`** walks through
  the end-to-end scan with inventory + bastion + waivers + Slack
  notification wiring.

**Deferred from the original v0.20 scope**

- 100+ count target was hit (shipped 119). STIG + ANSSI catalogs
  not shipped as separate framework yamls — the CIS Linux Server
  Benchmark control map is the primary v0.20 deliverable; STIG is
  largely a section-renaming exercise on the same underlying data
  and was held back to keep the release focused.
- Per-file 85% coverage on `internal/collectors/linux/` (shipped
  53.7%). The gap is dominated by the SSH transport layer
  (`gatherX` functions, `Dial`, `RunCommand` — all 0%) which would
  need a fake SSH server or interface refactor. Pure parsers
  (`ParseOSRelease`, `ParseSysctlOutput`, `ParseLoginDefs`,
  `parseSSHDConfig`, etc.) are at 90%+.
- Integration tests against per-distro rootfs JSON fixtures —
  the spec-driven check tests with constructed `core.Resource`
  literals cover the check logic exhaustively; rootfs fixtures
  would mostly re-exercise the collectors' SSH path which is the
  same gap as above.

**Definition of done — checklist**

- ✅ 100+ Linux checks registered (shipped 119).
- ✅ Every Linux check ships with bash + Ansible remediation
  (parity ratchet at strict 0/0).
- ✅ Per-distro detection + gating wired through every distro-
  specific check (SELinux → RHEL, AppArmor → Debian, nftables-on-
  RHEL → RHEL).
- ✅ Test coverage ≥85% on `internal/checks/linux/` (90.6%).
- ✅ README + ROADMAP updated with new check counts + framework
  catalog reference; `examples/quickstart-linux-hardening.yaml`
  exists.

---

### v0.20 — Linux hardening (original plan, kept for reference)

**Goal:** match the depth of OpenSCAP / Lynis on Linux server
hardening, with the same evidence-pack + remediation experience
operators get on cloud surfaces. v0.5 shipped 15 Linux checks as
a foundation; v0.20 takes that to full CIS Benchmark + STIG
coverage.

**Deliverables**

- **15 → 100+ checks** mapped to:
  - **CIS Benchmark Linux Server** (Level 1 + Level 2, with
    IG1/IG2/IG3 implementation-group taxonomy threaded through).
  - **STIG** Linux subset (the subset relevant to cloud servers).
  - **ANSSI** Linux Server hardening guide subset (French gov
    equivalent — broader audience signal).
- Coverage categories:
  - **Kernel sysctl** — full network + memory + filesystem +
    randomization knobs (~30 checks).
  - **Filesystem** — separate-partition checks (/tmp, /var,
    /var/log, /var/log/audit, /home), mount options (nodev,
    nosuid, noexec), permissions on system files.
  - **Services** — systemd unit hardening (PrivateTmp, NoNewPriv,
    ProtectSystem, CapabilityBoundingSet), enabled-services audit.
  - **Auth** — PAM stack (faillock, pwquality, lastlog), sudo
    (NOPASSWD audit, secure_path), sshd full coverage
    (HostKey rotation, MAC/Cipher floor, KexAlgorithms, AllowUsers).
  - **Audit** — auditd rules (CIS 4.1.x subset: identity, mac,
    perm, sudoers, mounts, time, network, login), journald
    persistent storage + forward-to-syslog, rsyslog config.
  - **Network** — iptables / nftables / ufw / firewalld depth,
    ICMP behavior, IPv6 hardening.
  - **Packages** — apt/dnf signing keys present, unused packages
    removed, prelink absent (kernel/CIS deprecates), aide presence
    + cron job.
  - **MAC** — SELinux enforcing / AppArmor enabled per-service
    profile audit.
- **Per-distro support:** Debian/Ubuntu (apt-based), RHEL/CentOS/
  Rocky/Alma (dnf), Alpine (apk), Amazon Linux 2 / 2023. Distro
  detected at collection time; per-distro test fixtures.
- **Every check with bash + Ansible remediation.** Idempotent
  Ansible tasks; bash one-liners safe to paste over SSH.
- **Integration tests** against rootfs fixtures (committed JSON
  representations of `/etc/sysctl.d`, `/etc/ssh/sshd_config`,
  `/etc/pam.d/*`, `/etc/audit/audit.rules` etc.) per distro.
- **Final phase: docs polish** — per-check remediation prose
  cleaned, `--help` polished, new `examples/quickstart-linux-
  hardening.yaml` walking through CIS Server Level 1.

**Definition of done**

- 100+ Linux checks registered with full per-distro coverage.
- Per-distro CIS Benchmark mapping coverage (which IG covers what).
- Every Linux check ships with bash + Ansible remediation.
- Test coverage ≥85% per file in `internal/checks/linux/` and
  `internal/collectors/linux/`.
- README + CHECKS.md updated with the new authoring conventions.

---

### v0.21 ✅ — Kubernetes + DOKS deepening (production grade) (shipped 2026-05-17)

v0.11 shipped 149 K8s checks (already strong); v0.21 took it to
**241 checks** across the pod-security / reliability / supply-chain
/ RBAC / network / admission / control-plane / managed-K8s surfaces,
with **bespoke kubectl strategy for every K8s check** (parity gate
at strict 0 — wildcard fallback no longer counted) and the NSA/CISA
Kubernetes Hardening Guide v1.2 framework yaml as the 9th catalog.

**Shipped**

- ✅ **241 K8s checks** (149 → 241, +61%) organized across 8 new
  spec-driven categories landing in distinct files to keep the
  v0.22 600-LoC invariant on each:
  - `pods_extra.go` (12) — pod-security deepening (shareProcessNamespace,
    dnsPolicy, hostUsers, fsGroup, runAsGroup, AppArmor, seccomp-not-
    unconfined, RuntimeClass, volume subPath, default SA,
    supplementalGroups)
  - `reliability.go` (12) — readiness/startup probes, ephemeral-
    storage limits, topology spread, image digest pinning, termination
    grace, preStop hook, owner-ref, init-container parity, host ports
  - `rbac_extra.go` (10) — escalation patterns (update clusterroles,
    patch nodes, pods/status, CSR create, mutating/validating webhook
    write, namespaces write, deletecollection pods, pods/eviction,
    pods/ephemeralcontainers) — each one a verbResourceCheck against
    a specific (apiGroup, resource, verbs) tuple
  - `network_extra.go` (10) — Ingress RCE annotations (CVE-2021-25742
    family), 0-CIDR source ranges, cloud-metadata egress, Lua plugins,
    publishNotReadyAddresses, broad selectors, no-rules ingresses,
    mixed TLS/plaintext ports
  - `supplychain.go` (10) — mutable tags, empty tags, trusted-registry
    allowlist, cosign signature verification, in-toto attestations,
    image-pull secret discipline, pull-policy consistency, base-OS
    EOL, registry TLS-only, vuln-scan freshness
  - `admission_extra.go` (8) — webhook timeout bounded, mutating
    sideEffects None, namespace exclusion, Gatekeeper / Kyverno
    installed, policy enforce mode, OLM installed, Subscription manual
    approval
  - `control_plane.go` (15) — CIS K8s Benchmark §1 manual-verify
    across apiserver / etcd / controller-manager / scheduler / kubelet
    flags, structured per the v0.20 manualVerifySpec pattern
  - `managed_extra.go` (15) — DOKS / EKS / GKE deepening manual-verify
    (private endpoint, KMS encryption, IRSA, IMDSv2, Workload Identity,
    Binary Authorization, etc.), 5 per vendor
- ✅ **Collector extensions** — `workloads.go` now emits 10 new
  pod-level attrs (share_process_namespace, dns_policy,
  priority_class_name, runtime_class_name, host_users, apparmor_profile,
  volume_subpath_mounts, termination_grace_period,
  topology_spread_constraints, init_container_count) + 4 new
  container-level attrs (has_readiness_probe, has_startup_probe,
  has_ephemeral_storage_limit, image_digest_pinned) + 3 new pod-level
  securityContext fields (run_as_group, fs_group, supplemental_groups).
- ✅ **Bespoke kubectl per check.** Parity ratchet
  `TestParity_Kubernetes` (internal/remediate/k8s_parity_test.go)
  at strict equality 0 — a single K8s check shipped without bespoke
  kubectl coverage fails pre-commit. Helm + Terraform deferred to
  per-check additions only where they're the natural fit (per
  pre-phase scope decision: most K8s findings — RBAC, secrets,
  pod-security on running pods — aren't naturally Helm-shaped).
- ✅ **kubectl strategy distribution** — 8 hand-authored extra
  files (pod_security_extra.go, reliability.go, rbac_extra.go,
  network_extra.go, supplychain.go, admission_extra.go,
  control_plane.go, managed_extra.go) + 11 backfill registrations
  distributed across new per-category files (doks.go, eks.go, gke.go,
  nodes.go, storage.go, secrets.go) + appends to existing extras
  files, all sharing a backfill_helper.go renderer that pulls the
  Check's own Remediation text. Drove the kubectl ratchet from
  baseline 102 → 0.
- ✅ **NSA / CISA Kubernetes Hardening Guide v1.2 framework yaml**
  (`internal/frameworks/nsa-cisa-k8s.yaml`) — 30+ chapter-section
  controls across 5 chapters (pod-security, network, auth, logging,
  upgrading). 9th shipping framework after the v0.20 cis-linux-server
  addition.
- ✅ **Test coverage** — `internal/checks/k8s/` at 52.4% (was 45.0%,
  +7.4pp). Per-source-file test split (`pods_extra_test.go`,
  `reliability_test.go`, `supplychain_test.go`, `control_plane_test.go`,
  `managed_extra_test.go`, shared `testhelpers_test.go`). Bug fixed
  in registryFromImage during test development.
- ✅ **examples/quickstart-kubernetes-deep.yaml** + **examples/
  quickstart-doks-deep.yaml** — end-to-end production scan configs
  exercising the full K8s + DOKS surface with Slack + waivers + 
  baseline diff wiring.

**Deferred from the original v0.21 scope**

- Helm + Terraform parity across every K8s check. Per-check decision:
  Helm template generation isn't naturally K8s-shaped (RBAC, secrets,
  pod-security on running pods), and 3-format strict parity at 250+
  checks would mean ~750 awkward template strategies. Helm/Terraform
  added per-check where they fit naturally; future deepening can lift
  ratchet ceilings as warranted.
- 250+ check count — shipped 241 (61% growth from 149; close to
  target). Remaining 9 ideas folded into v0.21.x manual-verify
  expansions or held for v0.22.
- **Integration tests against kind clusters** — same shape as v0.20
  Linux's fake-SSH-server gap. Closing collectors/k8s coverage to
  ≥85% needs a fake K8s API server (kube-apiserver-test-fixtures /
  envtest); scoped to v0.22 alongside the Linux SSH transport faking.
- **Per-check `nsa-cisa-k8s` Frameworks: mapping** — the framework
  yaml ships first; per-check mapping fills in as v0.22 refactor
  lifts the spec constructors to the spec-driven shape that makes
  multi-framework wiring cheaper.
- **Live-DOKS smoke test in CI** — gated on `DO_API_TOKEN` +
  `DOKS_CLUSTER_ID`; deferred to v0.22 alongside the action repo
  multi-provider work.

**Definition of done — checklist**

- ⚠️ 250+ K8s checks — shipped 241 (96%; close to target, defer to v0.21.x).
- ✅ NSA / CISA Hardening Guide framework catalog
  (`internal/frameworks/nsa-cisa-k8s.yaml`) shipped.
- ✅ Every K8s check carries bespoke kubectl (parity gate at strict 0).
- ⚠️ Test coverage ≥85% on `internal/checks/k8s/` — shipped 52.4%;
  collectors at 35.7%. Deferred to v0.22 alongside the fake K8s
  API server infrastructure work.
- ✅ README + ROADMAP updated; `examples/quickstart-kubernetes-deep.yaml`
  + `examples/quickstart-doks-deep.yaml` exist.

---

### v0.21 — Kubernetes + DOKS deepening (original plan, kept for reference)

**Goal:** the most comprehensive open-source Kubernetes security
scanner. v0.11 shipped 139 K8s checks (already strong); v0.21
takes that to full CIS Kubernetes Benchmark + NSA/CISA Kubernetes
Hardening Guide + PCI Kubernetes controls + supply-chain
verification (cosign / sigstore attestation).

**Deliverables**

- **139 → 250+ checks** covering:
  - **CIS Kubernetes Benchmark v1.x** — full Master + Worker +
    Policies sections.
  - **NSA / CISA Kubernetes Hardening Guide** — full coverage,
    mapped as a separate framework (`nsa-cisa-k8s`).
  - **PCI DSS Kubernetes** — the K8s-specific subset of PCI v4.0.
  - **Supply chain** — image signature verification (cosign),
    in-toto attestation presence, image source registry
    allowlist enforcement, base image age + EOL audit.
  - **Policy engine** — Gatekeeper or Kyverno presence, ConstraintTemplate /
    ClusterPolicy coverage audit, admission-webhook timing.
  - **Operator patterns** — Operator-Lifecycle-Manager presence,
    operator RBAC scope, CR completion tracking.
  - **RBAC graph analysis** — who can escalate to cluster-admin
    via what chain (currently flagged but not graphed).
  - **DOKS depth** — full add-on coverage, registry-integration
    completeness, node-image freshness, control-plane logging
    destinations.
  - **EKS + GKE depth** — match the DOKS depth.
- **Helm chart hardening** — checks for charts deployed via Helm:
  pinned versions, RBAC scope, secrets handling, hook usage,
  test-pod inclusion.
- **Every check with kubectl + Helm + Terraform remediation.**
  Per ADR-011 + ADR-006, generation only.
- **Integration tests against kind clusters** (committed kubeconfig
  + deployed-resource fixtures), plus optional **DOKS smoke**
  gated on `DO_API_TOKEN` + `DOKS_CLUSTER_ID`.
- **Final phase: docs polish** — per-check remediation prose,
  `--help` polished, new `examples/quickstart-kubernetes-deep.yaml`
  + `examples/quickstart-doks-deep.yaml` walking through full CIS
  + NSA coverage.

**Definition of done**

- 250+ K8s checks registered.
- NSA / CISA Hardening Guide ships as a new framework catalog
  (`internal/frameworks/nsa-cisa-k8s.yaml`).
- Every K8s check carries kubectl + Helm + Terraform remediation
  (CI gate).
- Test coverage ≥85% per file in `internal/checks/k8s/` and
  `internal/collectors/k8s/`.
- README + CHECKS.md updated.

---

### v0.22 ✅ — Internal refactor + toolchain refresh + action-repo polish (shipped 2026-05-17)

Structure debt paid down before v1.0 (#18). v0.22 shipped 8 of the
20 originally-drafted phases — the load-bearing refactor + toolchain
+ action work — and deferred spec-pattern lifts + fake-API-server
coverage + lint v2 + deep cookbook to v0.22.x point releases.

**Shipped**

- ✅ **600-LoC check-file CI gate** — new `internal/repocheck/`
  package with `TestCheckFilesUnderSizeLimit` (`file_size_test.go`).
  Walks `internal/checks/` + asserts every non-test `.go` file ≤
  600 LoC. Allowlist-based ratchet (same shape as parity tests) —
  closed empty after Phase 4 so future regressions fail pre-commit.
- ✅ **9 oversize files split** (was 6713 LoC over the ceiling
  across 9 files; now 0):
  - `k8s/rbac.go` (1045 → 486) → `rbac_roles.go` + `rbac_bindings.go`
  - `k8s/pods.go` (904 → 543) → `pods_resources.go` + `pods_volumes.go`
  - `k8s/network.go` (879 → 420) → `network_ingress.go` + `network_policies.go`
  - `k8s/cluster.go` (701 → 550) → `cluster_quotas.go`
  - `k8s/reliability.go` (671 → 466) → `init_containers.go`
  - `k8s/eks.go` (649 → 450) → `eks_nodegroups.go`
  - `aws/iam.go` (635 → 468) → `iam_policies.go`
  - `k8s/pods_extra.go` (627 → 581) → `pods_groups.go`
  - `digitalocean/tail.go` (602 → 506) → `projects_hygiene.go`

  11 new per-category sibling files; each file owns its own init()
  registering its own checks (no behavior change, no LoC growth).
- ✅ **Toolchain refresh**:
  - `runs-on: ubuntu-latest` → `runs-on: ubuntu-24.04` explicit pin
    in all three workflows (ci.yaml, release.yaml, govulncheck.yaml).
    `ubuntu-latest` already resolves to 24.04 since GHA Jan 2025;
    this prevents a future bump silently breaking builds.
  - `digitalocean/godo` + `spf13/cobra` + `spf13/viper` +
    `open-policy-agent/opa` + `k8s.io/{api,apimachinery,client-go}`
    (v0.34.1 → v0.36.0) bumped via `go get -u` + `go mod tidy`.
    Conservative — AWS SDK + GCP SDK majors held back for separate
    focused commits in v0.22.x.
- ✅ **compliancekit-action polish**:
  - **Multi-provider input** — old code silently dropped everything
    past the first comma-separated provider. New loop runs
    `compliancekit scan <provider>` per entry into per-provider
    sub-out-dirs + jq-merges findings.json arrays at the top-level
    out-dir. Worst-case exit code propagates so the action still
    fails on any provider's severity-floor breach.
  - **`upload-evidence-pack: true` input** — opt-in workflow-artifact
    upload via `actions/upload-artifact@v4`. New companion inputs
    `evidence-artifact-name` + `evidence-artifact-retention-days`.

**Deferred to v0.22.x point releases**

- **Spec-pattern lifts** — AWS IAM + GCP IAM + K8s pod-security
  onto the v0.20 spec shape. Value is real (~520 LoC cut targeted)
  but each lift is its own focused commit; running them under time
  pressure in the same milestone as the file splits would have
  conflated two diffs.
- **Fake K8s API server + fake SSH server** — closes the v0.20
  Linux collectors (53.7%) + v0.21 K8s collectors (35.7%) coverage
  gaps. Both need envtest / golang.org/x/crypto/ssh server-mode
  test-fixtures, scoped together as a focused commit.
- **golangci-lint v1.64.8 → v2.x migration** — config schema
  changed; needs careful per-linter reconciliation, brew formula
  pin update, lefthook config refresh.
- **Deep cookbook + docs pass** — 9 recipe playbooks
  (SOC2/ISO/PCI/HIPAA workflows) + 7 CI/CD integrations + ~50
  reference Rego policies + new CONTRIBUTING.md + ADR index +
  CHANGELOG.md (git-cliff) + SECURITY.md refresh. Scoped as its
  own milestone — the writing surface is large enough that
  combining it with the refactor would have produced a thin pass
  on both.
- **`internal/testutil/` extraction** — consolidate the
  `core.Resource` builder helpers. Cosmetic; ships with the
  spec-lift work.

**Definition of done — checklist**

- ✅ No check-registration file >600 LoC (CI-enforced).
- ⚠️ Spec-pattern lifts (AWS IAM + GCP IAM + K8s pod-security)
  — deferred to v0.22.x.
- ⚠️ golangci-lint v2 in CI + pre-commit — deferred to v0.22.x.
- ⚠️ `internal/collectors/linux/` + `/k8s/` coverage ≥85% —
  deferred to v0.22.x (fake API server work).
- ✅ All three GHA workflows pin `ubuntu-24.04` explicitly.
- ✅ Direct-dep sweep complete on the top-leverage subset.
- ✅ compliancekit-action accepts multi-provider input + offers
  evidence-pack workflow-artifact upload.
- ✅ Total Linux + CI test wall-clock not regressed >10% vs v0.21.
- ⚠️ Docs deep pass + cookbook — deferred to a focused milestone.

---

### v0.22 — Internal refactor + toolchain refresh + cookbook (original plan, kept for reference)

**Goal:** pay down accumulated structure debt before the v1.0 API
freeze (#18). v0.6 → v0.21 added 482 checks across 6 providers + 7
ingest adapters + 10 remediation formats + 8 notify sinks + waivers
+ policy DSL. The package boundaries are sound (kubescape / Trivy /
Prowler all settled on the same flat per-provider layout) so v0.22
is **deliberately not a directory rearrangement**. The win is in
file-level navigability, adopting the v0.20 spec-driven pattern
where it pays off, and getting the toolchain current before we
freeze the API surface.

Scoped tight to keep the milestone reviewable + to avoid blocking
v1.0 on refactor scope creep. **No new user-facing checks.**

**Why this slot and not a continuous refactor**

Three of the six providers (DigitalOcean v0.19, Linux v0.20,
Kubernetes v0.21) each shipped 90+ new files in a single milestone.
Refactoring mid-deepening means re-refactoring after each one. v0.22
runs *after* v0.21 closes for the same reason v0.20 ran after v0.19:
the spec-driven pattern only crystallizes after enough surface
exists to recognize the shape worth lifting out.

**Deliverables**

- **File split — 6 oversize files.** Mechanical split along
  existing logical boundaries; no behavior change. CI gate: no
  check-registration file >600 LoC after this milestone.
  - `internal/checks/k8s/rbac.go` (1045 LoC) → `rbac_roles.go` +
    `rbac_bindings.go` + `rbac_serviceaccounts.go`
  - `internal/checks/k8s/pods.go` (904 LoC) → `pods_security.go` +
    `pods_resources.go` + `pods_network.go`
  - `internal/checks/k8s/network.go` (879 LoC) → `network_policies.go`
    + `network_ingress.go` + `network_services.go`
  - `internal/checks/k8s/cluster.go` (701 LoC) → `cluster_admission.go`
    + `cluster_apiserver.go`
  - `internal/checks/k8s/eks.go` (649 LoC) → split by EKS family
    (control-plane / nodegroup / addons)
  - `internal/checks/aws/iam.go` (635 LoC) → split by IAM resource
    type (users / policies / roles / mfa)
- **Spec-driven pattern adoption.** The v0.20 spec-shape (struct
  literal slice + init() loop + per-shape closure) drove the
  Linux check surface from 15 → 119 with minimal LoC growth. Lift
  it into the providers where 50%+ of checks share a shape:
  - **AWS IAM** — policy-attached-to-user, password-policy, MFA-
    enforced, access-key-rotation all fit one spec; cuts ~150 LoC.
  - **GCP IAM** — same shape; cuts ~120 LoC.
  - **K8s pod-security** — runAsNonRoot, allowPrivilegeEscalation,
    readOnlyRootFilesystem, hostNetwork, hostPID, hostIPC all fit
    one `psSpec`; cuts ~250 LoC.
- **Lint + toolchain refresh.**
  - **golangci-lint v1.64.8 → v2.x.** Migration is non-trivial —
    config schema changed (`linters:` block restructured),
    `gocyclo` thresholds re-tune, removed linters need
    substitutes. Reconcile [`.golangci.yaml`](.golangci.yaml) +
    update [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) +
    [`feedback-collab`] memory + Homebrew formula pin.
  - **Go 1.27** when GA (currently 1.26.3); bump `go.mod`,
    `.github/workflows/*.yaml` `GO_VERSION`, Dockerfile, and the
    GoReleaser build matrix.
  - **Ubuntu runner pin.** `runs-on: ubuntu-latest` is already
    24.04 since GHA bumped the alias in Jan 2025. Pin explicitly
    to `ubuntu-24.04` in all three workflows (`ci.yaml`,
    `release.yaml`, `govulncheck.yaml`) so a future
    `ubuntu-latest` bump to 26.04 doesn't silently break builds.
  - **Dependency sweep.** `go list -u -m all` per phase; bump
    AWS / GCP / godo / hcloud / k8s.io / OPA / cobra / viper to
    their latest minor versions; `go mod tidy`. Per-bump test
    + lint + integration smoke before staging.
- **Test infrastructure.**
  - **Fake SSH server** for `internal/collectors/linux/` — closes
    the v0.20 deferred coverage gap (53.7% → ≥85%). The
    `gatherX` / `Dial` / `RunCommand` 0% blocks all gate on this.
  - **Test helpers consolidation** — `internal/testutil/` for
    the `core.Resource` builder helpers that have drifted into
    per-package `*_test.go` files (`hostWithSSHD`, `hostWithMAC`,
    `hostWithAuditRules` in checks/linux; equivalents in checks/k8s,
    checks/digitalocean). One canonical builder, per-provider
    convenience constructors.
- **compliancekit-action repo polish.**
  - **Multi-provider input.** Today `providers: digitalocean,linux`
    silently runs only the first (`scan` accepts one positional).
    Loop the comma-separated list + aggregate findings; backwards-
    compat with single-provider input.
  - **Version pinning.** `version: latest` resolves at job start —
    fragile against new releases mid-CI. Default to a pinned
    `latest-stable` (the latest non-prerelease tag at action
    build time); `latest` becomes opt-in.
  - **Output upload polish.** Optional `upload-evidence-pack:
    true` action input that uploads `evidence/` as a workflow
    artifact using `actions/upload-artifact@v4`.
  - **Node 20 → Node 22.** GitHub deprecated Node 16 in 2024;
    bump for the upload-sarif sub-action versions that depend on
    it (`github/codeql-action@v3` is already there; ensure other
    composite sub-actions are on `@v4`).
  - **Action test matrix.** `tests/` folder with workflow runners
    exercising every action input combination on `ubuntu-24.04` +
    `ubuntu-22.04` (back-compat) + `macos-14` (mac runners exist).
- **Docs polish (deep pass — first since v0.12).** Every shipping
  doc gets a reread + rewrite where it's drifted. Not surface
  edits — real restructure where v0.6 → v0.21 changed the shape
  of the project.
  - **README.md** — top-of-fold pitch tightened against the 482-
    check / 8-framework reality. "What's in the box" rewritten
    (the v0.6 table doesn't reflect spec-driven checks, waivers,
    Rego, notify, ingest, remediate). New "How auditors actually
    use this" section sourced from the v0.18-v0.20 evidence-pack
    work.
  - **docs/ARCHITECTURE.md** — §6 (Code organization) refreshed
    for the spec-pattern + 600-LoC invariant. §13 (Air-gapped
    operation) re-validated against the v0.13-v0.16 embed
    additions (frameworks, policies, mappings). New §X
    (Spec-driven check authoring) walks the pattern end-to-end.
  - **docs/DEVELOPMENT.md** — golangci-lint v2 config shape,
    spec-pattern authoring loop (struct → init() → register →
    test), the new `internal/testutil` helper API, the
    `*_<GOOS>_test.go` build-tag gotcha codified.
  - **CONTRIBUTING.md** — new, top-level. End-to-end "add a new
    check" walkthrough using the v0.20 spec-pattern; for each
    of the four provider archetypes (cloud-API, K8s-API,
    SSH-host, file-system) show the minimal struct + test +
    spec + remediation snippet to land a single check.
  - **ADR index consolidation.** docs/decisions/README.md (new)
    indexes ADR-001 → ADR-013 with status (Accepted / Resolved /
    Superseded / Revisited-at-v1.0). Retrospective table — which
    decisions held under load, which decisions need a second look
    before the v1.0 freeze.
  - **SECURITY.md** refresh — 2-year backwards-compat commitment
    language drafted ahead of v1.0. CVE-disclosure email + GPG
    key + 90-day disclosure window per industry norm.
  - **CHANGELOG.md** — new, auto-generated from conventional
    commit history via [git-cliff](https://git-cliff.org/) so it
    stays in sync. v0.1 → v0.20 backfilled from the existing
    tags + this ROADMAP.
  - **docs/checks.md** — regenerated (counts unchanged; remediation
    text changes for the AWS/GCP/k8s checks lifted into specs).
- **Deep examples — the "compliancekit Cookbook".** The
  existing `examples/quickstart-*.yaml` files are config-shape
  references. The Cookbook is the *workflow* layer — what
  auditors / SREs / security teams actually do with compliancekit
  over a quarter, not just "here's a config that scans X".
  - **`examples/recipes/`** — markdown playbooks, one per workflow:
    - `soc2-audit-pack.md` — SOC 2 12-week evidence collection
      timeline; what to capture each week; how to wire to your
      auditor's portal.
    - `iso27001-readiness.md` — ISO 27001:2022 Annex A readiness
      pass; control-by-control evidence checklist with which
      compliancekit checks satisfy what.
    - `pci-quarterly-scan.md` — PCI DSS v4.0 quarterly scan +
      waiver + POA&M emit flow; QSA-ready evidence pack.
    - `hipaa-baa-attestation.md` — HIPAA Security Rule §164.308/
      310/312 evidence walk with BAA-required artifact mapping.
    - `multi-cloud-fleet.md` — AWS + GCP + DO + Hetzner in one
      CI workflow with consolidated reporting + per-cloud waiver
      partitioning.
    - `k8s-pod-security-rollout.md` — applying CIS K8s benchmark
      + Pod Security Admission enforcement in stages, with
      waiver-based progressive rollout.
    - `linux-cis-l1-to-l2.md` — progressive CIS Linux Server
      hardening from L1 baseline → L2 high-security, leaning on
      the v0.20 tagged-section catalog.
    - `ci-gate-tuning.md` — composing `fail-on` × `severity-floor`
      × `baseline-diff` × `only-new-findings` for your team's risk
      tolerance; common pitfalls.
    - `evidence-pack-shipping.md` — what auditors actually want:
      OSCAL vs HTML vs CSV vs SARIF, redaction policies, raw-
      finding access via `--include-raw`, sha256 manifest
      verification.
  - **`examples/integrations/`** — end-to-end working configs for
    the toolchains people actually run:
    - `github-actions/` — multiple workflows: scheduled audit,
      PR-gate, baseline-diff, evidence-pack-on-tag, multi-cloud
      matrix.
    - `gitlab-ci/`, `jenkins/`, `circleci/` — equivalent shapes
      for non-GitHub teams.
    - `argocd/` — running compliancekit as an ArgoCD sync-wave
      pre-step so K8s deployments gate on compliance.
    - `datadog/` — forwarding `findings.json` to DD via fluent-bit
      so security teams see findings in the same UI as their
      observability data.
    - `splunk/` — same, for Splunk shops.
  - **`docs/cookbook.md`** — single-page index of every recipe
    + every integration, with a "use-case → recipe" navigation
    table so an SRE landing cold can find the right playbook in
    <30 seconds.
  - **`examples/policies/` extension** — the v0.16 Rego examples
    cover 15 reimplementations across providers. Extend with a
    full reference policy library (~50 policies) showing the
    canonical Rego pattern for each spec shape lifted in this
    milestone.

**Phase shape (estimate, per-commit-gate maintained)**

| Phase | Scope |
|---|---|
| 0 | Repo audit + file-size CI gate (fails pre-commit if any check file >600 LoC) |
| 1 | Split k8s/rbac.go (1045 → 3 files) |
| 2 | Split k8s/pods.go (904 → 3 files) |
| 3 | Split k8s/network.go + cluster.go + eks.go + aws/iam.go |
| 4 | AWS IAM spec-pattern lift |
| 5 | GCP IAM spec-pattern lift |
| 6 | K8s pod-security spec-pattern lift |
| 7 | Fake SSH server + collectors/linux coverage 53.7% → ≥85% |
| 8 | internal/testutil helpers extraction |
| 9 | golangci-lint v1 → v2 config migration + reconcile |
| 10 | Go 1.27 bump (gated on Go 1.27 GA — fallback: defer to v0.23) |
| 11 | Dependency sweep (AWS SDK / GCP SDK / godo / k8s.io / OPA / cobra / viper) |
| 12 | Ubuntu 24.04 pin + workflow YAML refresh |
| 13 | compliancekit-action multi-provider + version-pin + Node 22 + test matrix |
| 14 | README rewrite + ARCHITECTURE deep refresh |
| 15 | DEVELOPMENT.md + new CONTRIBUTING.md + ADR index consolidation |
| 16 | SECURITY.md refresh + CHANGELOG.md backfill (git-cliff) |
| 17 | examples/recipes/ — 9 workflow playbooks |
| 18 | examples/integrations/ — 7 CI/CD + observability integrations |
| 19 | examples/policies/ extension — ~50 reference Rego policies + cookbook index |
| 20 | Final docs/checks.md regen + ROADMAP polish |

**Definition of done**

- No check-registration file >600 LoC (enforced by CI gate).
- AWS / GCP IAM + K8s pod-security on spec-driven shape; net LoC
  decrease ≥400 across those areas.
- golangci-lint v2.x in CI + pre-commit; v1.64.8 references purged
  from docs.
- `internal/collectors/linux/` coverage ≥85% (closes v0.20 defer).
- All three GHA workflows pin `ubuntu-24.04` explicitly.
- `go list -u -m all` shows no minor-version drift on the top-15
  most-used deps.
- compliancekit-action accepts comma-separated `providers:` input
  + offers `version: latest-stable`.
- Total Linux + CI test wall-clock not regressed >10% vs v0.21.
- **Docs deep pass shipped:** README + ARCHITECTURE + DEVELOPMENT
  rewritten where drifted; new CONTRIBUTING.md + ADR index +
  CHANGELOG.md backfilled; SECURITY.md refreshed for v1.0 compat
  language.
- **Cookbook shipped:** 9 recipe playbooks + 7 integration configs
  + ~50 reference Rego policies + single-page cookbook index at
  `docs/cookbook.md`.

**Out of scope at v0.22 (explicit deferrals)**

- **New checks or new framework catalogs.** Goes to v0.21
  (K8s deepening) or v1.1+ (post-API-freeze).
- **`pkg/compliancekit` extraction.** That's the v1.0 milestone
  (#18). v0.22 stays under `internal/`.
- **Multi-binary split** (`ck-collector`, `ck-emit`, etc.).
  No demand signal yet; revisit at v2.x if the plugin marketplace
  needs it.
- **Per-service subfolders under each provider.** Considered + ruled
  out — every comparable scanner (kubescape, Trivy, Prowler,
  steampipe) keeps flat per-provider packages because Go subpackage
  semantics impose more friction than the navigability win is worth.
- **macOS / Windows / BSD hardening.** Stays at v1.6.

---

### v1.0 — API stability — `pkg/compliancekit` frozen

**Goal:** anyone embedding compliancekit gets a real contract.

**Deliverables**

- The internal types that survive into `pkg/compliancekit`:
  `Finding`, `Resource`, `ResourceGraph`, `Check`, `Framework`,
  `Severity`, `Status`, `Reporter`, `Collector`, `Evaluator`.
  These are the v0.1 types that survived three iterations and are
  the right shape.
- Anything in `internal/` stays internal. The promotion list is
  explicit, audited, and committed to with a stability promise.
- **SemVer 2.0 from this point**: breaking changes to anything
  under `pkg/` require a major bump.
- Go module path freeze: `github.com/darpanzope/compliancekit`
  stays stable. A v2.0 (if it ever happens) lives under
  `/v2/` per Go module conventions.
- Two-year compatibility commitment in writing in SECURITY.md.
- Long-form release notes documenting the API surface and the
  embedding pattern.

A few specific scope decisions worth pinning down here so they don't drift:

- **Vulnerability scanning is composed, not native.** We ingest Trivy / Grype output; we don't reimplement a CVE database. The audience gets a unified view, the maintainer cost stays sane.
- **IaC scanning is composed, not native.** We ingest Checkov / Trivy IaC / KICS / Terrascan SARIF; light native Terraform-plan parsing only for DO resources where we can do it in <500 LoC.
- **Auto-remediation is permanently opt-in.** Default install is audit-only. `--apply-fix` always requires explicit re-affirmation per run.
- **`serve` is permanently optional.** CLI parity is a hard invariant — every feature ships to CLI first, then daemon.
- **No telemetry, no phone-home, ever.** This is a load-bearing promise to the audience.

---

## Success metrics

- **v0.5 launch week:** 500+ stars, on HN front page for ≥4 hours.
- **30 days:** 1,000 stars, 10 external contributors, 3 GitHub Actions in public repos using it.
- **90 days:** 2,500 stars, mentioned in one major newsletter (`tldr.sec`, `KubeWeekly`, `Last Week in AWS`).
- **180 days:** at least one SaaS startup public-cases their SOC 2 prep using compliancekit.

Vanity metrics aren't the point. The honest goal: by month 6, someone googling **"open source DigitalOcean compliance"** lands on this repo as the obvious answer.
