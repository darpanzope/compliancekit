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
| **v0.8** | **GCP** | GCP hardening with the same SDK seam pattern as AWS |
| **v0.9** | **DigitalOcean deepening** | 5 checks → 25; Spaces, LBs, VPCs, managed DBs, K8s clusters |
| **v0.10** | **Hetzner Cloud** | The indie-cloud completion |
| **v0.11** | Containers + K8s + EKS/GKE/DOKS-deep | From cluster to instance in one scan |
| **v0.12** | Framework expansion (NIST 800-53 r5, HIPAA, PCI-DSS, MITRE ATT&CK) | Map every finding to ATT&CK |
| **v0.13** | IaC / OCSF / OSCAL ingest + emit | Plays nicely with the rest of the security stack |
| **v0.14** | Vuln / secret / SCA ingest (Trivy, Grype, Checkov, gitleaks) | Every CVE tied to a real instance |
| **v0.15** | Remediation generators (Bash / Terraform / Ansible / aws / gcloud / doctl) | Copy-paste this Terraform to fix |
| **v0.16** | Rego policy DSL (via OPA) | Write a check in 10 lines of Rego |
| **v0.17** | Notifications (Slack / Discord / Teams / email / webhook / PR / Jira) | Slack alert on every new high finding |
| **v0.18** | Waivers + in-code skip annotations | Mute findings the right way |
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

### v0.8 — GCP (weekend 8)

**Goal:** GCP at the same depth as AWS at v0.7. The SDK pattern is
identical so the second cloud is much cheaper than the first.

**Scope: 25 GCP checks**

| Service | Checks |
|---|---|
| IAM | 6 (no broad primitive roles in prod, no user-managed SA keys >90d, no SA keys at all where Workload Identity Federation works, audit logging on critical services, MFA on org admins) |
| Compute Engine | 5 (default network usage, SSH from 0.0.0.0/0, OS Login enforced, shielded-VM on, no auto-attached SAs with broad scopes) |
| GCS | 4 (uniform bucket-level access, public-access prevention, default encryption with CMEK where required, logging) |
| Cloud SQL | 3 (no public IP, automated backups on, deletion protection) |
| Cloud Logging | 2 (org-level sink to a hold bucket, log retention ≥365d for audit logs) |
| KMS | 2 (key rotation, separation of key admin and user) |
| BigQuery | 3 (no `allAuthenticatedUsers` ACLs, CMEK for sensitive datasets, no public datasets) |

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

### v0.9 — DigitalOcean deepening (weekend 9)

**Goal:** turn the v0.1 minimum-viable DO coverage into a complete
DO posture scanner. The audience that put compliancekit on the map
deserves a depth pass.

**Today (v0.5):** 5 DO checks — droplets-no-firewall, ssh-from-any,
backups-disabled, no-tags, old-image. **Goal at v0.9: 25 DO checks.**

| Surface | New checks |
|---|---|
| **Spaces** (S3-compatible object storage) | 4 (public-listing, CDN tier, default encryption, lifecycle policy on critical buckets) |
| **VPCs** | 3 (no default-VPC usage in prod, sane CIDR planning, peering hygiene) |
| **Load Balancers** | 3 (HTTPS redirect, TLS ≥1.2, no anonymous health-check IPs in the allowlist) |
| **Managed Databases** | 4 (trusted-sources only, automated backups on, point-in-time recovery for prod, end-of-life check) |
| **DOKS** (cluster-level only; node-level lands at v0.11) | 3 (cluster version not EOL, surge-upgrade on, private endpoint where possible) |
| **Container Registry** | 2 (image-retention policy, no `latest` tag in production manifests) |
| **App Platform** | 1 (HTTPS-only, custom-domain TLS) |

Plus existing v0.5 checks: 5. Total: 25.

**Plumbing**

- All new resource types added to `internal/collectors/digitalocean/`
  with corresponding `core.Resource` types.
- The existing godo SDK client is reused; no new SDK dependency.
- **godo rate-limit handling**: explicit per-resource pagination so
  a 500-droplet account does not hammer the API. The existing
  collector did one big `ListDroplets`; v0.9 introduces page-stream
  iteration.

**Framework mappings**

The CIS controls and ISO/SOC 2 control set is already broad enough
to absorb 20 more DO checks. No new framework yamls needed.

**Definition of done**

- 25 DO checks, all framework-mapped, all fixture-backed.
- Page-stream pagination verified against a real DO test account
  carrying ≥250 droplets and ≥10 LBs.
- The DigitalOcean tutorial article (from the v0.5 launch
  conversation with the DO community team) lands as a companion
  post.

---

### v0.10 — Hetzner Cloud (weekend 10)

**Goal:** the indie-cloud completion. Hetzner is the cheapest
serious-cloud option for the audience; pairing DO + Hetzner gives a
real choice within the same indie-SaaS demographic.

**Scope: ~15 Hetzner checks**

| Surface | Checks |
|---|---|
| Servers | 5 (firewall attached, SSH key vs password, server-image freshness, backups via snapshot schedule, rescue-mode keys revoked) |
| Firewalls | 3 (overly-permissive ingress, SSH-from-any, default-deny baseline) |
| Networks | 2 (private network usage for in-prod services, sane subnet planning) |
| Load Balancers | 2 (HTTPS termination, TLS ≥1.2) |
| Volumes | 2 (encryption-at-rest verification where Hetzner supports, lifecycle hygiene) |
| Floating IPs | 1 (no orphaned floaters paying for nothing) |

**Plumbing**

- New collector at `internal/collectors/hetzner/` using
  `github.com/hetznercloud/hcloud-go`. Already noted in
  [BINARY.md](BINARY.md) sizing.
- Resource scope adds `project` (Hetzner organisation-equivalent).
- The cloud-common abstractions established at v0.7-v0.8 absorb the
  Hetzner-specific bits with minimal new surface.

**Definition of done**

- 15 Hetzner checks, framework-mapped, fixture-backed.
- End-to-end run against a Hetzner Cloud test project.
- README "Providers" table updated to first-party for Hetzner.

---

### v0.11 — Containers + K8s + EKS / GKE / DOKS-deep (weekend 11)

**Goal:** Kubernetes posture across the four clouds we now ship.
Lands after all the cloud collectors so EKS/GKE/DOKS-specific
checks can read directly from the cluster's owning cloud account.

**Scope split**

- **Generic Kubernetes** (works against any cluster, kind/k3s
  included): ~20 checks covering kube-apiserver flags, pod-security
  admission, network policies, RBAC, secrets-not-in-env, runAsNonRoot,
  resource quotas, audit logging.
- **EKS-specific** (~6): managed-NG vs. node-group hygiene, public
  endpoint, IRSA usage, control-plane logging, in-place upgrades
  hygiene, KMS encryption of secrets.
- **GKE-specific** (~5): Autopilot mode, Workload Identity, private
  cluster, binary authorization, shielded nodes.
- **DOKS-specific** (~4 — building on v0.9 cluster-level): per-node
  upgrade strategy, registry-pull from DO Container Registry vs
  ghcr.io, surge-upgrade real config, alerting policy.

**Plumbing**

- New collector at `internal/collectors/k8s/` using
  `k8s.io/client-go`. Kubeconfig-driven discovery; works against
  arbitrary contexts. Already noted in
  [BINARY.md](BINARY.md) sizing.
- New collector adapters at `internal/collectors/aws/eks/`,
  `gcp/gke/`, `digitalocean/doks/` that *enrich* a `k8s.Cluster`
  resource with cloud-side context. Same pattern as Resource
  references across the graph.
- **kubescape-style host scanning is out of scope** — for now we
  stay declarative API-driven.

**Definition of done**

- ~35 K8s checks total; framework-mapped (CIS K8s Benchmark v1.x as
  the CIS source).
- One end-to-end demo against a kind cluster (generic), one against
  a DOKS cluster, one against EKS, one against GKE.
- Memory ceiling holds at <500MB for a 200-pod cluster; if not, a
  TODO lands for v1.0's API freeze.

---

### v0.12 — Framework expansion (NIST 800-53 r5, HIPAA, PCI-DSS, MITRE ATT&CK)

**Goal:** every existing check maps to at least one control in each
of the new frameworks where the mapping is honest. Honest is the
operative word: an inventory check claims neither HIPAA nor PCI-DSS
unless it actually reaches one.

**Deliverables**

- `internal/frameworks/nist-800-53-r5.yaml` (subset relevant to
  cloud + Linux posture).
- `internal/frameworks/hipaa.yaml` (the technical safeguards
  subset: §164.312).
- `internal/frameworks/pci-dss-v4.yaml` (the network-segmentation
  / encryption / audit-logging subset).
- `internal/frameworks/mitre-attack.yaml` — special-cased: maps to
  **tactic/technique IDs**, not "controls." The reporter handles
  it as a distinct lens.
- `compliancekit checks list --framework=...` continues to filter.
- **Tailoring**: `compliancekit.yaml` gets a `frameworks.tailoring`
  block where the operator declares "skip these controls" with a
  required justification (lands in `tailoring.json` next to the
  evidence pack, included in `control-mapping.csv` as a column).
- Auto-regenerated `docs/checks.md` shows the expanded mappings.

**Definition of done**

- All four new framework YAMLs land with the corresponding control
  catalog sourced and attributed in the file header.
- 90% of v0.5 checks reach at least one control in at least three
  of the new frameworks (the rest are explicitly "inventory-only").
- `docs/checks.md` line count growth is documented (sanity check on
  catalog explosion).

---

### v0.13 — IaC / OCSF / OSCAL ingest + emit

**Goal:** compose with the rest of the security stack instead of
competing with it.

**Deliverables**

- **OCSF ingest**: `compliancekit ingest --format=ocsf` reads
  vendor outputs (AWS Security Hub, GCP Security Command Center,
  Defender) and surfaces them as findings in the same envelope.
- **OSCAL emit**: `compliancekit evidence --emit=oscal-assessment-results`
  produces an OSCAL Assessment Results v1.0.4 document alongside the
  pack. Useful for FedRAMP-adjacent customers.
- **OSCAL ingest**: `compliancekit ingest --format=oscal-catalog`
  reads an OSCAL Catalog so a customer's bespoke framework can be
  scanned without writing a new yaml.
- **SARIF ingest**: `compliancekit ingest --format=sarif` reads
  Trivy / Checkov / KICS / Terrascan output and converts them to
  compliancekit findings, mapped to frameworks via a configurable
  table.
- ADR-003 (OCSF) is finally complete: OCSF is no longer just an
  output, it is a wire format for cross-tool composition.

---

### v0.14 — Vuln / secret / SCA ingest

**Goal:** every CVE tied to a real resource in the graph.

**Deliverables**

- **Trivy ingest**: read a `trivy fs --format=json` output, project
  vulnerabilities onto the resources they were found in (a Docker
  image referenced by a DO App Platform deploy gets the
  vulnerability list attached to that DO resource).
- **Grype ingest**: same shape.
- **Checkov ingest**: IaC vulns merge into the graph as resources
  proxying for the cloud resources they describe.
- **gitleaks ingest**: secret findings, with the rule of "we treat
  a leaked secret as a finding against the repository resource,
  not the file."
- **Compose, don't reimplement**: no native CVE database, no
  native dependency resolver. compliancekit's job is the graph and
  the evidence pack; the scanners are best left to specialists.

---

### v0.15 — Remediation generators

**Goal:** the "OK how do I fix it" question gets answered
copy-pasteably.

**Deliverables**

- **Per-check remediation generators** for the formats the audience
  already uses: Bash one-liners, Terraform blocks, Ansible playbook
  fragments, `aws` / `gcloud` / `doctl` / `hcloud` CLI commands.
- Generators live next to the check (`internal/checks/<provider>/
  <service>_remediate.go`) so a contributor adding a new check is
  expected to ship the remediation too — a check without a
  remediation generator is incomplete from v0.15 onwards.
- `compliancekit remediate --in=findings.json --format=terraform`
  emits a single file the operator applies.
- **Per ADR-006**: remediation is *generation*, not *application*.
  `--apply-fix` is the v2.x gate, intentionally a separate trust
  bar.

---

### v0.16 — Rego policy DSL (via OPA)

**Goal:** community-authored checks in <10 lines of Rego, no Go
toolchain required.

This is the ADR-002 deliverable, shifted from v0.13 to v0.16 to
make room for the cloud arc. The interface design (the `Evaluator`
seam in `internal/core/`) was set up at v0.1 specifically for this
slot; the move-to-later does not break the design.

**Deliverables**

- `internal/policies/*.rego` directory loaded at startup.
- OPA Rego library embedded via `github.com/open-policy-agent/opa`.
- One end-to-end example: re-implement five existing Go checks in
  Rego, ship them side-by-side, demonstrate identical findings
  output. Validates the model.
- Documentation in CHECKS.md for "writing a check in Rego."
- CI gates that the Go and Rego implementations of the side-by-side
  checks produce identical output.

---

### v0.17 — Notifications

**Goal:** Slack the right channel when a new high-severity finding
lands. The minimum-viable continuous-monitoring story without
running the daemon.

**Deliverables**

- Slack / Discord / Teams / email / generic webhook / GitHub PR
  comment / Jira-issue sinks behind a unified
  `compliancekit notify` subcommand.
- Sinks are pluggable: each lives in `internal/notify/<channel>.go`
  with a small interface so a contributor can add a new sink in <100
  LoC.
- Configurable severity threshold per sink; configurable "only-new-
  findings" mode that reads a baseline.
- **No telemetry, no phone-home, ever** — applies here. Every
  notification target is operator-configured.

---

### v0.18 — Waivers + in-code skip annotations

**Goal:** mute findings the right way — explicit, time-bounded,
auditable.

**Deliverables**

- `waivers.yaml` schema: `{check_id, resource_id, expires, reason,
  approver}`. Expired waivers stop muting and surface as info-level
  findings of their own.
- In-code annotations: `// compliancekit:waive <check-id> <reason>`
  comments in IaC and Bash files. Lifted into the graph at scan
  time the same way godoc comments are lifted into doc tools.
- **Waivers are visible in the evidence pack** — the auditor sees a
  waived finding listed with the reason and approver, not hidden.
- ADR-008 (to be written at v0.18 time): waivers vs. baselines —
  what is each for, when to use which.

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
