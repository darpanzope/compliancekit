<div align="center">

# compliancekit

**The open-source compliance scanner for the rest of us.**
Scan DigitalOcean, AWS, GCP, Hetzner, Kubernetes, and Linux fleets;
get findings mapped to nine compliance frameworks (SOC 2, ISO 27001,
CIS Controls v8, CIS Linux Server, NSA/CISA Kubernetes Hardening,
NIST 800-53 r5, HIPAA, PCI DSS, MITRE ATT&CK); generate an audit-ready
evidence pack — in one static binary.

[![ci](https://github.com/darpanzope/compliancekit/actions/workflows/ci.yaml/badge.svg)](https://github.com/darpanzope/compliancekit/actions/workflows/ci.yaml)
[![govulncheck](https://github.com/darpanzope/compliancekit/actions/workflows/govulncheck.yaml/badge.svg)](https://github.com/darpanzope/compliancekit/actions/workflows/govulncheck.yaml)
[![go report](https://goreportcard.com/badge/github.com/darpanzope/compliancekit)](https://goreportcard.com/report/github.com/darpanzope/compliancekit)
[![go reference](https://pkg.go.dev/badge/github.com/darpanzope/compliancekit/pkg/compliancekit.svg)](https://pkg.go.dev/github.com/darpanzope/compliancekit/pkg/compliancekit)
[![release](https://img.shields.io/github/v/release/darpanzope/compliancekit?sort=semver)](https://github.com/darpanzope/compliancekit/releases/latest)
[![license](https://img.shields.io/github/license/darpanzope/compliancekit)](LICENSE)

</div>

<!--
  Hero asciinema goes here once recorded. Placeholder:
  https://asciinema.org/a/<id>.svg
  Recording script lives in scripts/asciinema.sh; record with:
    asciinema rec scripts/demo.cast
-->

<p align="center">
  <em>asciinema cast lands at v0.5.0 final cut.</em>
</p>

---

## What this is

You run a SaaS. You have ten DigitalOcean droplets, an AWS account someone
opened once, a Kubernetes cluster from when you tried it, and a stripe of
CIS-shaped expectations from the SOC 2 auditor your customers won't shut
up about.

You don't have a security team. You don't have an SRE. You have a Saturday.

`compliancekit` is for you.

```
$ compliancekit scan
scanning digitalocean, linux (574 checks)...
✗ web-01: no firewall attached                       (high, soc2/CC6.6)
✗ web-01: SSH allowed from 0.0.0.0/0                 (high, iso27001/A.8.21)
✓ web-01: backups enabled                            (medium)
✗ db-01: auditd not running                          (medium, cis-v8/8.5)
...
24 findings (3 high, 8 medium, 13 low) in 4.2s
Hardening score: 73/100 (coverage 92%)

$ compliancekit evidence --in findings.json --out evidence/2026-Q2/
Generating evidence pack from findings.json (24 findings)...
SOC 2 Trust Services Criteria: 12 controls covered, 4 with open findings
ISO/IEC 27001:2022 Annex A:     9 controls covered, 3 with open findings
CIS Controls v8:               14 controls covered, 6 with open findings
Output: evidence/2026-Q2 (61 files, MANIFEST.sha256 written)
Auditor index: evidence/2026-Q2/summary.html
Control mapping: evidence/2026-Q2/control-mapping.csv
```

**Drift gating** (v0.6+):

```
$ compliancekit baseline --in findings.json     # snapshot accepted state
$ # ... PR makes a change ...
$ compliancekit diff .compliancekit/baseline.json findings.json --fail-on=new-high
+ 2 new   (1 high, 1 medium)
- 1 resolved
= 23 existing
Hardening score: 76 -> 73 (-3)
```

## Why this exists

Prowler exists. ScoutSuite exists. Steampipe exists. They are excellent
tools that target the **enterprise security teams who own AWS, GCP, and
Azure** — and they leave a huge slice of the market unserved.

What compliancekit does differently:

- **DigitalOcean, Hetzner, Linode, Vultr — first-class, not "we have a
  third-party plugin somewhere."** AWS and GCP land as first-class
  providers too (v0.7 and v0.8 per [ROADMAP.md](ROADMAP.md)) but the
  audience compliancekit was built for is the indie-SaaS founder, not
  the F500 security org.
- **Linux droplets over SSH.** Not "install our agent" — agentless,
  works on the boxes you already have.
- **Outputs an auditor will actually accept.** A JSON dump is not evidence.
  A folder of per-control Markdown plus a `MANIFEST.sha256` is.

Prowler for the people Prowler forgot.

## Install

### macOS (Homebrew)

```
brew install darpanzope/tap/compliancekit
```

### Linux / macOS (one-line installer)

```
curl -sSfL https://raw.githubusercontent.com/darpanzope/compliancekit/main/scripts/install.sh | sh
```

### Go

```
go install github.com/darpanzope/compliancekit/cmd/compliancekit@latest
```

### Docker

```
docker run --rm -v $PWD:/work ghcr.io/darpanzope/compliancekit:latest scan
```

Every release ships:
- Cross-compiled binaries (darwin/linux, amd64/arm64) on the GitHub Release.
- A cosign-signed checksum manifest and a Syft SBOM.
- A Docker image at `ghcr.io/darpanzope/compliancekit`.
- A Homebrew formula in `darpanzope/homebrew-tap`.

Reproduce the supply chain with:

```
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/darpanzope/compliancekit' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature compliancekit_<version>_checksums.txt.sig \
  compliancekit_<version>_checksums.txt
```

## Quickstart

End-to-end first scan in about a minute. Replace `<provider>` with the
cloud you actually use — each provider's auth is different, so pick one
to start.

**1. Install** (see [§Install](#install) above for other paths):

```sh
brew install darpanzope/tap/compliancekit
```

**2. Set the auth env var for your provider:**

| Provider | Env var | Where to get it |
|---|---|---|
| DigitalOcean | `DO_API_TOKEN` | https://cloud.digitalocean.com/account/api/tokens (read scope) |
| AWS | Standard SDK chain | `aws configure` / `AWS_PROFILE` / IMDSv2 / GitHub OIDC |
| GCP | Application Default Credentials | `gcloud auth application-default login` |
| Hetzner Cloud | `HCLOUD_TOKEN` | Hetzner Cloud Console → Security → API Tokens (read scope) |

Example for DO:

```sh
export DO_API_TOKEN=dop_v1_xxxxxxxxxxxx
```

**3. Grab a minimal config** matching your provider:

```sh
# pick one
curl -O https://raw.githubusercontent.com/darpanzope/compliancekit/main/examples/quickstart-do.yaml
curl -O https://raw.githubusercontent.com/darpanzope/compliancekit/main/examples/quickstart-aws.yaml
curl -O https://raw.githubusercontent.com/darpanzope/compliancekit/main/examples/quickstart-gcp.yaml
curl -O https://raw.githubusercontent.com/darpanzope/compliancekit/main/examples/quickstart-hetzner.yaml
curl -O https://raw.githubusercontent.com/darpanzope/compliancekit/main/examples/quickstart-k8s.yaml

mv quickstart-*.yaml compliancekit.yaml
```

**4. Confirm auth + run the scan:**

```sh
compliancekit doctor                # confirms token resolves + API is reachable
compliancekit scan                  # writes findings.{json,html,markdown} into ./out/
```

Expected output (numbers vary by account):

```
scanning digitalocean (574 checks)...
wrote ./out/findings.json
wrote ./out/findings.html
wrote ./out/findings.markdown

592 findings (23 critical, 164 high, 190 medium, 215 low)
Hardening score: 67/100 (coverage 100%)
findings at or above high severity present
```

Open `out/findings.html` in your browser. As of v1.2 you get:

- **Summary cards** at the top — score gauge, severity donut, framework-coverage bars (pure inline SVG; no chart library).
- **Filter chips** — multi-select across severity / status / provider / framework, with the active selection encoded in the URL fragment so a slice (e.g. `findings.html#severity=critical,high&provider=aws`) is a one-link Slack share.
- **Sticky resource sidebar** — every resource grouped provider → type, click to scroll, mobile-friendly collapse.
- **Dark / light / system toggle** — top-right, persisted to localStorage, tracks OS preference when set to system.
- **Baseline drift** — pass `--baseline=path` to add a "Drift vs baseline" card, score + actionable-count sparklines, and a "New" badge on every finding absent from the baseline.
- **Print-friendly** — `@media print` drops sticky chrome, expands every `<details>`, forces a light palette; Chrome's *Save as PDF* produces a clean A4 layout.
- **Single-file invariant preserved** — every CSS / JS / SVG is inlined; `curl -O findings.html` + open works offline.

To re-render a saved findings.json against a new compliancekit binary without re-scanning, use `compliancekit render --in=findings.json --out=report.html` (or with `--baseline=...` for the trend view).

**5. Generate the auditor-ready evidence pack (optional):**

```sh
compliancekit evidence --in out/findings.json --out evidence/2026-Q2/
open evidence/2026-Q2/summary.html
```

For the long-form walk-through (per-provider auth deep-dive, CI
integration, evidence pack structure, output formats), see
**[GETTING_STARTED.md](GETTING_STARTED.md)**. Full CLI reference in
[CLI.md](CLI.md). Config schema in [CONFIGURATION.md](CONFIGURATION.md).

## What's in the box today

Full per-check reference (auto-generated, IDs / severities / framework mappings / remediation): [docs/checks.md](docs/checks.md).

### Providers

| Provider | Status | Checks | Notes |
|---|---|---:|---|
| DigitalOcean | v0.19 ✅ | 144 | account hardening + governance (13) + droplets + lifecycle (12) + firewalls + dedup (12) + VPCs + peering (5) + LBs + TLS depth (10) + DNS + DMARC/SPF/DKIM/CAA/DNSSEC (14) + certs (2) + managed DBs (8) + Spaces + lifecycle/policy/audit (16) + Spaces keys (2) + Container Registry (3) + App Platform + observability (15) + Functions + runtime/env hygiene (13) + volumes (2) + snapshots (2) + CDN (2) + reserved IPs + region hygiene (3) + SSH keys (2) + images (2) + monitoring + alert coverage (3) + projects + billing (12). Every check carries bespoke Terraform + doctl + bash remediation (432 strategies, parity-gated by CI). |
| Linux over SSH | v0.20 ✅ | 119 | agentless; full CIS Linux Server Benchmark v8 surface across 9 spec frameworks: kernel sysctl (28) + filesystem mounts (15) + systemd services (10) + sshd deepening (10) + auditd rule presence (10) + login.defs / PAM / sudo (10) + packages + MAC SELinux/AppArmor (10) + firewall depth (10) + distro detection + legacy v0.5 baseline (16). Per-distro gating (Ubuntu/Debian, RHEL/CentOS/Rocky/Alma, Alpine, AL2/AL2023). Every check ships bespoke bash + Ansible (238 strategies, parity-gated at 0/0). |
| AWS | v0.7 ✅ | 30 | IAM (8) + S3 (5) + EC2 (5) + RDS (4) + CloudTrail (3) + KMS (2) + Config (2) + GuardDuty (1) |
| GCP | v0.8 ✅ | 25 | IAM (6) + Compute (5) + GCS (4) + Cloud SQL (3) + Logging (2) + KMS (2) + BigQuery (3) |
| Hetzner Cloud | v0.10 ✅ | 15 | servers (5) + firewalls (3) + networks (2) + load balancers (2) + volumes (2) + floating IPs (1) |
| Kubernetes + EKS / GKE / DOKS-deep | v0.21 ✅ | 241 | full CIS K8s Benchmark + NSA/CISA Kubernetes Hardening Guide v1.2 surface. v0.11 baseline (149) + v0.21 deepening (+92) across pod-security extra (12), reliability (12), supply-chain (10), RBAC depth (10), network depth (10), admission + policy engine (8), CIS control-plane manual-verify (15), DOKS/EKS/GKE deepening (15). Every K8s check ships bespoke kubectl (parity-gated at strict 0; Helm + Terraform per-check where natural-fit). |
| Cloudflare, GitHub, Google Workspace, Vercel, Linode, Vultr | v2.6 | — | tail clouds (re-slotted from v1.11 per ADR-016 — v1.x reserved for server / UI / UX / backend / CLI polish) |

### Frameworks

Every check maps across **nine shipping frameworks** (v0.12+ baseline plus the v0.20 CIS Linux Server Benchmark and v0.21 NSA/CISA Kubernetes Hardening Guide catalogs) — 668 controls total. Operators can scope controls out of audit via `tailoring:` in `compliancekit.yaml`; the evidence pack carries every scope-out with its written justification.

| Framework | Version | Coverage | Category |
|---|---|---:|---|
| SOC 2 Trust Services Criteria | 2017 (with 2022 PoF) | 60 (full CC1-CC9 + A + C + PI + P) | compliance |
| ISO/IEC 27001 Annex A | 2022 | 93 (full Annex A: org, people, physical, technological) | compliance |
| CIS Controls v8 | v8 | 153 safeguards × IG1/IG2/IG3 taxonomy | compliance |
| CIS Linux Server Benchmark | v8 | 90 sections × Level 1 / Level 2 (initial-setup, services, network, logging-auditing, access-auth, system-maintenance) | compliance |
| NSA / CISA Kubernetes Hardening Guide | v1.2 (Aug 2022) | 30 controls × 5 chapters (pod-security, network, auth, logging, upgrading) | compliance |
| NIST SP 800-53 | r5 | 131 (cloud + Linux subset across 14 families) | compliance |
| HIPAA Security Rule | 45 CFR §§164.308/310/312 | 50 implementation specs × required/addressable | compliance |
| PCI DSS | v4.0 | 61 sub-requirements × 12 themes | compliance |
| MITRE ATT&CK Enterprise | v15 (2024) | 12 tactics + 50 techniques (cloud + Linux subset) | threat model |

### Output formats

`compliancekit scan --output=<fmt>` accepts:

| Format    | Use case                                             |
|-----------|------------------------------------------------------|
| `json`    | machine-readable, feeds the evidence pack            |
| `markdown`| PR comments — pass/skip findings stripped            |
| `sarif`   | GitHub Code Scanning ingestion                       |
| `ocsf`    | OCSF 1.5 Compliance Finding events for SIEMs        |
| `html`    | single-file dark-mode dashboard, search + filter     |

`compliancekit evidence` then turns the JSON output into:

```
evidence/<period>/
├── MANIFEST.sha256                # sha256sum -c verifiable
├── control-mapping.csv            # Drata / Vanta / AuditBoard importable
├── vulnerabilities.csv            # v0.14+: one row per (CVE × resource); Snyk/Tenable importable
├── summary.html                   # auditor index
├── tailoring.json                 # operator scope-outs + justifications
├── assessment-results.oscal.json  # OSCAL AR v1.1.2, FedRAMP-style
├── profile.oscal.json             # OSCAL Profile of tailored framework subset
├── soc2/<control>/{findings.json, control.md}
├── iso27001/<control>/{findings.json, control.md}
└── cis-v8/<control>/{findings.json, control.md}
```

### Remediation generators (v0.15+)

`compliancekit remediate --in=findings.json --out=./remediation/`
emits copy-pasteable fix-it artifacts in the operator's tool of
choice:

| Format       | Surface                                                          |
|--------------|------------------------------------------------------------------|
| `terraform`  | HCL fragments for AWS, GCP, DigitalOcean, Hetzner                |
| `kubectl`    | strategic-merge patch + GitOps manifest for K8s findings         |
| `helm`       | values.yaml overlays for Helm-chart-deployed workloads           |
| `ansible`    | playbook task fragments for Linux / CIS host hardening           |
| `aws-cli`    | `aws <service>` one-liners                                       |
| `gcloud`     | `gcloud <service>` one-liners                                    |
| `az-cli`     | `az <service>` one-liners (Defender for Cloud ingest findings)   |
| `doctl`      | `doctl <service>` one-liners for DigitalOcean                    |
| `hcloud`     | `hcloud <service>` one-liners for Hetzner                        |
| `bash`       | POSIX-sh fallbacks for Linux + wildcard manual-review snippets    |

Each snippet declares a RiskClass (`safe`, `review`, `manual`),
optional `Verify` command, optional `Rollback` command, and prose
caveats. The output directory contains:

```
remediation/
├── remediation.md          # runbook grouped by risk class, with TOC + verify shortcuts
├── remediate.sh            # bash script bundling RiskSafe snippets (set -euo pipefail)
├── poam.oscal.json         # OSCAL v1.1.2 POA&M for manual / unmatched findings
├── remediate-terraform/    # per-resource .tf snippets
├── remediate-kubectl/      # per-resource patch + manifest YAML
└── remediate-<format>/     # one directory per Format
```

Per ADR-006 + ADR-011 the command is **generation only**; `--apply-fix`
is a v2.x trust gate intentionally deferred. Optional ticket
integration (`--tickets`) files Jira / Linear issues for manual
findings when credentials are provided via env vars.

### Ingest formats (v0.13+, expanded at v0.14)

External tool output merges into the same evidence pack:

| Format            | Use case                                                                           |
|-------------------|------------------------------------------------------------------------------------|
| `sarif`           | Generic — Trivy, Checkov, KICS, Terrascan, GitHub CodeQL, Semgrep                  |
| `ocsf`            | AWS Security Hub, GCP Security Command Center, Microsoft Defender for Cloud        |
| `oscal-catalog`   | Customer-supplied OSCAL Catalog → registers as a runtime scannable framework       |
| `trivy-json` *v0.14* | Trivy native JSON — per-package CVE / PURL / CVSS / image SHA detail            |
| `grype-json` *v0.14* | Grype native JSON — alternate vuln scanner, same typed Vulnerability shape      |
| `checkov-json` *v0.14* | Checkov native JSON — Terraform / K8s / Docker per-resource graph             |
| `gitleaks-json` *v0.14* | gitleaks native JSON — secrets with auto-redacted fingerprints (ADR-010)     |

Run standalone (`compliancekit ingest --format=trivy-json --in=trivy.json`),
or declare an `ingest:` block in `compliancekit.yaml` and the
`scan` command merges everything before writing the pack. v0.14+
adds an image-SHA correlation pass: when a Trivy / Grype image scan
reports a CVE on `container-image://<sha>` and the live graph has
K8s / DO / AWS resources referencing that SHA, the CVE finding is
cloned onto each running instance with a `running-on:<type>/<name>`
tag — so an auditor pivoting through "what's wrong with this
Deployment" sees the upstream image's CVEs too. Per-tool mapping
tables ship embedded; `compliancekit mapping list / show / validate
/ diff` manages overrides.

### Waivers (v0.18+)

Mute findings the right way — explicit, time-bounded, auditable.
Per [ADR-013](DECISIONS.md#adr-013--waivers-vs-baselines-distinct-concerns-distinct-mechanisms),
waivers are decisions (require reason + approver + expiry) while
baselines are snapshots (no metadata). Both can coexist; waived
findings stay visible in the evidence pack with full justification.

`waivers.yaml` shape:

```yaml
waivers:
  - check_id:    aws-s3-no-public-acls
    resource_id: aws.s3.bucket.public-cdn
    reason:      "public CDN bucket; CloudFront enforces signed URLs at the edge"
    approver:    security@acme.com
    expires:     2099-12-31
```

Wire it into `compliancekit.yaml` and `scan` mutes matching findings
(StatusSkip + Waiver block populated) during the run:

```yaml
waivers:
  file: ./waivers.yaml
```

In-code annotations work in 6 file types (Terraform, YAML, Bash,
Python, Dockerfile, Go) so operators can co-locate the waiver with
the resource it covers:

```hcl
resource "aws_s3_bucket" "public_cdn" {
  # compliancekit:waive aws-s3-no-public-acls aws.s3.bucket.public-cdn \
  #   reason="public CDN bucket; CloudFront enforces signed URLs" \
  #   approver=security@acme.com expires=2026-12-31
}
```

Defaults when keyword args are omitted: 90-day expiry (forces
re-review), approver `@annotation`, reason references the file +
line so the auditor knows where to investigate.

CLI surface:

```bash
compliancekit waivers list                              # active + expired table
compliancekit waivers show aws-s3-no-public-acls aws.s3.bucket.public-cdn
compliancekit waivers validate                          # schema + duplicate gate
compliancekit waivers check --in=findings.json          # CI gate: every fail must have a waiver
```

Glob matching on both CheckID and ResourceID (`aws-s3-*`,
`digitalocean.droplet.*`) when narrow waivers prove repetitive.
Expired waivers stop muting AND emit their own info-level
`compliancekit-waiver-expired` finding so auditors see the lapse.

Evidence pack additions:

- `control-mapping.csv` gains 4 columns: `waiver_active`,
  `waiver_reason`, `waiver_approver`, `waiver_expires`.
- New `waivers.json` artifact at the pack root with one entry per
  muted finding (cross-references the full Finding for audit traceability).

`compliancekit doctor` reports waivers health alongside provider
checks: "N active, M expired, K expiring within 30d".

### Notifications (v0.17+)

`compliancekit notify --in=findings.json` dispatches actionable
findings to 8 channels — Slack, Discord, Microsoft Teams, Email
(SMTP), generic webhook, GitHub PR comment, Jira, and PagerDuty.
Every sink is operator-configured via env vars; missing credentials
mean the sink is silently skipped (one channel never blocks the
others).

| Sink | Env vars | Notes |
|---|---|---|
| `slack` | `SLACK_WEBHOOK_URL` or `SLACK_BOT_TOKEN` + `SLACK_CHANNEL` | Block Kit payload, severity emoji |
| `discord` | `DISCORD_WEBHOOK_URL` | Embed with severity-colored bar |
| `teams` | `TEAMS_WEBHOOK_URL` | Legacy MessageCard connector |
| `email` | `SMTP_HOST/PORT/USERNAME/PASSWORD/FROM/TO` | Auto-selects TLS/STARTTLS/plain by port |
| `webhook` | `COMPLIANCEKIT_WEBHOOK_URL` + optional `COMPLIANCEKIT_WEBHOOK_SECRET` | HMAC-SHA256 signing in `X-CompliancekitSignature` header |
| `github-pr` | `GITHUB_TOKEN` + `GITHUB_REPO` + `GITHUB_PR_NUMBER` | Single summary comment per dispatch (no spam) |
| `jira` | `JIRA_NOTIFY_HOST/EMAIL/TOKEN/PROJECT` | Reuses the v0.15 ticket client |
| `pagerduty` | `PAGERDUTY_INTEGRATION_KEY` | Events v2; `dedup_key` from finding fingerprint; defaults to critical-only |

Per-sink severity floor: `<SINK>_THRESHOLD=high` (or info / low /
medium / high / critical). The stricter of per-sink + global
`--severity` wins. PagerDuty defaults to critical so a fresh install
doesn't wake on-call on noise.

Only-new-findings mode reads a v0.6 baseline and subtracts already-
known findings before dispatch — channels don't repeat on every scan:

```bash
compliancekit notify --in=findings.json \
  --baseline=.compliancekit/baseline.json \
  --severity=high \
  --url-prefix=https://compliance.acme.com
```

`compliancekit notify --list` shows registered sinks + per-sink
Configured/Threshold state. `compliancekit doctor` also reports the
notify section so misconfigured sinks surface alongside provider
problems.

### Rego policies (v0.16+)

Community-authored checks in <10 lines of Rego — no Go toolchain
required. compliancekit embeds OPA's interpreter (per
[ADR-012](DECISIONS.md#adr-012--rego-is-embedded-via-opas-go-library-not-shelled-out));
policies live as `*.rego` files, register alongside Go checks in
the same registry, and produce findings indistinguishable from
the Go-backed ones.

A minimal policy:

```rego
package compliancekit.example.bucket_public

metadata := {
  "id":          "example-bucket-public",
  "title":       "Buckets should not be public",
  "description": "Flags any bucket whose attributes.public=true.",
  "severity":    "high",
  "provider":    "example",
}

findings := [f |
  r := input.resources[_]
  r.type == "example.bucket"
  compliancekit.attr_bool(r, "public") == true
  f := {
    "resource_id": r.id,
    "status":      "fail",
    "message":     sprintf("bucket %q is public", [r.name]),
  }
]
```

Four custom built-ins available out of the box:

- `compliancekit.has_tag(resource, name)` — tag-membership test
- `compliancekit.attr_str(resource, key)` — string attribute, `""` on miss
- `compliancekit.attr_bool(resource, key)` — bool attribute, `false` on miss
- `compliancekit.cvss_band(score)` — `"critical"|"high"|"medium"|"low"|"info"`

The `policy` subcommand carries the authoring loop:

```bash
# Evaluate a policy against a synthetic resource graph
compliancekit policy test fixture.json examples/policies/aws/s3_public_access_block.rego

# CI gate: compile every .rego under a directory + check metadata
compliancekit policy validate examples/policies/aws

# Reformat in place (or --check for a CI lint gate)
compliancekit policy fmt examples/policies/aws/*.rego
```

15 side-by-side reimplementations of shipped Go checks live under
[examples/policies/](examples/policies/) (AWS, GCP, DigitalOcean,
Kubernetes, Linux — three per lane). Use them as templates for your
own policies.

## Use it in CI

```yaml
# .github/workflows/compliance.yaml
name: compliancekit
on:
  pull_request:
  schedule: [{ cron: '0 6 * * *' }]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: darpanzope/compliancekit-action@v1
        with:
          providers: digitalocean,linux
          fail-on: high
          output: sarif,markdown
        env:
          DO_API_TOKEN: ${{ secrets.DO_API_TOKEN }}
```

Findings appear inline on the PR and in the Code Scanning tab. Exit code 2
on any new finding at or above `fail-on` blocks the merge.

## Embed compliancekit in your own tool (v1.0+)

`pkg/compliancekit` is the SemVer-stable public surface — covered by
SemVer 2.0 for the entire v1.x line, with a machine-enforced CI gate
against [`pkg/compliancekit/api.txt`](pkg/compliancekit/api.txt) that
fails the build if any exported identifier drifts without an explicit,
reviewed diff. Anyone building a tool on top of compliancekit gets a
real contract for the first time at v1.0; see
[ADR-014](DECISIONS.md#adr-014--v10-api-freeze-pkgcompliancekit-is-the-semver-surface)
for the full rationale.

```go
import (
    "context"
    "github.com/darpanzope/compliancekit/pkg/compliancekit"
)

g := compliancekit.NewResourceGraph()
g.Add(compliancekit.Resource{
    ID:       "linux.host.web-01",
    Type:     "linux.host",
    Provider: "linux",
    Attributes: map[string]any{"ssh_password_auth": true},
})

reg := compliancekit.NewRegistry()
reg.Register(
    compliancekit.Check{
        ID:       "ssh-password-auth-disabled",
        Severity: compliancekit.SeverityHigh,
        Provider: "linux",
    },
    func(_ context.Context, graph *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
        var out []compliancekit.Finding
        for _, r := range graph.ByType("linux.host") {
            if r.AttrBool("ssh_password_auth") {
                out = append(out, compliancekit.Finding{
                    CheckID:  "ssh-password-auth-disabled",
                    Status:   compliancekit.StatusFail,
                    Severity: compliancekit.SeverityHigh,
                    Resource: r.Ref(),
                    Message:  "ssh password auth enabled",
                })
            }
        }
        return out, nil
    },
)
```

What graduates to the contract: the load-bearing types — `Severity`,
`Status`, `Resource` / `ResourceRef` / `EvidencePtr`, `ResourceGraph`
(with the `Query` DSL), `Vulnerability` / `Package` / `Secret` /
`WaiverRef`, `Source` / `Finding`, `Check` / `CheckFunc` / `Registry`,
the `Reporter` / `Collector` / `Evaluator` interfaces, and the
`Framework` / `Control` / `Tactic` catalog types. Everything under
`internal/` (engine, collectors, ingest adapters, reporter
implementations, policy evaluator, notify sinks, waivers loader)
stays internal and may change in any release.

Compat promise (per [SECURITY.md](SECURITY.md#two-year-compatibility-commitment-v10)):
security patches land on the last two minor versions of v1.x for at
least two years from each minor's release date.

Full canonical example with JSON round-trip + `Query` DSL +
custom-framework instantiation:
[`pkg/compliancekit/example_embed_test.go`](pkg/compliancekit/example_embed_test.go).
API reference rendered on
[pkg.go.dev](https://pkg.go.dev/github.com/darpanzope/compliancekit/pkg/compliancekit).

## FAQ

**Is this another agent I have to install on every host?**
No. The Linux provider works over SSH, snippets run remotely and are
parsed locally. No daemons, no auto-update, no callbacks.

**Will it touch my infrastructure?**
No. `compliancekit` is read-only by design (ADR-005 in
[DECISIONS.md](DECISIONS.md)). v0.15 ships remediation generators
(`compliancekit remediate`) — they emit Terraform / kubectl / cloud-CLI
artifacts the operator copy-pastes, never executed by the binary.
Auto-apply is permanently gated to v2.x per ADR-006 / ADR-011.

**My auditor wants Drata / Vanta / AuditBoard. Does this play nicely?**
Yes. `evidence` emits `control-mapping.csv` in a one-row-per-(control,
finding) shape every major GRC platform's import templates accept. The
underlying per-control evidence is a folder of Markdown + JSON, so
auditors who insist on "show me the artifact" get to drill straight in.

**Is the redaction safe enough for me to commit the evidence pack to a
private repo?**
The redactor masks AWS access keys, GitHub PATs, Slack tokens, bearer
headers, and email addresses by default. For anything more aggressive
(custom secret patterns, hostnames, IP ranges), use `--include-raw=false`
combined with your own grep-and-fail pipeline. Treat redaction as
defence-in-depth, not the perimeter.

**Why Go?**
One static binary, no runtime, friendly to CI environments that don't have
Python or Node. The same binary works on macOS, Linux, x86, and arm.

**Is there a hosted version?**
Not from us. The MIT licence lets anyone host one; `serve` mode (v1.3 foundation +
v1.4 Studio + v1.5 Explorer) is the same binary running long-lived with a SQLite/Postgres
backend so you can self-host without writing a new server. v1.4 added the config-builder
studio (`/settings`, `/checks`, framework tailoring, CI generator, waivers, scheduler,
audit + inbox) and v1.5 added the findings explorer (saved views, side-panel finding
detail, remediation studio, resource map, drift timeline, score-over-time, cross-scan
diff, Cmd+K global search, PDF export).

**Comparison to Prowler / ScoutSuite / Steampipe?**
They target enterprise security teams on the big three clouds. We target
indie SaaS teams on DigitalOcean, Hetzner, and Linux. They emit JSON;
we emit an evidence folder. There is overlap and we plan to ingest their
outputs from v0.13 onwards.

**License?**
[MIT](LICENSE). The bundled framework YAML files are derivative summaries
of the published standards; consult the standards' own licenses (AICPA SOC 2,
ISO/IEC 27001:2022, CIS Controls v8) before redistributing them outside this
binary.

## Contributing

We are actively accepting contributions in scope of the [ROADMAP](ROADMAP.md).
Start with [CONTRIBUTING.md](CONTRIBUTING.md) — the bar for new checks is
explicit and easy to clear.

Security issues: [SECURITY.md](SECURITY.md) (do not open a public issue).

## Acknowledgements

`compliancekit` learned from the prior art. In particular:
- [Prowler](https://github.com/prowler-cloud/prowler) — the bar for cloud
  security scanners and the original "open source for the auditor" project.
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) — the multi-cloud
  per-finding model.
- [Steampipe](https://github.com/turbot/steampipe) — proof that "SQL over
  cloud resources" is a viable interaction model; the resource-graph
  architecture in ARCHITECTURE §3 is a small genuflection in that
  direction.
- [Vanta](https://www.vanta.com/) and [Drata](https://drata.com/) —
  proof that "the evidence pack" is the artifact that actually matters.

If we're useful to you and you want to support the work,
[sponsor on GitHub](https://github.com/sponsors/darpanzope) or just star
the repo. Both help.
