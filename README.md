<div align="center">

# compliancekit

**The open-source compliance scanner for the rest of us.**
Scan DigitalOcean accounts and Linux fleets, get findings mapped to SOC 2 /
ISO 27001 / CIS Controls v8, generate an audit-ready evidence pack — in one binary.

[![ci](https://github.com/darpanzope/compliancekit/actions/workflows/ci.yaml/badge.svg)](https://github.com/darpanzope/compliancekit/actions/workflows/ci.yaml)
[![govulncheck](https://github.com/darpanzope/compliancekit/actions/workflows/govulncheck.yaml/badge.svg)](https://github.com/darpanzope/compliancekit/actions/workflows/govulncheck.yaml)
[![go report](https://goreportcard.com/badge/github.com/darpanzope/compliancekit)](https://goreportcard.com/report/github.com/darpanzope/compliancekit)
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
scanning digitalocean, linux (298 checks)...
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
scanning digitalocean (298 checks)...
wrote ./out/findings.json
wrote ./out/findings.html
wrote ./out/findings.markdown

592 findings (23 critical, 164 high, 190 medium, 215 low)
Hardening score: 67/100 (coverage 100%)
findings at or above high severity present
```

Open `out/findings.html` in your browser — search/filter, dark mode,
drill into any finding by ID, severity, or resource.

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
| DigitalOcean | v0.9 ✅ | 74 | account hardening (3) + droplets (8) + firewalls (6) + VPCs (3) + LBs (5) + DNS (4) + certs (2) + managed DBs (8) + Spaces (6) + Spaces keys (2) + Container Registry (3) + App Platform (5) + Functions (3) + volumes (2) + snapshots (2) + CDN (2) + reserved IPs (2) + SSH keys (2) + images (2) + monitoring (2) + projects (2) (every DO surface except DOKS, which lands at v0.11) |
| Linux over SSH | first-party | 15 | agentless; CIS Ubuntu/Debian benchmark subset; covers sshd, ufw/nftables, auditd, filesystem, users, kernel |
| AWS | v0.7 ✅ | 30 | IAM (8) + S3 (5) + EC2 (5) + RDS (4) + CloudTrail (3) + KMS (2) + Config (2) + GuardDuty (1) |
| GCP | v0.8 ✅ | 25 | IAM (6) + Compute (5) + GCS (4) + Cloud SQL (3) + Logging (2) + KMS (2) + BigQuery (3) |
| Hetzner Cloud | v0.10 ✅ | 15 | servers (5) + firewalls (3) + networks (2) + load balancers (2) + volumes (2) + floating IPs (1) |
| Kubernetes + EKS / GKE / DOKS-deep | v0.11 ✅ | 139 | generic K8s (95) — pods/controllers/RBAC/network/storage/namespaces/admission/nodes — plus EKS (12) + GKE (13) + DOKS (9) enrichment |
| Cloudflare, GitHub, Google Workspace, Vercel, Linode, Vultr | v1.7 | — | tail clouds |

### Frameworks

Every check maps across **seven shipping frameworks** (v0.12+) — 548 controls total. Operators can scope controls out of audit via `tailoring:` in `compliancekit.yaml`; the evidence pack carries every scope-out with its written justification.

| Framework | Version | Coverage | Category |
|---|---|---:|---|
| SOC 2 Trust Services Criteria | 2017 (with 2022 PoF) | 60 (full CC1-CC9 + A + C + PI + P) | compliance |
| ISO/IEC 27001 Annex A | 2022 | 93 (full Annex A: org, people, physical, technological) | compliance |
| CIS Controls v8 | v8 | 153 safeguards × IG1/IG2/IG3 taxonomy | compliance |
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
├── MANIFEST.sha256              # sha256sum -c verifiable
├── control-mapping.csv          # Drata / Vanta / AuditBoard importable
├── summary.html                 # auditor index
├── soc2/<control>/{findings.json, control.md}
├── iso27001/<control>/{findings.json, control.md}
└── cis-v8/<control>/{findings.json, control.md}
```

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

## FAQ

**Is this another agent I have to install on every host?**
No. The Linux provider works over SSH, snippets run remotely and are
parsed locally. No daemons, no auto-update, no callbacks.

**Will it touch my infrastructure?**
No. `compliancekit` is read-only by design (ADR-005 in
[DECISIONS.md](DECISIONS.md)). Remediation generators land at v0.15 and even
then they emit commands for you to run — they do not execute anything.

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
Not from us. The MIT licence lets anyone host one; the `serve` mode at v1.1
is the same binary running long-lived with a SQLite/Postgres backend so
you can self-host without writing a new server.

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
