# compliancekit — GitHub Action

<!--
This README is the source-of-truth for darpanzope/compliancekit-action.
At each compliancekit release, the contents of action/ in the main
repository are copied verbatim to the dedicated action repo and the
floating v1 tag is moved to point at it. Edit here, ship there.
-->

[![release](https://img.shields.io/github/v/release/darpanzope/compliancekit?label=compliancekit&logo=github)](https://github.com/darpanzope/compliancekit/releases)
[![marketplace](https://img.shields.io/badge/marketplace-compliancekit-blue?logo=github)](https://github.com/marketplace/actions/compliancekit)
[![license](https://img.shields.io/github/license/darpanzope/compliancekit)](https://github.com/darpanzope/compliancekit/blob/main/LICENSE)
[![sigstore cosign](https://img.shields.io/badge/sigstore-cosign-3b8eed?logo=sigstore)](https://docs.sigstore.dev/)

> Open-source compliance scanner for **DigitalOcean, AWS, GCP, Hetzner, Kubernetes, and Linux fleets** — runs in your CI, fails the build on findings above a severity threshold, and emits an **audit-ready evidence pack** for SOC 2, ISO 27001, CIS, NIST, HIPAA, PCI-DSS, and MITRE ATT&CK.

```yaml
- uses: darpanzope/compliancekit-action@v1
  with:
    fail-on: high
    output: sarif,markdown,json
  env:
    DO_API_TOKEN: ${{ secrets.DO_API_TOKEN }}
```

Findings land in **GitHub Code Scanning** (via SARIF), in a **PR comment** (via markdown), and as a **build artifact** (via JSON or the evidence pack). A single static Go binary, no SaaS, no telemetry, cosign-signed releases via Sigstore.

---

## What it scans

| Provider | Auth | Coverage |
|---|---|---:|
| 🌊 **DigitalOcean** | `DO_API_TOKEN` | 74 checks across 20 service families |
| ☁️ **AWS** | Standard SDK chain (env / profile / IMDSv2 / OIDC) | 30 checks across IAM / EC2 / S3 / RDS / CloudTrail / KMS / Config / GuardDuty |
| 🛰️ **GCP** | Application Default Credentials | 25 checks across IAM / Compute / GCS / Cloud SQL / Logging / KMS / BigQuery |
| 🇩🇪 **Hetzner Cloud** | `HCLOUD_TOKEN` | 15 checks across servers / firewalls / networks / LBs / volumes / floating IPs |
| ☸️ **Kubernetes** | `~/.kube/config` chain (works with EKS / GKE / DOKS / kind) | **139 checks** across pods, controllers, RBAC, network, storage, namespaces, nodes + EKS / GKE / DOKS enrichment |
| 🐧 **Linux fleet** | SSH (key + optional bastion) | 15 checks against CIS Ubuntu/Debian benchmark subset |

**Total: 298 checks**, every one framework-mapped and remediation-documented.

## Frameworks shipped

| Framework | Version | Coverage | Category |
|---|---|---:|---|
| SOC 2 TSC | 2017 (2022 PoF) | 60 controls | compliance |
| ISO/IEC 27001 Annex A | 2022 | 93 controls | compliance |
| CIS Controls v8 | v8 | 153 safeguards × IG1/IG2/IG3 | compliance |
| NIST SP 800-53 | r5 | 131 controls (cloud + Linux subset) | compliance |
| HIPAA Security Rule | 45 CFR §§164.308/310/312 | 50 implementation specs | compliance |
| PCI DSS | v4.0 | 61 sub-requirements | compliance |
| MITRE ATT&CK Enterprise | v15 (2024) | 12 tactics + 50 techniques | threat model |

**548 controls** total. Every check claims only the controls it actually reaches — no fake mappings. Operators can scope controls out via [`tailoring:`](#evidence-pack--tailoring) with a required written justification that flows into the audit trail.

---

## Quick start

### Scan on every PR, fail on high-severity findings

```yaml
# .github/workflows/compliancekit.yaml
name: compliancekit
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # for upload-sarif to Code Scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: darpanzope/compliancekit-action@v1
        with:
          providers: digitalocean,linux
          fail-on: high
          output: sarif,markdown,json
        env:
          DO_API_TOKEN: ${{ secrets.DO_API_TOKEN }}
```

That's it. Findings appear in the **Security → Code Scanning** tab; the markdown is at `out/findings.markdown` (handy for sticky PR comments — see [recipes](#recipes)); the JSON is at `out/findings.json` for downstream evidence-pack generation.

### Multi-cloud + Kubernetes scan

```yaml
- uses: darpanzope/compliancekit-action@v1
  with:
    config-file: compliancekit.yaml
    fail-on: high
  env:
    DO_API_TOKEN:                     ${{ secrets.DO_API_TOKEN }}
    AWS_ACCESS_KEY_ID:                ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY:            ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    GOOGLE_APPLICATION_CREDENTIALS:   ${{ secrets.GCP_SA_JSON_PATH }}
    HCLOUD_TOKEN:                     ${{ secrets.HCLOUD_TOKEN }}
    KUBECONFIG:                       ${{ secrets.KUBECONFIG_PATH }}
```

`compliancekit.yaml` toggles which providers are enabled — see [CONFIGURATION.md](https://github.com/darpanzope/compliancekit/blob/main/CONFIGURATION.md).

---

## Inputs

| Input | Default | Description |
|---|---|---|
| `version` | `latest` | compliancekit binary version to install (no leading `v`). `latest` resolves the highest published release. |
| `providers` | (config) | Comma-separated provider(s) to scan, e.g. `digitalocean,aws`. Empty = every provider enabled in `config-file`. |
| `config-file` | — | Path to `compliancekit.yaml` in the workspace. Without it, only env vars + defaults apply. |
| `inventory` | — | Path to a Linux inventory YAML. Only consulted when scanning the `linux` provider. |
| `frameworks` | (all) | Comma-separated framework filter, e.g. `soc2,nist-800-53-r5`. |
| `output` | `sarif,markdown,json` | One or more of `json`, `markdown`, `sarif`, `ocsf`, `html`. `sarif` enables Code Scanning ingestion. |
| `out-dir` | `./out` | Where compliancekit writes report files. |
| `fail-on` | `high` | Severity threshold for non-zero exit: `critical`, `high`, `medium`, `low`, `info`, or `never`. |
| `evidence` | `false` | Also produce an audit-ready evidence pack under `<out-dir>/evidence/`. |
| `evidence-period` | (current quarter) | Audit period label embedded in the evidence pack, e.g. `2026-Q2`. |
| `upload-sarif` | `true` | Auto-upload the SARIF output to GitHub Code Scanning. Requires `security-events: write`. |

## Outputs

| Output | Description |
|---|---|
| `reports-dir` | Absolute path to the directory the scan wrote into. |
| `evidence-dir` | Absolute path to the evidence pack (empty when `evidence: false`). |

---

## Permissions

The composite action runs in your job's permission context. Recommended job-level scope:

```yaml
permissions:
  contents: read          # checkout
  security-events: write  # upload-sarif (only if output contains sarif)
  pull-requests: write    # if you wire a PR-comment step downstream
```

If `upload-sarif: false`, drop `security-events: write`.

---

## Recipes

<details>
<summary><strong>Comment a finding summary on every PR</strong></summary>

```yaml
- uses: darpanzope/compliancekit-action@v1
  id: scan
  with:
    providers: aws
    output: markdown,json
    fail-on: medium

- uses: marocchino/sticky-pull-request-comment@v2
  with:
    path: ${{ steps.scan.outputs.reports-dir }}/findings.markdown
```

`findings.markdown` is filtered to actionable findings only — pass/skip rows are dropped so the PR comment stays readable.
</details>

<details>
<summary><strong>Quarterly evidence pack as a build artifact</strong></summary>

```yaml
name: evidence
on:
  schedule: [{ cron: '0 6 1 */3 *' }]   # first of every quarter
  workflow_dispatch:

permissions:
  contents: read

jobs:
  evidence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: darpanzope/compliancekit-action@v1
        id: scan
        with:
          providers: digitalocean,linux
          evidence: true
          fail-on: never
        env:
          DO_API_TOKEN: ${{ secrets.DO_API_TOKEN }}

      - uses: actions/upload-artifact@v4
        with:
          name: evidence-pack-${{ github.run_id }}
          path: ${{ steps.scan.outputs.evidence-dir }}
```

The pack contains per-control folders, `summary.html` (auditor index), `control-mapping.csv` (Drata / Vanta / AuditBoard ingest), and `MANIFEST.sha256` for tamper-evidence.
</details>

<details>
<summary><strong>Pin a specific version of compliancekit</strong></summary>

```yaml
- uses: darpanzope/compliancekit-action@v1
  with:
    version: 0.12.0
    fail-on: high
```

Without `version:` the action resolves the highest published release at run time. Pin to a literal version when you want reproducible scans.
</details>

<details>
<summary><strong>Tailoring: scope controls out with an audit-honest justification</strong></summary>

In `compliancekit.yaml`:

```yaml
tailoring:
  - framework: pci-dss-v4
    control: "10.6.1"
    justification: |
      Out of scope — we do not store, process, or transmit PAN.
      All payments are tokenized via Stripe Connect.
```

```yaml
- uses: darpanzope/compliancekit-action@v1
  with:
    config-file: compliancekit.yaml
    evidence: true
```

The evidence pack carries the justification in `tailoring.json`, in a `tailoring_justification` column of `control-mapping.csv`, and as a visible card at the top of `summary.html`. Auditors see every scope-out decision with its written reason.
</details>

<details>
<summary><strong>Scan a Kubernetes cluster (EKS / GKE / DOKS / kind)</strong></summary>

```yaml
- uses: actions/checkout@v4

- name: Configure kubectl
  uses: azure/k8s-set-context@v3
  with:
    method: kubeconfig
    kubeconfig: ${{ secrets.KUBECONFIG }}

- uses: darpanzope/compliancekit-action@v1
  with:
    providers: kubernetes
    fail-on: high
```

compliancekit reads from `~/.kube/config` like any other K8s tool. For EKS, also enable the AWS provider; for GKE, also enable GCP; for DOKS, also enable DigitalOcean — that lights up the cloud-side enrichment checks (public endpoint, secrets KMS, Workload Identity, HA control plane, auto-upgrade, etc.).
</details>

---

## Why compliancekit

| | compliancekit | Prowler | ScoutSuite | Steampipe |
|---|---|---|---|---|
| Single static binary | ✅ | ❌ Python | ❌ Python | ✅ |
| DigitalOcean / Hetzner | ✅ | ❌ | partial | partial |
| Audit-ready evidence pack | ✅ | ❌ | ❌ | ❌ |
| Tailoring with auditor trail | ✅ v0.12+ | ❌ | ❌ | ❌ |
| ATT&CK kill-chain view | ✅ v0.12+ | ❌ | ❌ | ❌ |
| Cosign-signed releases | ✅ | ❌ | ❌ | ✅ |
| Multi-arch Docker | ✅ | partial | ❌ | ✅ |

compliancekit is **Prowler for the people Prowler forgot** — designed for the indie SaaS audience on DigitalOcean, Hetzner, and AWS-but-not-enterprise, with evidence-pack output that ingests directly into Drata / Vanta / AuditBoard.

## Supply-chain integrity

Every compliancekit release is:

- ✅ **Cosign-signed** (Sigstore Fulcio keyless, GitHub OIDC). `checksums.txt.{sig,pem}` shipped alongside artifacts.
- ✅ **SBOM-attested** per platform (Syft, CycloneDX JSON).
- ✅ **Multi-arch Docker image** at `ghcr.io/darpanzope/compliancekit:<version>` with manifest signatures.
- ✅ **Reproducible builds** (`CGO_ENABLED=0`, `-trimpath`, ldflags pin source commit + date).

Verify any release:

```sh
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/darpanzope/compliancekit' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  checksums.txt
```

---

## License

[MIT](https://github.com/darpanzope/compliancekit/blob/main/LICENSE) — same as compliancekit itself. No warranty, no telemetry, no SaaS lock-in.

## Links

- 🛠️ **Source / binary**: [github.com/darpanzope/compliancekit](https://github.com/darpanzope/compliancekit)
- 📚 **Getting started**: [GETTING_STARTED.md](https://github.com/darpanzope/compliancekit/blob/main/GETTING_STARTED.md)
- 📋 **Full check catalog**: [docs/checks.md](https://github.com/darpanzope/compliancekit/blob/main/docs/checks.md)
- 🗺️ **Roadmap**: [ROADMAP.md](https://github.com/darpanzope/compliancekit/blob/main/ROADMAP.md)
- 🐛 **Issues**: [github.com/darpanzope/compliancekit/issues](https://github.com/darpanzope/compliancekit/issues)
