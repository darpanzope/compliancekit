# compliancekit-action

<!--
This README is the source-of-truth for darpanzope/compliancekit-action.
At each compliancekit release, the contents of action/ in the main
repository are copied verbatim to the dedicated action repo and the
floating v1 tag is moved to point at it. Edit here, ship there.
-->

[![release](https://img.shields.io/github/v/release/darpanzope/compliancekit?label=compliancekit&logo=github)](https://github.com/darpanzope/compliancekit/releases)
[![marketplace](https://img.shields.io/badge/marketplace-compliancekit--scan-blue?logo=github)](https://github.com/marketplace/actions/compliancekit-scan)
[![ci](https://img.shields.io/github/actions/workflow/status/darpanzope/compliancekit/ci.yaml?branch=main&label=ci)](https://github.com/darpanzope/compliancekit/actions/workflows/ci.yaml)
[![license](https://img.shields.io/github/license/darpanzope/compliancekit)](https://github.com/darpanzope/compliancekit/blob/main/LICENSE)
[![cosign](https://img.shields.io/badge/sigstore-cosign-3b8eed?logo=sigstore)](https://docs.sigstore.dev/)

Run [compliancekit](https://github.com/darpanzope/compliancekit) inside a GitHub
Actions job. Scans your live cloud and Kubernetes infrastructure on every pull
request, maps every finding to a compliance framework, and emits an
auditor-ready evidence pack — without leaving your CI.

```yaml
- uses: darpanzope/compliancekit-action@v2
  with:
    providers: digitalocean
    fail-on: high
  env:
    DO_API_TOKEN: ${{ secrets.DO_API_TOKEN }}
```

That single step:

- Installs the cosign-verified `compliancekit` binary on the runner.
- Scans the providers you enable, against **574 checks** mapped to
  **668 controls** across **9 frameworks**.
- Writes SARIF (Code Scanning), Markdown (PR comments), and JSON
  (downstream evidence pack) to `./out/`.
- Fails the job when a finding is at or above the `fail-on` severity.

No SaaS round-trip, no telemetry, no shell-out to Docker. A single static Go
binary released with Sigstore cosign signatures and SBOMs.

---

## Contents

- [Coverage](#coverage)
- [Quick start](#quick-start)
- [Inputs](#inputs)
- [Outputs](#outputs)
- [Generated artifacts](#generated-artifacts)
- [Configuration file](#configuration-file)
- [Frameworks and tailoring](#frameworks-and-tailoring)
- [Recipes](#recipes)
- [Permissions and OIDC](#permissions-and-oidc)
- [Supply-chain integrity](#supply-chain-integrity)
- [Troubleshooting](#troubleshooting)
- [Links](#links)

---

## Coverage

### Providers

| Provider     | Authentication                                       | Checks |
| ------------ | ---------------------------------------------------- | -----: |
| DigitalOcean | `DO_API_TOKEN` (read scope is enough)                |    144 |
| AWS          | Standard SDK chain — env, profile, IMDSv2, or OIDC   |     30 |
| GCP          | Application Default Credentials or WIF               |     25 |
| Hetzner      | `HCLOUD_TOKEN` (project-scoped)                      |     15 |
| Kubernetes   | `~/.kube/config` chain — works for EKS, GKE, DOKS    |    241 |
| Linux        | SSH key (bastion supported)                          |    119 |

**Total: 574 checks**, every one framework-mapped and remediation-documented.
See the live [check catalog](https://github.com/darpanzope/compliancekit/blob/main/docs/checks.md)
for IDs, severities, and per-control mapping.

### Frameworks

| Framework                                  | Version                       | Coverage                                                                                       | Category     |
| ------------------------------------------ | ----------------------------- | ---------------------------------------------------------------------------------------------: | ------------ |
| SOC 2 TSC                                  | 2017 (2022 PoF)               | 60 (full CC1-CC9 + A + C + PI + P)                                                             | compliance   |
| ISO/IEC 27001 Annex A                      | 2022                          | 93 (org, people, physical, technological)                                                      | compliance   |
| CIS Controls v8                            | v8                            | 153 safeguards (IG1 / IG2 / IG3)                                                               | compliance   |
| CIS Linux Server Benchmark                 | v8                            | 90 sections × Level 1 / Level 2 (initial-setup, services, network, logging-auditing, access, sysmaint) | compliance   |
| NSA / CISA Kubernetes Hardening Guide      | v1.2 (Aug 2022)               | 30 controls × 5 chapters (pod-security, network, auth, logging, upgrading)                     | compliance   |
| NIST SP 800-53                             | r5                            | 131 controls (cloud + Linux subset across 14 families)                                         | compliance   |
| HIPAA Security Rule                        | 45 CFR §§164.308 / 310 / 312  | 50 implementation specs (required / addressable)                                               | compliance   |
| PCI DSS                                    | v4.0                          | 61 sub-requirements                                                                            | compliance   |
| MITRE ATT&CK Enterprise                    | v15 (2024)                    | 12 tactics + 50 techniques (cloud + Linux subset)                                              | threat model |

**668 controls** total across **9 frameworks**. Every check claims only the
controls it actually reaches — no aspirational mappings. Operators scope
individual controls out via [`tailoring:`](#frameworks-and-tailoring) with a
required written justification that flows through to the audit trail.

---

## Quick start

The minimum viable workflow scans one provider on every push, lets
`upload-sarif` post results to the **Security → Code Scanning** tab, and
fails the build on `high`-severity findings:

```yaml
# .github/workflows/compliance.yaml
name: compliance
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # required for SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: darpanzope/compliancekit-action@v2
        with:
          providers: digitalocean
          fail-on: high
        env:
          DO_API_TOKEN: ${{ secrets.DO_API_TOKEN }}
```

A fuller version with a configuration file, several providers, and an
evidence pack uploaded as an artifact:

```yaml
- uses: darpanzope/compliancekit-action@v2
  id: scan
  with:
    config-file: compliancekit.yaml
    evidence: true
    evidence-period: ${{ github.event.repository.updated_at }}
    fail-on: high
  env:
    DO_API_TOKEN:                   ${{ secrets.DO_API_TOKEN }}
    AWS_ACCESS_KEY_ID:              ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY:          ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    GOOGLE_APPLICATION_CREDENTIALS: ${{ secrets.GCP_SA_JSON_PATH }}
    HCLOUD_TOKEN:                   ${{ secrets.HCLOUD_TOKEN }}

- uses: actions/upload-artifact@v4
  with:
    name: compliance-evidence
    path: ${{ steps.scan.outputs.evidence-dir }}
```

---

## Inputs

| Input              | Default                  | Description                                                                                                       |
| ------------------ | ------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| `version`          | `latest`                 | compliancekit binary version (no leading `v`). `latest` resolves the highest published GitHub release at run time.|
| `providers`        | (all enabled in config)  | Comma-separated provider list — `digitalocean,aws,gcp,hetzner,kubernetes,linux`. Empty = obey the config file.    |
| `config-file`      | —                        | Path to a `compliancekit.yaml` relative to `$GITHUB_WORKSPACE`. Optional; env vars + defaults work without one.   |
| `inventory`        | —                        | Path to a Linux SSH inventory YAML. Consulted only when the `linux` provider runs.                                |
| `frameworks`       | (all 9)                  | Comma-separated framework filter — `soc2,iso27001,cis-v8,cis-linux-server,nsa-cisa-k8s,nist-800-53-r5,hipaa,pci-dss-v4,mitre-attack`. |
| `output`           | `sarif,markdown,json`    | Comma-separated formats. Available: `json`, `markdown`, `sarif`, `ocsf`, `html`. HTML reports embed per-format remediation snippets inline (v1.1+). |
| `out-dir`          | `./out`                  | Directory the scan writes into. Relative paths resolve under `$GITHUB_WORKSPACE`.                                 |
| `fail-on`          | `high`                   | Severity threshold for non-zero exit: `critical`, `high`, `medium`, `low`, `info`, or `never` to disable.         |
| `evidence`         | `false`                  | Produce an audit-ready evidence pack at `<out-dir>/evidence/` alongside the reports.                              |
| `evidence-period`  | (current calendar quarter) | Audit period label embedded in `evidence/`. Free-form (`2026-Q2`, `2026-H1`, etc.).                             |
| `upload-sarif`     | `true`                   | Auto-upload SARIF to GitHub Code Scanning. Requires `security-events: write` on the job.                          |
| `upload-evidence-pack` | `false`              | **v1.1+.** When `true` (and `evidence: true` produced a pack), uploads `evidence/` as a workflow artifact via `actions/upload-artifact@v4`. Off-by-default to keep small repos from silently retaining large packs. |
| `evidence-artifact-name` | `compliancekit-evidence-pack` | **v1.1+.** Name of the workflow artifact written when `upload-evidence-pack: true`. |
| `evidence-artifact-retention-days` | `0`            | **v1.1+.** Retention window (days) for the uploaded artifact. `0` = org/repo default. Max per GitHub: 90 (public repos), 400 (private/internal). |

## Outputs

| Output         | Description                                                                                       |
| -------------- | ------------------------------------------------------------------------------------------------- |
| `reports-dir`  | Absolute path to the scan output directory. Combine with `outputs/` to feed downstream steps.     |
| `evidence-dir` | Absolute path to the evidence pack. Empty string when `evidence: false`.                          |

Use them like:

```yaml
- uses: darpanzope/compliancekit-action@v2
  id: scan
  with:
    evidence: true

- run: ls -la "${{ steps.scan.outputs.reports-dir }}"
- run: zip -r evidence.zip "${{ steps.scan.outputs.evidence-dir }}"
```

---

## Generated artifacts

Every scan writes a deterministic tree under `out-dir`. The shape depends
on which `output:` formats and whether `evidence:` is enabled.

```
out/
├── findings.json            # canonical machine-readable record
├── findings.sarif           # SARIF 2.1.0 (Code Scanning ingestion)
├── findings.markdown        # filtered to actionable rows, ready for PR comments
├── findings.html            # standalone interactive viewer (optional)
├── findings.ocsf.json       # OCSF 1.3 event stream (optional)
└── evidence/                # only when evidence: true
    ├── summary.html         # auditor index page
    ├── control-mapping.csv  # Drata / Vanta / AuditBoard ingest
    ├── tailoring.json       # full scope-out decisions
    ├── MANIFEST.sha256      # tamper-evident hashlist
    └── controls/
        ├── soc2-CC6.1/
        │   ├── README.md
        │   ├── evidence.json
        │   └── findings.csv
        ├── iso27001-A.8.2/
        └── … (one folder per (framework, control) pair)
```

### Sample `findings.markdown`

```markdown
## compliancekit — 12 actionable findings · 0 critical · 4 high · 6 medium · 2 low

| Severity | Resource                          | Check                          | Frameworks                   |
|---------:|-----------------------------------|--------------------------------|------------------------------|
|   HIGH   | do/droplet/web-prod-3 (sfo3)      | droplet-public-ssh             | SOC 2 CC6.1; CIS 1.4         |
|   HIGH   | do/spaces/customer-backups        | spaces-bucket-public-read      | SOC 2 CC6.7; ISO A.5.10      |
|   MED    | k8s/Deployment/checkout/api       | pod-runs-as-root               | CIS-K8s 5.2.6; NIST AC-6     |
| …        | …                                 | …                              | …                            |

_Generated by compliancekit v1.0.0 · framework filter: soc2,iso27001,cis-v8_
```

### Sample `findings.sarif` (truncated)

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [{
    "tool": {
      "driver": {
        "name": "compliancekit",
        "version": "0.12.0",
        "rules": [{
          "id": "do.spaces.public_read",
          "shortDescription": { "text": "Spaces bucket allows public read" },
          "helpUri": "https://github.com/darpanzope/compliancekit/blob/main/docs/checks.md#dospacespublic_read"
        }]
      }
    },
    "results": [{
      "ruleId": "do.spaces.public_read",
      "level": "error",
      "message": { "text": "Bucket 'customer-backups' grants Read to AllUsers" },
      "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "do://spaces/sfo3/customer-backups" } } }]
    }]
  }]
}
```

---

## Configuration file

`compliancekit.yaml` lives in your repo. It enables providers, sets defaults,
and declares tailoring scope-outs. The action reads it via `config-file:`.

```yaml
# compliancekit.yaml
project: acme-saas
environment: prod

providers:
  digitalocean:
    enabled: true
    token_env: DO_API_TOKEN

  aws:
    enabled: true
    regions: []          # empty = every region visible to the credential

  gcp:
    enabled: true
    projects: []         # empty = credential's default project

  kubernetes:
    enabled: true        # auth via standard kubeconfig chain

# Limit the report to the frameworks you actually plan to certify against.
frameworks:
  - soc2
  - iso27001
  - cis-v8

# Severity gate; matches the action input `fail-on:`.
fail_on: high
```

Full schema reference:
[CONFIGURATION.md](https://github.com/darpanzope/compliancekit/blob/main/CONFIGURATION.md).
Per-provider quickstarts live in
[examples/](https://github.com/darpanzope/compliancekit/tree/main/examples).

---

## Frameworks and tailoring

Pick which frameworks render in your report with the `frameworks:` input:

```yaml
- uses: darpanzope/compliancekit-action@v2
  with:
    frameworks: soc2,iso27001,nist-800-53-r5
```

Valid IDs: `soc2`, `iso27001`, `cis-v8`, `nist-800-53-r5`, `hipaa`,
`pci-dss-v4`, `mitre-attack`.

### Tailoring (scope-outs with audit trail)

When a control is genuinely not applicable to your environment, declare it in
`compliancekit.yaml` with a written justification — the evidence pack carries
the reason through to the auditor view.

```yaml
tailoring:
  - framework: pci-dss-v4
    control: "10.6.1"
    justification: |
      Out of scope — we do not store, process, or transmit Primary Account
      Numbers (PAN). All payments are tokenized via Stripe Connect; no
      Cardholder Data Environment exists.

  - framework: soc2
    control: P1.1
    justification: |
      Not committed in our SOC 2 report; current audit covers Security and
      Availability only. Revisit if Privacy is added.
```

The pack records every scope-out in:

- `tailoring.json` (machine-readable, at pack root)
- `control-mapping.csv` (new `tailored` + `tailoring_justification` columns)
- `summary.html` (dedicated card + per-row inline justification)

A real-shaped example with several frameworks lives at
[`examples/quickstart-tailoring.yaml`](https://github.com/darpanzope/compliancekit/blob/main/examples/quickstart-tailoring.yaml).

---

## Recipes

<details>
<summary><strong>1. Comment the finding summary on every pull request</strong></summary>

Drop a sticky comment so reviewers see what changed without leaving the PR.

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: darpanzope/compliancekit-action@v2
        id: scan
        with:
          providers: aws,kubernetes
          output: markdown,sarif,json
          fail-on: medium

      - uses: marocchino/sticky-pull-request-comment@v2
        if: github.event_name == 'pull_request'
        with:
          path: ${{ steps.scan.outputs.reports-dir }}/findings.markdown
          header: compliancekit
```

`findings.markdown` is filtered to actionable findings — pass and skip rows
are dropped so the PR comment stays readable.

> **v1.1 behavior change.** Multi-provider input (`providers: a,b,c`) now
> actually loops every provider. Pre-v1.1 silently scanned only the first
> entry. Workflows pinning `@v1` pick up the fix on next run — re-check
> findings counts if you relied on the old behavior.
</details>

<details>
<summary><strong>2. Authenticate to AWS with OIDC (no static keys)</strong></summary>

This is the recommended pattern. Configure an IAM role with the
GitHub Actions OIDC trust policy, then exchange the workflow's identity
token for short-lived AWS credentials — no `AWS_ACCESS_KEY_ID` secret
ever lives in your repo.

```yaml
permissions:
  id-token: write          # required for OIDC
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/compliancekit-readonly
          aws-region: us-east-1

      - uses: darpanzope/compliancekit-action@v2
        with:
          providers: aws
          fail-on: high
```

The role only needs read-equivalent scope. A starter trust + permissions
policy ships in [docs/aws-iam.md](https://github.com/darpanzope/compliancekit/blob/main/docs/aws-iam.md).
</details>

<details>
<summary><strong>3. Authenticate to GCP via Workload Identity Federation</strong></summary>

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - id: gcp-auth
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: projects/123/locations/global/workloadIdentityPools/github/providers/repo
          service_account: compliancekit-readonly@my-project.iam.gserviceaccount.com

      - uses: darpanzope/compliancekit-action@v2
        with:
          providers: gcp
          fail-on: high
        env:
          GOOGLE_APPLICATION_CREDENTIALS: ${{ steps.gcp-auth.outputs.credentials_file_path }}
```
</details>

<details>
<summary><strong>4. Scan a Kubernetes cluster (EKS / GKE / DOKS / kind)</strong></summary>

compliancekit uses the standard kubeconfig chain. Pair `providers: kubernetes`
with the underlying cloud provider to light up enrichment checks (public
endpoint, secrets-at-rest KMS, Workload Identity, HA control plane,
auto-upgrade, etc.).

```yaml
jobs:
  scan-eks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/compliancekit-readonly
          aws-region: us-east-1

      - run: aws eks update-kubeconfig --name prod --region us-east-1

      - uses: darpanzope/compliancekit-action@v2
        with:
          providers: aws,kubernetes
          fail-on: high
```

For DOKS, replace the EKS step with
`doctl kubernetes cluster kubeconfig save <cluster>`; for GKE use
`gcloud container clusters get-credentials …`.
</details>

<details>
<summary><strong>5. Quarterly evidence pack as a release artifact</strong></summary>

A scheduled run that captures evidence on the first of every quarter,
uploads the pack as a build artifact, and attaches the SHA-256 manifest to
a GitHub Release. `fail-on: never` keeps the workflow green so the artifact
always uploads, even when findings exist.

```yaml
name: evidence
on:
  schedule: [{ cron: '0 6 1 1,4,7,10 *' }]   # 06:00 UTC on Jan 1, Apr 1, Jul 1, Oct 1
  workflow_dispatch:

permissions:
  contents: write          # publish the release
  security-events: write

jobs:
  pack:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: darpanzope/compliancekit-action@v2
        id: scan
        with:
          config-file: compliancekit.yaml
          evidence: true
          evidence-period: ${{ github.run_id }}
          fail-on: never
        env:
          DO_API_TOKEN:    ${{ secrets.DO_API_TOKEN }}
          HCLOUD_TOKEN:    ${{ secrets.HCLOUD_TOKEN }}

      - uses: actions/upload-artifact@v4
        with:
          name: evidence-${{ github.run_id }}
          path: ${{ steps.scan.outputs.evidence-dir }}
          retention-days: 365
```
</details>

<details>
<summary><strong>6. Slack alert on critical findings only</strong></summary>

```yaml
- uses: darpanzope/compliancekit-action@v2
  id: scan
  with:
    providers: aws
    fail-on: never              # we'll gate ourselves
    output: json,markdown,sarif

- name: Count critical findings
  id: count
  run: |
    crit=$(jq '[.findings[] | select(.severity=="critical")] | length' \
      "${{ steps.scan.outputs.reports-dir }}/findings.json")
    echo "count=$crit" >> "$GITHUB_OUTPUT"

- uses: slackapi/slack-github-action@v1
  if: steps.count.outputs.count != '0'
  with:
    payload: |
      {
        "text": ":rotating_light: compliancekit found ${{ steps.count.outputs.count }} CRITICAL findings on ${{ github.repository }}",
        "blocks": [{
          "type": "section",
          "text": { "type": "mrkdwn", "text": "<${{ github.server_url }}/${{ github.repository }}/security/code-scanning|Open Code Scanning →>" }
        }]
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
    SLACK_WEBHOOK_TYPE: INCOMING_WEBHOOK
```
</details>

<details>
<summary><strong>7. Matrix scan across multiple cloud accounts</strong></summary>

Useful when you operate per-environment AWS accounts (prod, staging, dev)
or several DigitalOcean teams. Each cell gets its own runner, its own
secrets, its own report — and GitHub renders them as parallel checks on
the PR.

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        env:
          - { name: prod,    aws_role: prod-readonly,    do_secret: DO_TOKEN_PROD }
          - { name: staging, aws_role: staging-readonly, do_secret: DO_TOKEN_STAGING }

    permissions:
      contents: read
      id-token: write
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/${{ matrix.env.aws_role }}
          aws-region: us-east-1

      - uses: darpanzope/compliancekit-action@v2
        with:
          providers: aws,digitalocean
          out-dir: ./out-${{ matrix.env.name }}
          fail-on: high
        env:
          DO_API_TOKEN: ${{ secrets[matrix.env.do_secret] }}
```
</details>

<details>
<summary><strong>8. Pin a specific version and verify the binary signature</strong></summary>

For reproducible scans (e.g. inside a regulated CI pipeline), pin the
version and verify the release signature in a preceding step.

```yaml
- uses: sigstore/cosign-installer@v3

- name: Verify compliancekit release
  run: |
    ver=0.12.0
    base=https://github.com/darpanzope/compliancekit/releases/download/v${ver}
    curl -sSfL -O ${base}/checksums.txt
    curl -sSfL -O ${base}/checksums.txt.sig
    curl -sSfL -O ${base}/checksums.txt.pem
    cosign verify-blob \
      --certificate-identity-regexp 'https://github.com/darpanzope/compliancekit' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate checksums.txt.pem \
      --signature checksums.txt.sig \
      checksums.txt

- uses: darpanzope/compliancekit-action@v2
  with:
    version: 0.12.0
    fail-on: high
```

You can also pin the action ref itself to a commit SHA
(`darpanzope/compliancekit-action@<40-char-sha>`) for strictest reproducibility.
</details>

---

## Permissions and OIDC

Most workflows want:

```yaml
permissions:
  contents: read           # actions/checkout
  security-events: write   # SARIF upload to Code Scanning
  id-token: write          # OIDC exchange for cloud auth (recipes 2 + 3)
  pull-requests: write     # PR-comment recipe
```

If you set `upload-sarif: false`, drop `security-events: write`.
If you do not use OIDC, drop `id-token: write`.

GitHub's `GITHUB_TOKEN` permissions are scoped per job and never escalate;
[see GitHub's reference](https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs).

---

## Supply-chain integrity

Every compliancekit release is:

- **Cosign-signed** (Sigstore Fulcio keyless, GitHub OIDC). `checksums.txt.sig`
  and `checksums.txt.pem` ship next to every artifact.
- **SBOM-attested** per platform via Syft (CycloneDX JSON).
- **Multi-arch Docker image** at `ghcr.io/darpanzope/compliancekit:<version>`,
  manifest cosign-signed for both `linux/amd64` and `linux/arm64`.
- **Reproducibly built** — `CGO_ENABLED=0`, `-trimpath`, ldflags pin the
  source commit and build date. Two builds of the same tag from the same
  commit produce byte-identical binaries.

The action itself runs as a [composite action](./action.yaml). It downloads
the prebuilt binary for the runner's OS/arch, verifies the SHA-256 against
`checksums.txt`, and installs to `/usr/local/bin/compliancekit`. No Docker
image is pulled inside the action.

Verify a release manually:

```sh
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/darpanzope/compliancekit' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  checksums.txt
```

---

## Troubleshooting

<details>
<summary><strong>SARIF upload fails with “Resource not accessible by integration”</strong></summary>

The job is missing `security-events: write`. Add it to your `permissions:`
block, or set `upload-sarif: false` if you do not want Code Scanning ingestion.
</details>

<details>
<summary><strong>“no credentials found” when scanning AWS / GCP</strong></summary>

The provider SDK couldn't find credentials. Either:

- Pass them via env (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`, or
  `GOOGLE_APPLICATION_CREDENTIALS` pointing at a service-account JSON).
- Or use OIDC with `aws-actions/configure-aws-credentials@v4` or
  `google-github-actions/auth@v2` before the compliancekit step (see
  recipes 2 and 3).
</details>

<details>
<summary><strong>Kubernetes provider sees zero resources</strong></summary>

The runner has no kubeconfig. Run your cluster's kubeconfig step first
(`aws eks update-kubeconfig`, `gcloud container clusters get-credentials`,
`doctl kubernetes cluster kubeconfig save`, …) so `~/.kube/config` exists
before the compliancekit step.
</details>

<details>
<summary><strong>Action fails with checksum mismatch</strong></summary>

Either the GitHub release was edited (rare; report it), or you pinned a
`version:` that does not exist. Run with `version: latest` once to
confirm, then pin to a real tag.
</details>

<details>
<summary><strong>The job is non-zero but I want to upload artifacts anyway</strong></summary>

Add `if: always()` to the upload step. compliancekit writes every artifact
to disk before propagating the non-zero exit, so the files are present even
on a failed gate:

```yaml
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: compliance
    path: ${{ steps.scan.outputs.reports-dir }}
```
</details>

<details>
<summary><strong>Markdown PR comment is too large</strong></summary>

Lower the scope: tighten `frameworks:` (e.g. only `soc2`), or run the
comment-style workflow with `fail-on: medium` and a stricter `providers:`
list. The Markdown output is already pre-filtered to actionable findings
(pass / skip rows are dropped).
</details>

---

## Links

- Source and binary: <https://github.com/darpanzope/compliancekit>
- Getting started: [GETTING_STARTED.md](https://github.com/darpanzope/compliancekit/blob/main/GETTING_STARTED.md)
- Configuration reference: [CONFIGURATION.md](https://github.com/darpanzope/compliancekit/blob/main/CONFIGURATION.md)
- CLI reference: [CLI.md](https://github.com/darpanzope/compliancekit/blob/main/CLI.md)
- Check catalog: [docs/checks.md](https://github.com/darpanzope/compliancekit/blob/main/docs/checks.md)
- Roadmap: [ROADMAP.md](https://github.com/darpanzope/compliancekit/blob/main/ROADMAP.md)
- Architecture: [ARCHITECTURE.md](https://github.com/darpanzope/compliancekit/blob/main/ARCHITECTURE.md)
- Examples: [examples/](https://github.com/darpanzope/compliancekit/tree/main/examples)
- Issues: <https://github.com/darpanzope/compliancekit/issues>

## License

[MIT](https://github.com/darpanzope/compliancekit/blob/main/LICENSE) — same as
compliancekit itself. No warranty, no telemetry, no SaaS lock-in.
