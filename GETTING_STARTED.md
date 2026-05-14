# Getting started with compliancekit

A 10-minute end-to-end walk-through: install → set a token → first scan → evidence pack.

If you're in a hurry, the [README §Quickstart](README.md#quickstart) is the
60-second version. This doc is the long form with the gotchas called out.

## 1. Install

Pick the path that matches your environment:

| Path | Command |
|---|---|
| macOS (Homebrew) | `brew install darpanzope/tap/compliancekit` |
| Linux / macOS (script) | `curl -sSfL https://raw.githubusercontent.com/darpanzope/compliancekit/main/scripts/install.sh \| sh` |
| Go | `go install github.com/darpanzope/compliancekit/cmd/compliancekit@latest` |
| Docker | `docker run --rm -v $PWD:/work ghcr.io/darpanzope/compliancekit:latest scan` |

Verify:

```sh
compliancekit version
# compliancekit 0.10.0 (commit ..., built ...)
```

If you want to verify the supply chain, see the [cosign block in the README](README.md#install).

## 2. Pick your provider

| Cloud | Auth method | Walk-through |
|---|---|---|
| DigitalOcean | `DO_API_TOKEN` env var | [§DigitalOcean](#digitalocean) |
| AWS | Standard SDK chain (env / profile / IMDSv2 / OIDC) | [§AWS](#aws) |
| GCP | Application Default Credentials | [§GCP](#gcp) |
| Hetzner Cloud | `HCLOUD_TOKEN` env var | [§Hetzner](#hetzner) |
| Kubernetes | `~/.kube/config` chain (works with EKS / GKE / DOKS / kind / etc.) | [§Kubernetes](#kubernetes) |
| Linux fleet (via SSH) | Inventory file + SSH key | [§Linux](#linux-over-ssh) |

Each provider section below assumes you've installed the binary and works
standalone — start with whichever cloud you actually use.

---

### DigitalOcean

**1. Get a token.** Go to
<https://cloud.digitalocean.com/account/api/tokens>, create a personal
access token with **read scope** (compliancekit only reads — never grant
write). Copy it; you won't see it again.

**2. Set it in your shell:**

```sh
export DO_API_TOKEN=dop_v1_xxxxxxxxxxxx
```

**3. Grab the minimal config:**

```sh
curl -O https://raw.githubusercontent.com/darpanzope/compliancekit/main/examples/quickstart-do.yaml
mv quickstart-do.yaml compliancekit.yaml
```

Or paste this into `compliancekit.yaml`:

```yaml
providers:
  digitalocean:
    enabled: true
    token_env: DO_API_TOKEN
frameworks: [soc2, iso27001, cis-v8]
severity: { fail_on: high, min_report: info }
output: { format: [json, html, markdown], out_dir: ./out }
```

**4. Confirm auth works:**

```sh
compliancekit doctor
```

Expected:

```
✓ config: loaded from compliancekit.yaml
✓ severity: fail_on=high, min_report=info
✓ frameworks: soc2, iso27001, cis-v8
✓ output: format=json,html,markdown, evidence=false, out_dir=./out
✓ providers.digitalocean: DO_API_TOKEN resolved (token length: 71)
✓ providers.digitalocean: API reachable (631ms)
```

If you see `env var DO_API_TOKEN is unset`, the export didn't take in
this shell — set it again. If you see `401 Unauthorized`, the token is
wrong or expired.

**5. Run the scan:**

```sh
compliancekit scan digitalocean
```

Expected (numbers depend on your account):

```
scanning digitalocean (298 checks)...
wrote ./out/findings.json
wrote ./out/findings.html
wrote ./out/findings.markdown

592 findings (23 critical, 164 high, 190 medium, 215 low)
Hardening score: 67/100 (coverage 100%)
findings at or above high severity present
```

Open `out/findings.html` in your browser — search/filter, dark mode, drill
into any finding. `out/findings.json` is the machine-readable shape your
CI consumes. `out/findings.markdown` is the human-readable summary.

---

### AWS

**1. Pick an auth source.** Any of these works (in order of preference):

| Source | When | How |
|---|---|---|
| GitHub OIDC | CI | Configure an IAM role with OIDC trust; the GitHub Action handles it |
| EC2 IMDSv2 | Running on EC2 | Attach an IAM role to the instance |
| AWS_PROFILE | Laptop | `~/.aws/credentials` + `export AWS_PROFILE=myprofile` |
| AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY | Laptop, last resort | `export AWS_ACCESS_KEY_ID=...; export AWS_SECRET_ACCESS_KEY=...` |

Narrow the principal to `ReadOnlyAccess` or a custom least-privilege
policy (compliancekit calls `Describe*` / `List*` / `Get*` only — never
mutates).

**2. Grab the config:**

```sh
curl -O https://raw.githubusercontent.com/darpanzope/compliancekit/main/examples/quickstart-aws.yaml
mv quickstart-aws.yaml compliancekit.yaml
```

**3. Confirm + scan:**

```sh
compliancekit doctor
compliancekit scan aws
```

`regions: []` (empty in the example) means "every region visible to the
credential" — resolved at scan time via EC2 `DescribeRegions`. To narrow:

```yaml
providers:
  aws:
    enabled: true
    regions: [us-east-1, us-west-2]
```

Cross-account scanning: set `role_arn:` to the role to assume after
loading base credentials. Or use the AWS organization-style approach of
multiple scans with different profiles.

---

### GCP

**1. Set up Application Default Credentials.** Easiest on a laptop:

```sh
gcloud auth application-default login
```

In CI, prefer Workload Identity Federation (no long-lived service-account
keys). For a service account key file:

```sh
export GOOGLE_APPLICATION_CREDENTIALS=$HOME/path/to/sa-key.json
```

Narrow the SA to `roles/viewer` plus any service-specific reader roles
your fleet uses.

**2. Grab the config:**

```sh
curl -O https://raw.githubusercontent.com/darpanzope/compliancekit/main/examples/quickstart-gcp.yaml
mv quickstart-gcp.yaml compliancekit.yaml
```

**3. Confirm + scan:**

```sh
compliancekit doctor
compliancekit scan gcp
```

`projects: []` uses the credential's default project. For multi-project
scans, list them explicitly:

```yaml
providers:
  gcp:
    enabled: true
    projects: [my-prod, my-staging, my-dev]
```

Per-project errors emit `gcp.collect_error` placeholders rather than
aborting the scan; partial data still ships.

---

### Hetzner

**1. Get a token.** Go to
`https://console.hetzner.cloud/projects/<your-project>/security/tokens`,
create a token with **Read scope**. One token = one project — Hetzner
has no multi-project API surface.

**2. Set it:**

```sh
export HCLOUD_TOKEN=hcloud-xxxxxxxxxxxx
```

**3. Grab the config + scan:**

```sh
curl -O https://raw.githubusercontent.com/darpanzope/compliancekit/main/examples/quickstart-hetzner.yaml
mv quickstart-hetzner.yaml compliancekit.yaml
compliancekit doctor
compliancekit scan hetzner
```

Multi-project: keep a separate `compliancekit.yaml` per project (with
different `HCLOUD_TOKEN` exports), or run multiple scans with
`--config` pointing at different files.

---

### Kubernetes

**1. You already have credentials.** compliancekit uses the standard
kubeconfig chain — `kubectl` works, compliancekit works. EKS, GKE,
DOKS, kind, k3s, on-prem — all reachable through the same path.

```sh
kubectl config current-context        # confirms which cluster you'll scan
```

**2. Grab the config + scan:**

```sh
curl -O https://raw.githubusercontent.com/darpanzope/compliancekit/main/examples/quickstart-k8s.yaml
mv quickstart-k8s.yaml compliancekit.yaml
compliancekit doctor                  # confirms the kubeconfig context resolves
compliancekit scan kubernetes
```

You'll get the **139 K8s checks** (95 generic Kubernetes + EKS/GKE/DOKS
enrichment) across every workload, RBAC binding, NetworkPolicy,
Secret, namespace, and node in the cluster.

**Multi-cluster:** list contexts explicitly under
`providers.kubernetes.contexts:` to scan many clusters in one pass.

**Cloud enrichment:** to get the EKS / GKE / DOKS posture checks
(public endpoint, secrets KMS, Workload Identity, HA control plane,
auto-upgrade, etc.) firing alongside the generic K8s checks, also
enable the matching cloud provider in the same config — for example
`digitalocean` for DOKS, `aws` for EKS, `gcp` for GKE. The cloud
collector discovers the cluster's cloud-side configuration; the K8s
collector reads what's inside.

**Noisy namespaces:** the quickstart excludes `kube-system`,
`kube-public`, and `kube-node-lease` by default. Drop these from
`exclude_namespaces:` if you want to scan platform components too —
expect a wave of pod-security findings on managed addons.

---

### Linux over SSH

The Linux provider scans your droplet/EC2/server fleet over SSH — no
agents installed. Needs an inventory file describing the hosts:

```yaml
# examples/inventory.yaml (a sample lives in this repo)
groups:
  prod:
    hosts:
      - host: web1.example.com
        user: ops
      - host: web2.example.com
        user: ops
```

Then in `compliancekit.yaml`:

```yaml
providers:
  linux:
    enabled: true
    inventory: ./inventory.yaml
    ssh:
      user: ops
      key_file: ~/.ssh/id_ed25519
      max_parallel: 16
```

`compliancekit scan linux` walks every host in parallel and emits one
resource per check per host. Use `ssh-agent` (`SSH_AUTH_SOCK`) or
specify `key_file` per inventory entry.

## 3. Read the findings

`out/findings.json` is the source of truth. Three reporter renders make
it easier to read:

| File | Best for |
|---|---|
| `findings.html` | Human review — dark mode, search, filter |
| `findings.markdown` | PR comments, Slack messages, code reviews |
| `findings.json` | Programmatic ingest, CI gates, evidence pack |

Inspect by check ID:

```sh
jq '.findings[] | select(.check_id == "do-firewall-ssh-from-any")' out/findings.json
```

Inspect by severity:

```sh
jq '.findings[] | select(.severity == "critical" and .status == "fail") | .message' out/findings.json
```

Inspect by resource:

```sh
jq '.findings[] | select(.resource.id == "digitalocean.droplet.123456")' out/findings.json
```

## 4. Generate an evidence pack

For auditors:

```sh
compliancekit evidence \
  --in out/findings.json \
  --out evidence/2026-Q2/ \
  --period 2026-Q2

open evidence/2026-Q2/summary.html
```

The pack contains:
- Per-framework, per-control folders (`cis-v8/`, `iso27001/`, `soc2/`)
- `control-mapping.csv` — importable into Drata / Vanta / AuditBoard
- `summary.html` — single-file auditor index
- `MANIFEST.sha256` — tamper-evidence (`sha256sum -c MANIFEST.sha256`)

Sensitive tokens (AWS keys, GitHub PATs, Slack tokens, bearer headers,
email addresses) are **redacted by default** in finding messages. For
auditor-trusted distribution where redaction is unwanted, pass
`--include-raw`.

## 5. Run it in CI

GitHub Actions:

```yaml
# .github/workflows/compliance.yaml
name: compliance
on: [push, pull_request, schedule]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # for OIDC (AWS, GCP)
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: darpanzope/compliancekit-action@v1
        with:
          providers: digitalocean,aws,gcp
        env:
          DO_API_TOKEN: ${{ secrets.DO_API_TOKEN }}
          AWS_ROLE_ARN: arn:aws:iam::123456789012:role/ScannerRole
          # GCP via Workload Identity Federation
```

The action returns exit code 2 if any finding meets or exceeds the
configured `fail_on` severity, which fails the workflow step — gate PR
merges on it.

## 6. Where to go next

- **[CLI.md](CLI.md)** — full command reference (every subcommand,
  flag, exit code).
- **[CONFIGURATION.md](CONFIGURATION.md)** — every config field, default,
  and env-var override.
- **[CHECKS.md](CHECKS.md)** — how a check is structured, how to author
  one (Go for now; Rego coming at v0.16).
- **[docs/checks.md](docs/checks.md)** — auto-generated per-check
  reference: IDs, severities, framework mappings, remediation.
- **[ROADMAP.md](ROADMAP.md)** — what's shipping next; v0.12
  (NIST 800-53 r5 + HIPAA + PCI-DSS v4 + MITRE ATT&CK framework
  expansion) is the current target. Kubernetes shipped at v0.11.

If something in this guide is wrong or unclear, that's a bug — please
[open an issue](https://github.com/darpanzope/compliancekit/issues/new)
or send a PR.
