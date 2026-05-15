# Configuration

compliancekit is configured through four sources, in increasing precedence:

1. Built-in defaults
2. `compliancekit.yaml` file
3. Environment variables (`COMPLIANCEKIT_*`)
4. CLI flags

Later sources override earlier ones. A flag always wins.

## File location lookup

`compliancekit scan` looks for the config file in:

1. `--config=<path>` (explicit flag)
2. `./compliancekit.yaml`
3. `$XDG_CONFIG_HOME/compliancekit/config.yaml`
4. `~/.compliancekit/config.yaml`

First hit wins. No file is required for `compliancekit scan digitalocean` — env vars and flags are sufficient.

## Full schema

```yaml
# compliancekit.yaml

project: acme-saas              # string, optional. Appears in evidence pack metadata.
environment: prod               # string, optional. e.g. "prod" | "staging" | "dev".

providers:                      # object, required. At least one provider must be enabled.

  digitalocean:
    enabled: true               # bool, default false
    token_env: DO_API_TOKEN     # string. Name of env var holding the token. Never inline tokens.
    teams: [primary]            # array<string>, v0.6+. Multi-team scan.
    scope:
      include_tags: []          # array<string>. Only scan resources with these tags.
      exclude_tags: []
      include_regions: []       # array<string>. e.g. ["nyc3", "sfo3"].
      exclude_regions: []
      include_resources: []     # array<string>. Specific resource URNs.
      exclude_resources: []

  linux:                        # v0.2+
    enabled: true
    inventory: ./inventory.yaml # string, path to inventory file
    ssh:
      user: ops                 # default: $USER
      key_file: ~/.ssh/id_ed25519   # falls back to SSH agent if absent
      port: 22
      timeout: 10s
      max_parallel: 16          # bounded concurrency
      strict_host_key: true     # if false, accepts unknown host keys (insecure)
      bastion:                  # optional jump host
        host: bastion.acme.com
        user: ops
        port: 22

  aws:                          # v0.7+
    enabled: false
    # Authentication uses the standard SDK chain (env vars,
    # AWS_PROFILE, AWS_ROLE_ARN, IMDSv2, OIDC). Nothing to configure
    # here for auth. The fields below narrow the scan only.
    regions: []                 # array<string>, e.g. ["us-east-1", "us-west-2"].
                                # Empty = all regions visible to the credential
                                # (resolved via EC2 DescribeRegions; opt-in
                                # regions that aren't enabled are filtered out).
    profile: ""                 # optional. Overrides AWS_PROFILE.
    role_arn: ""                # optional. Equivalent to AWS_ROLE_ARN
                                # (assume-role for cross-account scanning).

  gcp:                          # v0.8+
    enabled: false
    # Authentication uses Application Default Credentials:
    #   GOOGLE_APPLICATION_CREDENTIALS pointing at a service-account
    #   JSON, gcloud user creds, GCE/GKE metadata server, or Workload
    #   Identity Federation. Nothing to configure here for auth.
    projects: []                # array<string>. Empty = use the
                                # credential's default project. Unknown
                                # project IDs become per-project
                                # gcp.collect_error placeholders rather
                                # than aborting the whole scan.

  kubernetes:                   # v0.11+
    enabled: false
    # Auth uses the standard kubeconfig chain:
    #   1. `kubeconfig` field below (explicit path), or
    #   2. KUBECONFIG env var, or
    #   3. ~/.kube/config (default).
    # Each scanned context's in-cluster credentials are loaded via
    # client-go's standard chain; no extra credentials live in this
    # config. AccountID = kubeconfig context name; Region = parsed
    # API server host.
    kubeconfig: ~/.kube/config
    contexts: []                # array<string>, default: current-context.
                                # List multiple to scan many clusters
                                # in one pass.
    namespaces: []              # array<string>, default: all namespaces
                                # subject to exclude_namespaces below.
    exclude_namespaces: []      # array<string>, strips matching
                                # namespaces after `namespaces` is
                                # applied. Useful for skipping
                                # platform namespaces (e.g. kube-system,
                                # kube-public, kube-node-lease).

  hetzner:                      # v0.10+
    enabled: false
    token_env: HCLOUD_TOKEN

frameworks:                     # array<string>, default ["soc2", "cis-v8"]
  - soc2                        # SOC 2 TSC (2017 with 2022 PoF) — 60 controls
  - iso27001                    # ISO/IEC 27001:2022 Annex A — 93 controls
  - cis-v8                      # CIS Controls v8 — 153 safeguards (IG1/IG2/IG3)
  - nist-800-53-r5              # v0.12+. NIST SP 800-53 r5 — 131 controls (cloud + Linux subset)
  - hipaa                       # v0.12+. HIPAA Security Rule §§164.308/310/312 — 50 specs
  - pci-dss-v4                  # v0.12+. PCI DSS v4.0 — 61 sub-requirements
  - mitre-attack                # v0.12+. MITRE ATT&CK Enterprise — kill-chain threat model

# v0.12+. Tailoring lets an operator scope individual (framework,
# control) pairs out of audit, with a required written justification.
# The justification flows into evidence/tailoring.json + a column in
# evidence/control-mapping.csv + the summary.html header card so the
# auditor sees every scope-out decision with its reason.
tailoring:                      # v0.12+
  - framework: pci-dss-v4
    control: "10.6.1"
    justification: |
      Out of scope — we do not store, process, or transmit
      Primary Account Numbers (PAN). All payments are tokenized
      via Stripe Connect; CDE does not exist in our environment.
  - framework: soc2
    control: P1.1
    justification: |
      Privacy commitment not yet declared in our SOC 2 report.
      Pre-audit; revisit at next audit window.

# v0.13+. Pull in external tool output during scan. Each entry is
# decoded by its `format` adapter and its findings merge into the
# native scan result before reports / evidence pack are written.
#
# Supported formats:
#   sarif           — SARIF 2.1.0 (Trivy / Checkov / KICS / Terrascan / CodeQL / Semgrep)
#   ocsf            — OCSF 1.x (AWS Security Hub / GCP SCC / Defender)
#   oscal-catalog   — OSCAL Catalog v1.x (registers as a runtime framework)
#   trivy-json      — v0.14+ Trivy native JSON (per-package CVE/PURL/CVSS detail)
#   grype-json      — v0.14+ Grype native JSON (alternate vuln scanner)
#   checkov-json    — v0.14+ Checkov native JSON (richer than SARIF)
#   gitleaks-json   — v0.14+ gitleaks native JSON (auto-redacted secrets, ADR-010)
#
# v0.14+ adds an image-SHA correlation pass: when a Trivy/Grype
# image scan reports a CVE on container-image://<sha256> and a
# K8s/DO/ECS resource in the live graph references that SHA, the
# finding is cloned onto the running instance with a "running-on"
# tag so the same CVE appears under both the image and its
# consumers in the evidence pack.
ingest:                         # v0.13+
  - format: trivy-json
    file: ./out/trivy.json      # path relative to working dir
    tool: trivy                 # provenance tag on every produced Finding
    tool_version: v0.50.4       # optional, propagates to vulnerabilities.csv
  - format: grype-json
    file: ./out/grype.json
    tool: grype
  - format: gitleaks-json
    file: ./out/gitleaks.json
    tool: gitleaks
  # SARIF / OCSF / OSCAL Catalog also supported — see v0.13 examples.

profile: ci-fast                # v0.6+. names a key under `profiles:` below.

# Named subsets of the check catalog. Selectors are AND-composed
# when populated; empty selectors are no-ops. include_ids is the
# escape hatch and short-circuits the other include_* selectors.
profiles:                       # v0.6+
  ci-fast:
    description: Fast PR-time sanity scan
    include_severities: [critical, high]
  pre-audit:
    description: Comprehensive pre-audit scan
    include_frameworks: [soc2, iso27001]
  cis-only:
    description: CIS Controls v8 alignment only
    include_frameworks: [cis-v8]
  do-only:
    include_providers: [digitalocean]
  custom:
    include_ids:
      - do-droplet-no-firewall
      - linux-sshd-no-root-login
    exclude_tags: [experimental]

severity:
  fail_on: high                 # exit non-zero if any finding at this severity or above
  min_report: info              # don't include findings below this

output:
  format: [json, html]          # any of: json, json-ocsf, html, markdown, sarif
  out_dir: ./out
  evidence: true                # write the evidence pack to <out_dir>/evidence/
  include_raw: false            # if true, evidence pack includes unredacted API responses
  redaction: default            # default | none | strict

state:
  dir: .compliancekit           # state directory
  backend: file                 # file (default) | sqlite (v1.1+) | postgres (v1.1+)
  retention_days: 90            # how long to keep historical scans

waivers:                        # v0.15+
  file: ./waivers.yaml

notify:                         # v0.14+
  slack:
    webhook_env: SLACK_WEBHOOK
    on: [new_high, new_critical]
  webhook:
    url: https://hooks.example.com/compliancekit
    headers:
      X-Token-Env: WEBHOOK_TOKEN

server:                         # v1.1+, only used by `compliancekit serve`
  listen: 0.0.0.0:8080
  base_url: https://compliance.acme.com
  auth:
    mode: oidc                  # none | local | oidc
    oidc:
      issuer: https://accounts.example.com
      client_id: compliancekit
```

## inventory.yaml — for the linux provider (v0.2+)

```yaml
groups:
  web:
    hosts:
      - host: web-01.acme.com
      - host: web-02.acme.com
        user: ubuntu             # per-host override
        port: 2222
  db:
    hosts:
      - host: db-01.acme.com
        ssh:
          key_file: ~/.ssh/db_key

hosts:                            # ungrouped hosts
  - host: bastion.acme.com
    tags: [prod, jump]
```

Inventory files can be split across multiple files via `include: [other-inventory.yaml]` (v0.6+).

## Environment variables

Any config field is overridable via `COMPLIANCEKIT_<UPPER_SNAKE_PATH>`. Nested fields use `_` as separator:

| Env var | Overrides |
|---|---|
| `COMPLIANCEKIT_PROJECT` | `project` |
| `COMPLIANCEKIT_ENVIRONMENT` | `environment` |
| `COMPLIANCEKIT_OUTPUT_OUT_DIR` | `output.out_dir` |
| `COMPLIANCEKIT_SEVERITY_FAIL_ON` | `severity.fail_on` |
| `COMPLIANCEKIT_PROVIDERS_DIGITALOCEAN_ENABLED` | `providers.digitalocean.enabled` |

Plus the well-known external env vars:

| Env var | Purpose |
|---|---|
| `DO_API_TOKEN` | DigitalOcean API token (name configurable via `providers.digitalocean.token_env`) |
| `HCLOUD_TOKEN` | Hetzner Cloud token (v0.10+) |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | AWS credentials (v0.7+, standard SDK chain) |
| `AWS_PROFILE` | AWS profile name from `~/.aws/credentials` (v0.7+) |
| `AWS_ROLE_ARN` | AWS role to assume after loading base credentials (v0.7+) |
| `GOOGLE_APPLICATION_CREDENTIALS` | GCP service account JSON path (v0.8+) |
| `SLACK_WEBHOOK` | Slack notify webhook (v0.17+) |
| `SSH_AUTH_SOCK` | SSH agent socket (standard) |

## Secrets

Secrets must not appear inline in config. Two supported sources at v0.1:

1. **Environment variable** — referenced by name: `token_env: DO_API_TOKEN`.
2. **File path** — for SSH keys: `key_file: ~/.ssh/id_ed25519`.

Future (v1.x):

- HashiCorp Vault (`token_source: vault://...`)
- AWS Secrets Manager
- Doppler
- 1Password CLI

Token redaction is applied to logs and evidence-pack outputs by default. Disabling redaction requires `output.redaction: none` plus a confirmation flag.

## Config validation

```
compliancekit doctor --check-config
```

Validates schema, resolves env vars, checks network connectivity, and prints what *would* run without scanning. Run this once after editing the config.

## Per-environment configs

Two patterns work:

```
# Explicit
compliancekit scan --config=./prod.yaml

# Auto-resolve
compliancekit scan --env=prod
# → loads ./compliancekit.prod.yaml if present, else ./compliancekit.yaml
```

You can also use environment variables in any string value via `${VAR}` substitution (v0.6+):

```yaml
project: ${ORG_NAME}-saas
output:
  out_dir: /tmp/compliance-${BUILD_ID}
```

## Defaults at a glance

| Field | Default |
|---|---|
| `frameworks` | `[soc2, cis-v8]` |
| `severity.fail_on` | `high` |
| `severity.min_report` | `info` |
| `output.format` | `[json]` |
| `output.out_dir` | `./out` |
| `output.evidence` | `false` |
| `output.include_raw` | `false` |
| `output.redaction` | `default` |
| `state.dir` | `.compliancekit` |
| `state.backend` | `file` |
| `state.retention_days` | `90` |
| `providers.linux.ssh.user` | `$USER` |
| `providers.linux.ssh.port` | `22` |
| `providers.linux.ssh.timeout` | `10s` |
| `providers.linux.ssh.max_parallel` | `16` |
| `providers.linux.ssh.strict_host_key` | `true` |

## Examples

### Minimal — DO scan only, env-driven

No config file. Just:

```
export DO_API_TOKEN=...
compliancekit scan digitalocean
```

### Multi-provider, multi-framework

```yaml
# compliancekit.yaml
project: acme-saas
environment: prod
providers:
  digitalocean:
    enabled: true
    token_env: DO_API_TOKEN
  linux:
    enabled: true
    inventory: ./inventory.yaml
frameworks: [soc2, iso27001, cis-v8]
output:
  format: [json, html, sarif]
  evidence: true
severity:
  fail_on: high
```

### CI-only — strict mode

```yaml
project: ${CI_PROJECT_NAME}
providers:
  digitalocean:
    enabled: true
    token_env: DO_API_TOKEN
output:
  format: [sarif]
  out_dir: ./ci-out
severity:
  fail_on: high
  min_report: medium
```

Invoke as:

```
compliancekit scan --quiet
```

CI fails on findings at `high` or above, ignores `low`/`info`.
