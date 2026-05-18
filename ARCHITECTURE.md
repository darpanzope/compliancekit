# Architecture

This document captures the technical decisions behind `compliancekit` and the reasoning for each. It is the source of truth for engineering decisions; if something here is wrong, fix it here first, then change the code.

## 1. Goals and non-goals

### Goals
- **One static binary.** Zero runtime dependencies. Curl-pipe-bash-able. Air-gapped friendly.
- **Two scan sources to start:** DigitalOcean API + Linux hosts over SSH.
- **One opinionated output:** an evidence pack a real auditor will accept — timestamped artifacts, SHA-256 manifest, control-mapping CSV. Plus HTML/JSON/Markdown for humans and CI.
- **Three frameworks at v0.5:** SOC 2 Trust Services Criteria, ISO 27001 Annex A, CIS Controls v8 (with the Linux Benchmark for OS checks).
- **Run anywhere:** developer laptop, CI runner, a $4 droplet on a cron. No SaaS, no callback, no telemetry.

### Non-goals (for v0.x)
- A SaaS dashboard. Optional `compliancekit serve` may come at v1.x but never required.
- Auto-remediation. Reports only — the human stays in the loop.
- Vulnerability scanning. That's Trivy's job. We compose with it; we don't replace it.
- IaC scanning. tfsec/Checkov own this; we may *consume* their output later but won't reimplement.

## 2. Language and runtime

**Decision: Go (1.22+).**

Why:
- Single static binary; cross-compiles trivially to `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`, `windows/amd64` from one machine.
- Audience expectation: the cloud-native security ecosystem speaks Go (Trivy, Falco, Tetragon, Vault, Terraform, kubectl, k9s). A Python tool here would feel off-brand.
- Strong stdlib for HTTP, JSON, file I/O, and crypto. `golang.org/x/crypto/ssh` is production-grade.
- `github.com/digitalocean/godo` is the official, well-maintained DO SDK.
- Cobra + Viper give us a polished CLI surface with minimal effort.
- Easy concurrency via goroutines for parallel API calls and SSH fan-out.

Alternatives considered:
- **Rust** — better long-term, slower iteration today, smaller ecosystem for compliance.
- **Python** — Prowler's stack; deployment is painful, no static binary story.
- **TypeScript/Bun** — immature for SSH and system-level ops; bigger bundle.

**Go version pin:** `1.26` minimum. `go.mod` tracks latest stable. CI builds golangci-lint from source against the runner's Go (via `go install`) so the linter doesn't lag the language; the pre-built binary route was abandoned after it constrained us to Go 1.24 stdlib and triggered govulncheck CVE alerts.

## 3. High-level architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  compliancekit (single binary)               │
│                                                              │
│  CLI (cobra)                                                 │
│   ├─ scan ──┬──────────────────────────────────────────┐    │
│   ├─ report │                                          │    │
│   ├─ evidence                                          │    │
│   └─ checks │                                          │    │
│             ▼                                          │    │
│        ┌─────────────────────────────────────────┐    │    │
│        │ Engine                                  │    │    │
│        │   for each Provider:                    │    │    │
│        │     for each Check:                     │    │    │
│        │       run → emit Finding                │    │    │
│        └─────────────────┬───────────────────────┘    │    │
│                          │                            │    │
│         ┌────────────────┼────────────────┐           │    │
│         ▼                ▼                ▼           │    │
│   Provider          Provider         Provider         │    │
│   digitalocean      linux            (v0.7+: aws,     │    │
│   (godo)            (SSH)             gcp, hetzner,   │    │
│                                       k8s)            │    │
│                                                       │    │
│         │                │                │           │    │
│         └────────────────┴────────────────┘           │    │
│                          │                            │    │
│                          ▼                            │    │
│              ┌────────────────────────┐               │    │
│              │ Findings store         │               │    │
│              │ (in-memory + optional  │◀──────────────┘    │
│              │ state file for diff)   │                    │
│              └────────────┬───────────┘                    │
│                           │                                │
│       ┌───────────────────┼───────────────────┐            │
│       ▼                   ▼                   ▼            │
│   Reporter           Reporter             Reporter         │
│   json/html/md       sarif                evidence-pack    │
│                                           (folder + sha)   │
└──────────────────────────────────────────────────────────────┘

External world:
   DigitalOcean API ◀── godo
   Linux hosts      ◀── SSH (x/crypto/ssh)
   GitHub Actions   ──▶ wraps the binary
   Drata / Vanta    ──▶ consumes the evidence pack
```

Six pluggable surfaces, each behind a small interface:

```go
// Collector fetches raw cloud / host data and emits typed Resources.
// Split from Provider on day 1 so multiple checks can reuse one fetch,
// and so cross-resource / cross-provider checks become trivial later.
type Collector interface {
    Name() string
    Collect(ctx context.Context, cfg ProviderConfig) ([]Resource, error)
}

// Resource is the typed, normalized node in the resource graph.
// Edges (Droplet → Firewall, Bucket → CDN) live in Attributes/Relations.
type Resource struct {
    ID, Type, Provider, Region, Account string
    Attributes map[string]any
    Relations  map[string][]string  // ref → []Resource.ID
}

// Evaluator runs checks against the Resource graph and emits Findings.
// Day-1 evaluator is Go-only; Rego slot lands at v0.16 without
// breaking the Check signature.
type Evaluator interface {
    Evaluate(ctx context.Context, graph ResourceGraph) ([]Finding, error)
}

type Reporter interface {
    Format() string  // "json", "json-ocsf", "html", "sarif", "evidence-pack", ...
    Render(findings []Finding, graph ResourceGraph, w io.Writer) error
}

type Framework interface {
    ID() string  // "soc2", "iso27001", "cis-v8", "nist-800-53", "mitre-attack", ...
    MapCheck(checkID string) []ControlID
}

type StateStore interface {
    Load() (PreviousRun, error)
    Save(findings []Finding) error
}
```

Adding a cloud is a new `Collector`. Adding an output is a new `Reporter`. Adding a framework is a YAML mapping plus a thin `Framework` impl. Adding a policy language (Rego) at v0.16 is a new `Evaluator`. No core changes.

**Why split Collector from Evaluator on day 1:** the natural shape of the v0.1 code is "fetch → check → emit." That works for 10 checks. By v0.6 we'll want check-level fact reuse, cross-resource queries, and Rego policies that read a graph — all easier if the seam exists from the start. Cost: ~50 extra LoC in v0.1. Benefit: no painful refactor at v0.6.

## 4. Check definition model

Checks are declared in YAML, executed by typed Go functions. The split keeps the catalogue browseable and the execution fast.

```yaml
# internal/checks/digitalocean/spaces.yaml
- id: do-spaces-public-acl
  title: "Spaces buckets must not allow public read"
  severity: high
  description: |
    Public-read Spaces buckets can leak customer data. Buckets should
    default to private; objects intended for public distribution should
    go through the CDN with explicit per-object ACLs.
  remediation: |
    For each public bucket:
      doctl spaces update <name> --acl private
  frameworks:
    soc2: [CC6.1, CC6.6]
    iso27001: [A.5.10, A.8.2]
    cis-v8: [3.3]
  scanner: spaces.PublicACL   # Go function reference
```

Why YAML for the metadata, Go for the logic:
- Auditors and contributors can read/grep the catalogue without Go knowledge.
- `compliancekit checks list` and the docs site auto-generate from YAML.
- Framework mappings stay declarative and diff-able.
- Logic stays typed, testable, and fast.

## 5. Repository layout

```
compliancekit/
├── cmd/
│   └── compliancekit/
│       └── main.go                # cobra root
├── internal/
│   ├── cli/                       # cobra command files
│   ├── engine/                    # orchestrator
│   ├── core/                      # types: Finding, Check, Provider, Framework
│   ├── providers/
│   │   ├── digitalocean/
│   │   │   ├── provider.go
│   │   │   ├── droplets.go
│   │   │   ├── spaces.go
│   │   │   ├── databases.go
│   │   │   ├── k8s.go
│   │   │   ├── loadbalancers.go
│   │   │   ├── vpc.go
│   │   │   ├── registry.go
│   │   │   └── account.go
│   │   └── linux/
│   │       ├── provider.go
│   │       ├── ssh.go             # connection pool
│   │       ├── inventory.go       # hosts.yaml parser
│   │       ├── sshd.go
│   │       ├── firewall.go
│   │       ├── audit.go
│   │       ├── filesystem.go
│   │       ├── users.go
│   │       └── kernel.go
│   ├── frameworks/
│   │   ├── soc2.yaml
│   │   ├── iso27001.yaml
│   │   ├── cis-v8.yaml
│   │   └── nist-800-53.yaml       # v0.12+
│   ├── checks/
│   │   ├── digitalocean/*.yaml
│   │   └── linux/*.yaml
│   ├── report/
│   │   ├── json.go
│   │   ├── html.go                # embeds web/report/*
│   │   ├── markdown.go
│   │   ├── sarif.go
│   │   └── evidence/
│   │       ├── pack.go
│   │       ├── manifest.go        # SHA-256 manifest
│   │       └── mapping_csv.go
│   ├── state/
│   │   └── store.go               # .compliancekit/state.json
│   └── config/
│       └── config.go              # compliancekit.yaml
├── pkg/
│   └── compliancekit/             # public API for embedders
├── web/
│   └── report/                    # HTML/CSS/JS for the dashboard (go:embed)
├── docs/
│   ├── checks/                    # auto-generated catalogue
│   ├── frameworks/                # control mappings reference
│   ├── self-hosting.md
│   └── ci-integration.md
├── examples/
│   ├── compliancekit.yaml         # full config example
│   ├── inventory.yaml             # SSH inventory example
│   └── github-actions.yaml
├── action.yml                     # GitHub Action manifest (root for marketplace)
├── .github/
│   ├── workflows/
│   │   ├── ci.yaml
│   │   ├── release.yaml           # goreleaser + cosign (v0.5+)
│   │   ├── govulncheck.yaml       # Go CVE call-graph scan
│   │   └── codeql.yaml            # static analysis (re-added at v0.5 when repo is public)
│   └── ISSUE_TEMPLATE/
├── Dockerfile
├── .goreleaser.yml
├── Makefile
├── go.mod
├── go.sum
├── README.md
├── ARCHITECTURE.md                # this file
├── ROADMAP.md
├── CONTRIBUTING.md
├── SECURITY.md
└── LICENSE
```

## 6. CLI surface

```
compliancekit scan                 # scans everything in compliancekit.yaml
compliancekit scan digitalocean    # scan one provider
compliancekit scan linux --inventory=inventory.yaml
compliancekit scan --output=json --out=findings.json

compliancekit report --format=html --in=findings.json --out=./report
compliancekit evidence --in=findings.json --out=./evidence/2026-Q2/

compliancekit checks list                          # full catalogue
compliancekit checks list --framework=soc2         # mapped to SOC 2
compliancekit checks show do-spaces-public-acl

compliancekit diff previous.json current.json      # drift between runs

compliancekit version
compliancekit doctor               # checks env, creds, connectivity
```

Subcommand-first (cobra), config-file driven (viper), flag-overridable.

## 7. Configuration

`compliancekit.yaml` is the single source of truth for a scan run. Everything else (flags, env vars) can override.

```yaml
project: acme-saas
environment: prod

providers:
  digitalocean:
    token_env: DO_API_TOKEN          # never inline the token
    teams: [primary]                  # support multiple teams in v0.6+
    scope:
      include_tags: [prod]
      exclude_resources: []

  linux:
    inventory: ./inventory.yaml
    ssh:
      user: ops
      key_file: ~/.ssh/id_ed25519
      timeout: 10s
      max_parallel: 16
      bastion:                       # optional
        host: bastion.acme.com
        user: ops

frameworks:
  - soc2
  - cis-v8

output:
  format: [json, html]
  out_dir: ./out
  evidence: true

state:
  dir: .compliancekit
```

## 8. DigitalOcean coverage (v0.1)

Initial check set, ranked by audit value. Each maps to at least one SOC 2 CC and one CIS Control.

| Area | Check |
|---|---|
| Droplets | Public IP without firewall attached |
| Droplets | SSH password auth not disabled in metadata-installed image |
| Droplets | Backups disabled |
| Droplets | Image / kernel older than 365 days |
| Droplets | No project assignment / no required tags |
| Spaces | Public ACL on bucket |
| Spaces | No CDN with HTTPS |
| Spaces | No lifecycle policy |
| Databases | Public network access allowed |
| Databases | Backup retention < 7 days |
| Databases | TLS not enforced |
| Databases | Trusted sources list empty |
| Databases | EOL engine version |
| K8s (DOKS) | Public API endpoint exposed |
| K8s (DOKS) | Cluster version below latest minor |
| K8s (DOKS) | Surge upgrade disabled |
| Load Balancers | TLS version below 1.2 |
| Load Balancers | Cert expires within 30 days |
| Load Balancers | HTTP not redirected to HTTPS |
| VPC / Firewalls | Inbound rule `0.0.0.0/0` on 22, 3389, 3306, 5432, 6379, 27017, 9200 |
| Container Registry | Public registry |
| Account | 2FA not enforced on team members |
| Account | API token older than 365 days |
| Account | API token unused for 90+ days |
| Account | No billing alerts configured |
| Account | Audit log retention setting unknown / off |

## 9. Linux coverage (v0.2)

Subset of CIS Ubuntu 22.04 / Debian 12 Benchmark, weighted for "what actually matters in 2026".

| Area | Check |
|---|---|
| SSH | `PermitRootLogin no` |
| SSH | `PasswordAuthentication no` |
| SSH | `Protocol 2` only |
| SSH | `MaxAuthTries <= 4` |
| SSH | `LoginGraceTime <= 60s` |
| Firewall | ufw or nftables active, default-deny inbound |
| Audit | auditd running and enabled at boot |
| Audit | journald `Storage=persistent`, retention configured |
| Filesystem | `/etc/shadow` mode 0640, owner root:shadow |
| Filesystem | `/etc/passwd` mode 0644 |
| Filesystem | `/root` mode 0700 |
| Updates | `unattended-upgrades` active |
| Users | No users with empty password fields |
| Users | No non-root users with UID 0 |
| Users | Login.defs PASS_MAX_DAYS <= 365 |
| Kernel | `kernel.randomize_va_space = 2` |
| Kernel | `net.ipv4.conf.all.send_redirects = 0` |
| Kernel | `net.ipv4.conf.all.accept_source_route = 0` |
| Services | No `telnetd`, `rsh-server`, `nis`, `ypserv` installed |
| Network | No listening ports outside allowlist |
| Logging | rsyslog/journald forwarding to a remote target |
| Time | NTP/chrony active and synced |

Checks ship as small shell snippets executed over a pooled SSH connection, results parsed in Go. No agent install; agentless by design.

## 10. Output: the evidence pack

This is the differentiator. Output structure:

```
evidence/2026-Q2/
├── MANIFEST.sha256              # checksum of every file below
├── control-mapping.csv          # check_id, control_id, status, evidence_path
├── soc2/
│   ├── CC6.1-logical-access/
│   │   ├── do-droplets-firewall.json     # raw API response
│   │   ├── do-droplets-firewall.md       # human summary
│   │   ├── linux-sshd-config.txt         # captured config
│   │   └── linux-sshd-config.md
│   ├── CC6.6-network-security/
│   └── ...
├── iso27001/
│   └── A.8.2-privileged-access/
├── cis-v8/
│   └── 4.1-secure-configuration/
└── summary.html                 # auditor-readable index
```

Properties:
- Every artifact has a stable, dated filename so it survives auditor handoff.
- `MANIFEST.sha256` proves nothing was tampered with after the run.
- `control-mapping.csv` is Drata/Vanta/AuditBoard-import-friendly.
- Sensitive values redacted by default; opt-in raw-mode via flag.

## 11. State and drift

`.compliancekit/state.json` stores a hash of each finding. On the next run, findings are classified:
- **new** — appeared since last run
- **existing** — unchanged
- **resolved** — was present, now gone

`compliancekit diff` makes this explicit for CI use:

```
$ compliancekit diff previous.json current.json
+ 2 new (1 high, 1 medium)
- 1 resolved
= 24 existing
```

Exit code reflects severity of new findings for fail-the-build CI integration.

## 12. Distribution

| Channel | Set up at |
|---|---|
| `go install github.com/darpanzope/compliancekit/cmd/compliancekit@latest` | v0.1 |
| GitHub Releases (cross-compiled binaries) | v0.4 via goreleaser |
| Homebrew tap: `brew install darpanzope/tap/compliancekit` | v0.4 via goreleaser |
| Docker: `ghcr.io/darpanzope/compliancekit` | v0.4 |
| GitHub Action: `darpanzope/compliancekit-action@v1` | v0.4 |
| Cosign-signed releases (SLSA L3 attestation) | v0.5 |

The GitHub Action is the highest-leverage distribution: it bundles "run on PR, comment with diff" into ~10 lines of YAML and the audience (SaaS devops teams) already lives in Actions.

## 13. Security and privacy

- **No telemetry.** Ever. Documented in the README.
- **No phone-home.** The binary never makes a network call we don't explicitly run.
- **Secrets via env or file path only.** Never inline in config.
- **SSH key handling:** prefers SSH agent, falls back to file path with strict perm check.
- **API tokens:** truncated in logs; never written to evidence-pack outputs.
- **Supply chain:** `go.sum` checked in, dependabot enabled, cosign signatures on releases, SBOM generated by goreleaser.

## 14. Testing strategy

- **Unit tests** for each check's parser/logic — gofakeit-style fixtures.
- **Provider mocks**: record real DO API responses with the `-record` flag, replay in tests.
- **SSH integration**: a Docker-Compose harness spinning up Ubuntu/Debian containers; checks run against them in CI.
- **Snapshot tests** for HTML/JSON/Markdown reports.
- **`compliancekit doctor`** doubles as a smoke test we run in CI.

## 15. Locked decisions

These were open questions; each is now decided. Full reasoning lives in [DECISIONS.md](DECISIONS.md).

- **Resource graph:** designed in at v0.1 via the `Collector` + `Resource` split. Avoids a painful v0.6 refactor for ~50 LoC of upfront cost.
- **Policy DSL:** Rego (via OPA Go library), landing at v0.16. The `Evaluator` interface is shaped from day 1 so Rego slots in without breaking check signatures. Go remains the option for complex / perf-sensitive checks.
- **OCSF output:** lands at v0.3 alongside SARIF. Cheap to add early, painful to retrofit; aligns with Prowler's downstream-SIEM story.
- **GRC layer (risk register, vendor register, CAIQ/SIG templates):** in scope, at v1.6. Scanning maturity precedes GRC features so we earn technical credibility before the soft-skills layer.
- **`serve` mode:** optional, never required. The CLI must always be feature-complete. Day-1 internal interfaces are daemon-aware (no globals, context-cancellable) so v1.3 is a feature add, not a rewrite.
- **Auto-remediation:** opt-in at v2.x, behind `--yes-i-mean-it`, dry-run by default, full audit log. Permanently splits the project into "audit-only" (default, safe) and "act-on-it" (advanced) modes.

## 16. Open questions (decide as we go)

- **Plugin host: subprocess gRPC vs. WASM (wazero) vs. both.** Punted to v2.0; the answer depends on whether closed-source plugins become a real ask.
- **Postgres vs. SQLite default for `serve` mode.** Probably SQLite default, Postgres opt-in. Decide at v1.3.
- **CIS Certification pursuit.** Worth the paperwork for credibility, but not free. Decide post-launch once we see audience traction.
