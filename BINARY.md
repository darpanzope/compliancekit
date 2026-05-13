# Binary architecture

What the compiled artifact actually looks like — runtime shape, what's inside it, what touches the network, how it grows across versions. This is the operational sibling of ARCHITECTURE.md (which is about code shape).

## 1. The artifact

```
compliancekit            ~25-40 MB static ELF/Mach-O/PE
├── No CGO                CGO_ENABLED=0 → no libc dependency
├── No runtime deps       Curl-pipe-bash works; air-gapped works
└── Cross-compiled to:    linux/amd64, linux/arm64,
                          darwin/amd64, darwin/arm64,
                          windows/amd64
```

Built with:

```
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags="-s -w -X main.version=v0.1.0" \
  ./cmd/compliancekit
```

`-s -w` strips symbol and debug info. `-trimpath` removes local filesystem paths from the binary. `-X main.version=...` injects build metadata. Reproducible builds via `goreleaser` from v0.5.

## 2. Process model

Single process. Goroutines for concurrency. No subprocess fan-out (except plugin host at v2.0).

```
┌─────────────────────────────────────────────────────┐
│ compliancekit (single process)                      │
│                                                     │
│  main() → cobra dispatch                            │
│           │                                         │
│           ├─ scan      → engine.Run(ctx)            │
│           │     │                                   │
│           │     ├─ Collector goroutine pool         │
│           │     │   (bounded: max_parallel=16)      │
│           │     │   ├─ DO API calls (HTTPS)         │
│           │     │   └─ SSH connections (pooled)     │
│           │     │                                   │
│           │     ├─ Resource graph (in-memory)       │
│           │     │                                   │
│           │     ├─ Evaluator goroutine pool         │
│           │     │   (CPU-bound, GOMAXPROCS)         │
│           │     │                                   │
│           │     └─ Findings (in-memory slice)       │
│           │                                         │
│           ├─ report    → reader → reporter → writer │
│           ├─ evidence  → reader → packer → fs       │
│           ├─ doctor    → connectivity smoke test    │
│           └─ checks    → catalogue queries          │
│                                                     │
└─────────────────────────────────────────────────────┘

External I/O (outbound only by default):
   ──► HTTPS to api.digitalocean.com (godo)
   ──► SSH/22 to inventory hosts (x/crypto/ssh)
   ──► (v0.14+) HTTPS to webhook sinks
   ──► (v0.10+) HTTPS to ingestor sources

No inbound listener until v1.1's `compliancekit serve`.
```

## 3. What's embedded vs. fetched at runtime

Everything required for a scan ships **inside** the binary. Nothing is fetched at runtime by default — air-gapped is a first-class deployment.

```
binary
├── go code (compiled)
│   ├── cmd/compliancekit         CLI entrypoint
│   ├── internal/cli              cobra command definitions
│   ├── internal/engine           orchestrator
│   ├── internal/core             types
│   ├── internal/collectors/...   DO + Linux (v0.2+)
│   ├── internal/evaluators/...   Go-native, eventually Rego
│   ├── internal/reporters/...    json, html, sarif, ocsf, ...
│   ├── internal/frameworks/...   soc2, iso27001, cis-v8 ...
│   ├── internal/state            local state store
│   └── internal/config           viper config loader
│
└── embedded files (go:embed)
    ├── internal/checks/digitalocean/*.yaml       check metadata
    ├── internal/checks/linux/*.yaml              check metadata
    ├── internal/frameworks/*.yaml                control mappings
    ├── web/report/*.{html,css,js,svg}            HTML report assets
    └── internal/policies/*.rego                  (v0.13+) Rego checks
```

**Why embedded:** one binary, zero install steps, no "missing config" failure mode. Updating the check catalogue means a new release — which is the right cadence for compliance content anyway.

## 4. Dependency graph (linked into the binary)

```
github.com/darpanzope/compliancekit
├── github.com/spf13/cobra              CLI framework
├── github.com/spf13/viper              config loader
├── github.com/digitalocean/godo        DO API SDK
├── golang.org/x/crypto/ssh             SSH transport       (v0.2+)
├── gopkg.in/yaml.v3                    check/config parsing
├── github.com/rs/zerolog               structured logging
│
├── (v0.10) github.com/owenrumney/go-sarif    SARIF emitter
│
├── (v0.13) github.com/open-policy-agent/opa
│            └── Rego evaluator
│
├── (v0.8)  k8s.io/client-go                  K8s collector
│
├── (v0.7)  github.com/hetznercloud/hcloud-go Hetzner SDK
│
├── (v1.1)  modernc.org/sqlite                pure-Go SQLite
│            github.com/jackc/pgx/v5          Postgres (opt-in)
│
└── (v2.0)  github.com/tetratelabs/wazero     WASM plugin host
             google.golang.org/grpc           subprocess plugins
```

Pure-Go choices throughout (no CGO) keep cross-compilation trivial. `modernc.org/sqlite` over `mattn/go-sqlite3` for the same reason.

## 5. Memory shape

A scan is bounded by the size of the resource graph, not the size of the cloud. Typical scan footprint:

| Audience | Resources | Findings | Peak RSS |
|---|---|---|---|
| Solo dev / hobby | 10-50 | ~30 | <50 MB |
| Startup (typical DO) | 100-500 | 100-500 | <150 MB |
| Mid-sized fleet | 1k-5k | 1k-5k | <500 MB |
| Large (v1.x territory) | 10k+ | 10k+ | streams to disk |

At v1.1's `serve` mode, the resource graph stays in memory for the daemon's lifetime; refreshes are deltas against the prior snapshot.

## 6. I/O policy — security invariants

These are load-bearing promises to the audience and enforced in code:

| Direction | Default | Required? |
|---|---|---|
| Outbound HTTPS to provider APIs | Yes | When provider is enabled |
| Outbound SSH to inventory hosts | Yes | When linux provider is enabled |
| Outbound webhook to notification sinks | Off | Opt-in via config |
| Outbound telemetry / phone-home | **Never** | — |
| Inbound HTTP listener | Off | Only when `serve` is invoked |
| Filesystem writes | Limited to `--out-dir` and `state.dir` | — |
| Secret values in logs | **Never** | Token redaction enforced via middleware |
| Secret values in evidence pack | **Never** (default), opt-in via `--include-raw` | — |

A `compliancekit doctor` run prints exactly which outbound destinations the configured providers will touch. No hidden network behavior.

## 7. Permission model

What the binary needs to run:

| Operation | Requires |
|---|---|
| `scan digitalocean` | `DO_API_TOKEN` env (read scope is sufficient) |
| `scan linux` | SSH agent or key file with read access to target hosts |
| `report` / `evidence` | Local filesystem write access only |
| `serve` (v1.1+) | Bind to configured port (default 8080); local FS or DB write |
| `remediate` (v2.x, opt-in) | Write-scope cloud token + explicit `--apply` |

Audit-only by default. The binary cannot mutate cloud or host state until v2.x, and even then only with explicit flags.

## 8. Startup sequence

```
main()
  ├─ cobra.Execute()
  │    └─ matched command's RunE(ctx, args)
  │         ├─ load config (viper: file → env → flags)
  │         ├─ resolve secrets (env-only at v0.1)
  │         ├─ build context.Context with cancellation
  │         ├─ build Collectors per enabled provider
  │         ├─ build Evaluators (Go-native at v0.1)
  │         ├─ build Reporters per --output flag
  │         ├─ engine.Run(ctx, collectors, evaluators)
  │         │    ├─ collect()  → []Resource
  │         │    ├─ evaluate() → []Finding
  │         │    └─ report()   → write outputs
  │         └─ exit code from severity policy
  └─ end
```

Cold start to first API call: <100 ms. Configuration parsing is the only meaningful pre-work.

## 9. Internal package boundaries

Standard Go layout, with `internal/` enforced as private:

```
cmd/                      entry points (main packages, thin)
  └── compliancekit/      the CLI binary
internal/                 private to this module
  ├── cli/                cobra command files
  ├── core/               Finding, Resource, Check, types
  ├── engine/             orchestrator
  ├── collectors/         per-provider data fetchers
  ├── evaluators/         check execution (Go, later Rego)
  ├── reporters/          per-format output writers
  ├── frameworks/         control mappings (YAML + thin Go)
  ├── checks/             check YAML + Go scanner funcs
  ├── state/              local state store
  ├── config/             viper-backed config loader
  └── notify/             (v0.14+) Slack/Discord/webhook/...
pkg/                      public API for embedders
  └── compliancekit/      stable from v1.0
web/                      embedded static assets
  └── report/             HTML/CSS/SVG for go:embed
```

`pkg/` is intentionally empty until v1.0. Anyone embedding compliancekit before then is opting into churn.

## 10. Binary lineage across versions

How the artifact changes shape over time:

| Version | Adds to binary | Size impact |
|---|---|---|
| v0.1 | cobra, viper, godo, yaml, zerolog | ~20 MB |
| v0.2 | x/crypto/ssh | +2 MB |
| v0.3 | embedded HTML/CSS/JS, SARIF emitter, OCSF mapper | +1 MB |
| v0.4 | evidence-pack writer, sha256 manifest | negligible |
| v0.5 | version metadata, build provenance | negligible |
| v0.7 | hcloud-go (Hetzner) | +2 MB |
| v0.8 | client-go (K8s) | +5 MB |
| v0.10 | SARIF ingester, OSCAL types | +1 MB |
| v0.13 | OPA Rego runtime | +6 MB |
| v1.1 | SQLite (pure Go), HTTP server, REST handlers | +3 MB |
| v2.0 | wazero (WASM), gRPC | +4 MB |

Even at v2.0, the binary stays under ~50 MB and remains a single artifact. Comparable: Trivy is ~75 MB, Prowler (Python) ships as a 200+ MB Docker image.

## 11. What's deliberately *not* in the binary

- **No embedded vuln database.** Trivy's CVE DB is 100s of MB and updates constantly. We compose with Trivy; we don't ship CVE data.
- **No bundled framework PDFs.** SOC 2 / ISO standards are copyrighted. We ship our derivative control mappings, not the source docs.
- **No web UI framework.** v1.1's `serve` UI is server-rendered HTML (htmx-style) embedded via `go:embed`. No React, no Vue, no bundler.
- **No mandatory database.** v1.1 introduces SQLite as a *default* state store; file-only state remains valid.
- **No telemetry SDK.** Period.

## 12. Threat model summary

What the binary protects against, and what's outside scope:

| In scope | Out of scope |
|---|---|
| Secret leakage in logs / outputs | Compromise of the machine running the binary |
| Supply-chain integrity (cosign at v0.5, go.sum, SBOM) | Supply-chain compromise of upstream Go modules |
| Unauthorized writes to cloud state (audit-only by default) | An operator who explicitly passes `--apply` at v2.x |
| Drive-by exfiltration via the binary (no phone-home) | An operator who configures a webhook to a malicious URL |
| Token scope creep (we ask only for read scope) | A token over-scoped by the operator |

The binary is trustworthy software run by a trusted operator. We don't try to defend against the operator.

## 13. Reproducibility

Any commit on `main` produces bit-identical binaries when built with:

```
git checkout <sha>
make release-build       # uses pinned Go version + -trimpath
sha256sum bin/*
```

`goreleaser` writes a `metadata.json` per release with input hashes. SLSA L3 attestation arrives at v0.5.

## 14. Operational characteristics

For people running this in production CI or on a cron:

| Property | Value |
|---|---|
| Cold start | <100 ms |
| Typical scan time | 2-10 s (small fleet) · 1-3 min (mid-sized) |
| Disk usage (state dir) | <10 MB per scan, retained per `state.retention_days` |
| Concurrent scans on one host | Safe; each scan uses its own state file unless `--state-dir` collides |
| Signal handling | `SIGINT`/`SIGTERM` cancels in-flight work cleanly; partial findings written to `<out>/findings.partial.json` |
| Memory ceiling | Bounded by resource count; OOM-protected via `--max-resources` (v0.6+) |
| Exit code policy | See CLI.md §Exit codes |

## 15. Packaging targets

| Channel | Set up at | Format |
|---|---|---|
| `go install` | v0.1 | source build |
| GitHub Releases | v0.5 | cross-compiled tarballs + checksums |
| Homebrew tap | v0.5 | formula via goreleaser-brew |
| Docker (ghcr.io) | v0.5 | distroless base, ~30 MB image |
| GitHub Action | v0.5 | composite action wrapping the Docker image |
| Nix flake | v0.6 | community contribution welcome |
| AUR / deb / rpm | v0.7+ | community contributions welcome |
| Cosign signatures + SBOM | v0.5 | SLSA L3 attestation |
