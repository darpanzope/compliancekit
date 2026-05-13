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

## v0.5 — Public launch (weekend 5)
**Goal:** ship to the public and earn the first 500 stars.

### Deliverables
- README: hero asciinema, install one-liner, the audience pitch ("Prowler for the people Prowler forgot"), framework table, sample evidence pack, FAQ.
- `goreleaser` for cross-compiled binaries + Homebrew tap + Docker image (`ghcr.io/darpanzope/compliancekit`).
- GitHub Action `darpanzope/compliancekit-action@v1` with composable inputs (token, frameworks, output formats, fail-on-severity).
- Cosign-signed releases + SBOM via goreleaser.
- `CONTRIBUTING.md`, `SECURITY.md`, issue templates, PR template.
- Auto-generated check catalogue at `docs/checks/`.
- Companion blog post on `darpan.cloud`.

### Launch sequence (single day)
1. Tag `v0.5.0`. Goreleaser publishes Homebrew formula, Docker image, GitHub Release with binaries.
2. Post on Hacker News: *"Show HN: compliancekit — SOC 2 evidence packs for DigitalOcean and Linux."*
3. Cross-post: r/devops, r/sysadmin, r/cybersecurity, r/digitalocean, r/SaaS, lobste.rs.
4. Email DigitalOcean's community-tutorials team — they actively promote OSS that helps their users.
5. Submit to `tldr.sec` newsletter.
6. LinkedIn + Twitter post with the demo gif.

### Definition of done
- One-line install works on macOS and Linux.
- `compliancekit-action` runs successfully on a public test repo.
- README is the kind of README we'd star.

---

## Post-launch: v0.6 and beyond

Sequenced for compounding value. Each minor is one or two weekends. Reality will reorder this once launch feedback arrives — the value is in having the shape locked, not the order.

| Version | Theme | Headline |
|---|---|---|
| v0.6 | Drift + profiles + baseline + hardening index | 0-100 hardening score in 30 seconds |
| v0.7 | Hetzner Cloud | DO + Hetzner from one tool |
| v0.8 | Containers + K8s + DOKS-deep | From cluster to droplet in one scan |
| v0.9 | Framework expansion + MITRE ATT&CK + tailoring | Map every finding to ATT&CK |
| v0.10 | IaC / OCSF / OSCAL ingest + emit | Plays nicely with the rest of the security stack |
| v0.11 | Vuln / secret / SCA ingest | Every CVE tied to a real droplet |
| v0.12 | Remediation generators (Bash / Terraform / Ansible / doctl) | Copy-paste this Terraform to fix |
| v0.13 | Rego policy DSL (via OPA) | Write a check in 10 lines of Rego |
| v0.14 | Notifications (Slack / Discord / Teams / email / webhook / PR / Jira) | Slack alert on every new high finding |
| v0.15 | Waivers + in-code skip annotations | Mute findings the right way |
| v1.0 | API stability — `pkg/compliancekit` frozen | Embed compliancekit in your own tools |
| v1.1 | `serve` mode + SQLite/Postgres backend + REST API + webhook receivers | Continuous monitoring without the SaaS bill |
| v1.2 | Multi-tenant / organizations | MSP-friendly: one binary, many clients |
| v1.3 | Trust Center generator | Your public security page, generated |
| v1.4 | GRC layer — risk register, vendor register, CAIQ/SIG templates, training tracking | Risk + vendors + questionnaires in repo |
| v1.5 | Auditor portal (auth-gated, time-boxed, watermarked exports) | Give your auditor read-only access |
| v1.6 | macOS + Windows + BSD hardening | Hardening for every machine you own |
| v1.7 | More clouds — AWS, GCP, Cloudflare, GitHub, Workspace, Vercel, Linode, Vultr | Every cloud your SaaS touches |
| v1.8 | OSCAL ecosystem (catalogs in, assessment results out) + SCAP DataStream import | FedRAMP-curious? OSCAL in, OSCAL out |
| v1.9 | Risk score + executive PDF + time-series dashboard | One number for your board |
| v2.0 | Plugin marketplace — subprocess gRPC + WASM (wazero), cosign-signed | Install a check pack with one command |
| v2.x | K8s operator — CRDs (`ComplianceScan`, `ComplianceProfile`, `ComplianceWaiver`) | Reconcile compliance from a CRD |
| v2.x | Auto-remediation (opt-in, dry-run default, full audit log) | Fix it for me — if you really want |

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
