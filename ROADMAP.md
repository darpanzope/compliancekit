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
| **v0.8** ✅ | **GCP** | First-class GCP hardening, 25 checks across IAM/Compute/GCS/Cloud SQL/Logging/KMS/BigQuery |
| **v0.9** ✅ | **DigitalOcean depth pass — everything except DOKS** | 5 → 74 checks across 20 services; the most comprehensive OSS DigitalOcean scanner |
| **v0.10** ✅ | **Hetzner Cloud** | 15 checks across servers/firewalls/networks/LBs/volumes/floating IPs |
| **v0.11** ✅ | **Kubernetes + EKS / GKE / DOKS-deep** | 139 checks across pods, controllers, RBAC, network, storage, namespaces/admission, nodes + EKS/GKE/DOKS enrichment — production-grade K8s posture across the four clouds we ship |
| **v0.12** ✅ | **Framework expansion (NIST 800-53 r5, HIPAA, PCI-DSS v4, MITRE ATT&CK) + tailoring + evidence-pack depth** | 7 frameworks × 548 controls; existing 3 expanded to full catalogs; ATT&CK as the first kill-chain threat-model lens; tailoring lets operators scope controls out with justifications |
| **v0.13** ✅ | IaC / OCSF / OSCAL ingest + emit + OSCAL AR/Profile emit + mapping CLI | 3 ingest formats (SARIF / OCSF / OSCAL Catalog) covering 7 tools; 2 OSCAL emits (Assessment Results + Profile); 106 starter rule mappings; lossless OCSF round-trip; runtime framework registration |
| **v0.14** ✅ | Vuln / secret / SCA ingest (Trivy, Grype, Checkov, gitleaks) + image-SHA graph join + vulnerabilities.csv + ADR-010 secret-redaction | 4 native-JSON adapters, every CVE tied to its running cloud resource, fingerprint-only secret handling |
| ~~v0.15~~ ✅ | Remediation generators (Bash, Terraform, kubectl, Helm, Ansible, aws/gcloud/az/doctl/hcloud + POA&M + Jira/Linear) | Copy-paste this Terraform to fix |
| ~~v0.16~~ ✅ | Rego policy DSL (via OPA) + 4 custom built-ins + `policy test/validate/fmt` CLI + 15 reimplementations | Write a check in 10 lines of Rego |
| ~~v0.17~~ ✅ | Notifications — 8 sinks (Slack, Discord, Teams, Email, Webhook, GitHub PR, Jira, PagerDuty) + dedup + only-new mode + per-sink severity floor | Slack alert on every new high finding |
| ~~v0.18~~ ✅ | Waivers + in-code skip annotations — 4 CLI subcommands + 6 file types + evidence-pack `waivers.json` + 4 control-mapping columns + ADR-013 | Mute findings the right way |
| ~~v0.19~~ ✅ | DigitalOcean deepening — 74 → 144 checks across 21 services; every DO check ships with bespoke Terraform + doctl + bash remediation (432 strategies); checks-package coverage 96.1% | Production-grade DO posture |
| ~~v0.20~~ ✅ | Linux hardening — production grade — 15 → 119 checks across 9 spec frameworks; CIS Linux Server Benchmark v8 catalog (90+ sections, L1/L2 tagged); per-distro detection (Debian, RHEL, Alpine, AL2/AL2023); every check ships bespoke bash + Ansible (238 strategies, parity gate at 0/0); checks-package coverage 90.6% | Linux hardening at OpenSCAP/Lynis depth |
| ~~v0.21~~ ✅ | Kubernetes + DOKS deepening — production grade — 149 → 241 checks (+92 / +61%) across 12 phases; NSA/CISA Kubernetes Hardening Guide v1.2 framework yaml; every K8s check ships bespoke kubectl (102 backfilled, strict-equality parity gate at 0); checks-package coverage 52.4% | Production-grade K8s posture across CIS + NSA/CISA |
| ~~v0.22~~ ✅ | Internal refactor + toolchain refresh + action-repo polish — 600-LoC check-file CI gate (internal/repocheck); 9 oversize files split (rbac/pods/network/cluster/reliability/eks/aws-iam/pods_extra/tail.go) into 11 new per-category siblings; Ubuntu 24.04 explicit pin in all 3 workflows; godo + k8s.io v0.34→0.36 + cobra + viper + opa dep sweep; compliancekit-action multi-provider input loop + jq-merged findings + opt-in evidence-pack workflow-artifact upload. **No new user-facing checks; sets up v1.0 API freeze.** Spec-pattern lifts + fake-API-server coverage + lint v2 + deep cookbook deferred to v0.22.x. | Structure debt paid down |
| ~~v1.0~~ ✅ | API stability — `pkg/compliancekit` frozen — 10 type families graduated out of `internal/core` (Severity, Status, Resource, ResourceGraph + Query, Vulnerability/Package/Secret/WaiverRef, Source + Finding, Check + CheckFunc + Registry, Reporter/Collector/Evaluator interfaces, Framework/Control/Tactic); machine-enforced contract via `cmd/genapi` + `pkg/compliancekit/api.txt` CI gate; behavioural contract via `-tags=external` embed test; SECURITY.md two-year compat language for the last two minors; ADR-014 codifies what's in / out / why. 13 phases over one weekend; `internal/core` deleted, 432 files updated to import `pkg/compliancekit` directly. | Embed compliancekit in your own tools |
| ~~v1.1~~ ✅ | **Beautiful CLI** — `internal/ui` package owns the palette + glyph + Styler + Table primitives. lipgloss-driven severity colors (palette tuned for light/dark terminals, AdaptiveColor pairs), status glyphs (`✓✗⚠–·` with ASCII fallbacks), Unicode box-drawing tables across `checks list/show` + `doctor` + `waivers list` + `mapping list` + `notify --list` + `policy validate`, doctor probes accumulate + sort failures-first with sub-items grouped under their parent, diff colorization (`+` green / `-` strikethrough / `=` muted), styled `--help` (bold sections + accented commands), Cobra-provided shell completion (bash/zsh/fish/pwsh), new `compliancekit motd` fleet-at-a-glance card. Global `--no-color` + NO_COLOR + CLICOLOR=0 + non-TTY auto-detect all honored. **Scan progress bar deferred to v1.1.x** — needs an engine progress-channel API change that risked a v1.0 surface diff. 10 phases / 10 commits; lipgloss adds ~3 MB to the stripped binary. | The CLI looks the part for the audience that lives in the terminal |
| ~~v1.2~~ ✅ | **HTML report overhaul** — `internal/report/assets/` is now a 4-file system: template.html with named `{{ block }}` partials + CSS-vars palette, icons/sprite.svg (22 symbols across severity/status/theme/providers), chart.js (gauge + donut + hbar + sparkline drawers), template-driven layout. Two complete palettes (dark + light) + system-preference resolution, persisted to localStorage, no FOUC. Summary cards (score gauge + severity donut + framework coverage bars), filter chips with multi-select OR / cross-group AND + URL-fragment share-views, sticky resource sidebar grouped provider → type → resource, baseline-driven drift card with score + actionable-count sparklines + per-finding "new" badges, @media print + responsive 800/600/400px breakpoints, empty-state celebration panel. New `compliancekit render` subcommand re-renders findings.json against any reporter format without re-scanning, takes `--baseline=path` for trend visualisation. Golden snapshot tests pin empty / all_clear / mixed / critical_only fixtures. 10 phases / 10 commits; single-file invariant preserved (zero CDN / font / external asset). | The HTML report goes from utilitarian to share-with-the-board |
| ~~v1.3~~ ✅ | **`serve` mode — foundation** (v1.3.0 + v1.3.1 shipped 2026-05-18) — embedded HTTP server (chi router, CSP / security headers, `/health`, `/metrics`), SQLite default + Postgres optional backend (scans / findings / resources / providers / checks / waivers / audit_log / users / api_tokens), REST API v1 (read + write), auth (local + OIDC for Google/GitHub/Okta + scoped API tokens), webhook receivers (GitHub PR events, generic POST w/ HMAC verification), background worker pool + job queue, CLI `--push-to-server=...` upload, minimal UI shell (login / nav / scans list / providers status / checks browser; the v1.2 report served from the daemon at `/scans/:id`). 12 phases; new ADR-015 codifies the UI stack. v1.3.1 patched `auth.Mount(r, users, sessions)` after the v1.3.0 demo surfaced a `POST /api/auth/login`=404 from the UI login form. | Continuous monitoring without the SaaS bill |
| ~~v1.4~~ ✅ | **Studio — config-as-UI** (v1.4.0 shipped 2026-05-19, #26) — first-run onboarding wizard (5-min cloud setup w/ per-provider doc + token guide), settings page with provider auth status + "test connection", check-catalog browser with search/filter + per-check toggle, granular per-service selector (AWS→IAM/S3/EC2 etc.), framework tailoring UI (per-control include/exclude w/ justification), live `compliancekit.yaml` preview side-panel as you toggle, CI generator (`.github/workflows/compliance.yaml` + GitLab + CircleCI variants), waivers manager (add/edit/expire w/ approver), scan-now trigger w/ live SSE progress, cron scheduler (timezone-aware), audit log + in-UI notifications inbox layered on v0.17 outbound. **Daemon-bootstrap CLI subcommands** (`compliancekit serve users create --admin`, `serve tokens issue --scope=...`) close the v1.3.1 throwaway-seeddemo gap. **Demo mode** (`compliancekit serve --demo`) seeds realistic findings + resources for first-impression evaluators and screenshot-grade onboarding. 13 phases. | The config builder operators want to ship to their team |
| ~~v1.5.1~~ ✅ | **Post-ship security + control-plane patch** (shipped 2026-05-19) — closed 22 of 25 functional gaps surfaced by the v1.5.0 demo audit (F1-F25 in `reference-v1-5-1-audit`). **Security:** OIDC providers wired (F15) + RequireCSRF chained onto every mutating route (F16) + cookie Secure conditional + `--insecure-cookies` dev flag (F17) + session-auth IsAdmin scopeGate (F18) + webhook secret column fix via migration 0006 (F19). **Control plane:** RealRunner replaces StubRunner — builds `*config.Config` from DB (closes F1+F2+F3+F11), filters check registry by `checks_state` (F7), partial `framework_tailoring` honor via F7 mirror (F6); schedules cron loop goroutine (F4); DB-backed waivers loader at scan time (F5). **Wiring:** UI mutators call AuditLog (F8); inbox producers for scan completion + score regression + waiver expiry (F9); saved-view team-share admin checkbox (F10); `/settings/webhooks` CRUD UI (F14). **Render:** scan source badge (F12); loadFindings full column projection (F20); API check enrichment with title + description + remediation (F22). **CSP fix:** `unsafe-eval` + extracted `/assets/app.js` so Cmd+K palette actually works (ADR-017). F21 (webhook trigger metadata) + F23/F24 cosmetic carry over to v1.6. 13 phase commits. | Make the dashboard actually do what it shows |
| ~~v1.5~~ ✅ | **Explorer + Remediation Studio** (v1.5.0 shipped 2026-05-19, #27) — SQL-backed findings explorer + cursor pagination + htmx infinite-scroll (handles 100k+ findings via `/findings`), advanced chip-based filter bar (multi-OR within group, AND across; severity / status / provider / framework / resource_type / check_id / name search / since-days / scan time-window), saved filter views (`/findings/views` per-user + team-wide pinned, share via URL), Linear-style side-panel finding detail (`/findings/{id}/detail` no page reload; Overview / Remediation / Timeline / Context tabs), remediation studio (`/findings/{id}/remediation` tabbed per format: bash / terraform / kubectl / helm / ansible / aws-cli / gcloud / az / doctl / hcloud; copy + download per format; risk-class badge), interactive resource map (`/resources/map` hierarchical SVG; provider → service → resource; per-tile severity badges; click-to-filter — cytoscape.js escape hatch documented for v1.5.x if pan/zoom/drag needs full force-directed layout), resource inventory table (`/resources` flat-table alt; sortable + searchable), drift timeline (`/findings/{id}/timeline` lazy-loaded into side panel; first-seen / status-change / latest events via fingerprint join), score-over-time chart (`/scores` vanilla-SVG polyline across last 60 completed scans), cross-scan diff (`/scans/diff?a=...&b=...` 3-column New / Resolved / Changed via fingerprint), Cmd+K global search (`/search` JSON across resources / findings / checks / providers / saved views; Alpine modal mounted at body level), PDF export (`/scans/{id}/pdf` browser-native save-as via window.print; chromedp escape hatch for v1.5.x). 11 phases; new migration 0005 saved_views (schema v5); 1 new external dep: `github.com/robfig/cron/v3` actually came in v1.4 — v1.5 added no new deps. | The findings explorer Wiz / Snyk users will want to switch to |
| ~~v1.6~~ ✅ | **Live Operations** (v1.6.0 shipped 2026-05-20, #38) — SSE event bus (`/api/v1/events`) with monotonic-cursor replay + 5-min ring (phase 0); live dashboard cards via Alpine.js subscriber + per-page widgets (phase 1, `scansLive()` / `findingsLive()` / chrome `Live`/`Reconnecting` pill); per-collector + throttled per-check `scan.progress` streaming via new `engine.Progress` observer interface (phase 2); multi-tab BroadcastChannel sync + 250ms leader election (phase 3, saves daemon connection budget linearly with tab count); toast system on critical findings + scan transitions + webhook receipts (phase 4); `webhook.received` publish on accepted GitHub/generic webhooks (phase 5; WebSocket fallback deferred to v1.7+ — every v1.6 surface is unidirectional so SSE was right shape); admin-only `/admin/logs` live tail with 500-line ring + chained slog handler (phase 6); connection-loss UX polish (phase 7, exponential backoff with ±20% jitter, localStorage cursor persistence across tab handoffs, "replayed N missed event(s)" toast); activity timeline widget on `/scans` with wildcard subscribe + per-type filter (phase 8); F21 carryover — `scans.trigger` column (migration 0007) + webhook trigger metadata persistence rendered inline next to source badge (phase 9). 10 phases; new migration 0007. **Closed all 25 audit gaps from v1.5.1** (F21 closed here; F6 still partial via F7 mirror). | See your fleet live, not on refresh |
| ~~v1.7~~ ✅ | **TUI mode (k9s for compliance)** (v1.7.0 shipped 2026-05-20, #39) — `compliancekit tui` Bubble Tea client (phase 0). Two source modes: `--findings=path.json` (file, offline) + `--server=URL --api-token=…` (daemon, live SSE). Multi-pane layout — providers tree (20%) + findings list (50%) + detail panel (30%); Tab cycles focus (phase 1). Vim keybindings (j/k/g/G/Tab/Enter/Backspace/n/N) + `:command` filter parser (sev=/sev>=/status=/provider=/check=/fw=/reset) + `/search` substring across check + resource (phase 2). `:tail` opens an SSE subscription to `/api/v1/events`; finding.created events append to the list live (phase 3). `R` opens a full-screen resource-tree navigator — provider → resource_type → resource with worst-severity rollup + finding counts (phase 4; `g`/`G` reserved for vim top/bottom so `R` is the binding). In-place actions: `w` waive (daemon POSTs `/api/v1/waivers` / file mode prints YAML), `r` remediate-preview (renders the bash strategy via `remediate.Default`); `a` ack + `c` comment flash as placeholders (real persistence v1.8 collaboration) (phase 5). `:diff <path>` overlays baseline diff with gutter glyphs (+ new, - resolved, ~ changed; fingerprint join via `Finding.Fingerprint()`) (phase 6). `?` help overlay + severity color theming (lipgloss adaptive-color matching the v1.1 CLI palette: CRIT red, HIGH orange, MED yellow, LOW blue, INFO grey) (phase 7). 11 unit tests covering model + commands + diff + graph deterministic surfaces (phase 8; bubbletea teatest goldens deferred). CLI.md documents the full subcommand + keybindings (phase 9). 2 new deps: `github.com/charmbracelet/bubbletea` + `github.com/charmbracelet/bubbles`. | Live in the terminal? Live in compliancekit |
| ~~v1.8~~ ✅ | **Collaboration & workflow** (v1.8.0 shipped 2026-05-20, #40) — 10 phase commits. Migration 0008 lays the collaboration foundation (comments + finding_activity + finding_assignment + resource_owner + resource_follower); `pkg/compliancekit` gains additive `User` + `Comment` types + three Finding fields (Comments / Assignee / Followers) per ADR-014. Per-finding markdown comments via `internal/server/comments` (goldmark + bluemonday tight allowlist — no img, no script, no raw HTML; thread by `Finding.Fingerprint()` so the conversation persists across scans; Comments tab on the side-panel; CommentCount badge). Assignee + owner widgets on the overview tab via htmx swap; `?assignee=me|<id>` filter on the findings explorer. Activity stream — `collab.Activities` with 12 kinds (state_changed/comment_added/edited/waiver_applied/revoked/scan_ran/webhook_event/assigned/unassigned/owner_changed/follower_added/removed) + 8 actor sources; timeline tab renders both scan-history + activity. `@mentions` — `comments.ExtractMentions` regex with lookbehind-style guard against `user@host` false-trigger; `/api/v1/users/search` autocomplete endpoint; Alpine `commentComposer` factory in app.js; inbox row + Slack DM via v0.17 sink. Slack two-way — migration 0009 `slack_thread_mapping`; `/webhooks/slack/events` URL_verification + thread-reply ingest; `/webhooks/slack/commands` `/ck ack <fp> [reason]` / `/ck assign <fp> @user` / `/ck waive <fp> <reason>`; signing-secret HMAC over `v0:<ts>:<body>` with 5-min replay window. GitHub PR two-way — migration 0010 `github_pr_mapping` with N:N fan-out; existing `/webhooks/github` route now handles `issue_comment.created` events; `[bot]` logins filtered to prevent self-echo; per-fingerprint `external_id` suffix preserves redelivery dedup. Jira/Linear two-way — migration 0011 `external_issue_mapping`; `/webhooks/jira` + `/webhooks/linear` (HMAC-SHA256); on status="done"/state="completed" fans out across linked fingerprints + records `waiver_revoked` activity. Teams CRUD — migration 0012 (`teams` + `team_members`); `/settings/teams` admin-only modal-driven; resource follower opt-in widget. Inbox 2.0 — migration 0013 adds snoozed_until/muted_thread_id/event_type + `inbox_prefs` (timezone, DND window, daily/weekly digest, per-event-type routing); snooze presets (1h/4h/tomorrow/next_week); `buildDigest` markdown summary; `/inbox/prefs` page + `/inbox/digest/preview` JSON output. 2 new deps: `github.com/yuin/goldmark` + `github.com/microcosm-cc/bluemonday`. Outbound mapping writes (Slack thread map, GitHub PR map, Jira/Linear ticket-create map) deferred to v1.8.x — inbound + schema + read paths ship now. | Findings stop being a wall of text, start being a conversation |
| ~~v1.9~~ ✅ | **Workflow automation / rules engine** (v1.9.0 shipped 2026-05-20, #41) — 9 phase commits. Migration 0014 lays `rules` + `rule_runs` (JSON condition/action blobs + simulated flag). New `pkg/compliancekit/rules` subpackage exports Rule/Condition/Term/Action + Trigger constants; cmd/genapi extended to walk subpackages so api-check covers it. Internal engine: `rules.Registry` for ConditionEvaluator + ActionDispatcher; AND/OR composition with per-term `negate`; `WithSimulator()` returns a sibling that records simulated=1 + suppresses dispatch. Condition library (11 kinds): severity / framework / provider / resource_type / resource_tag / check_id / finding_age / drift_delta / time_of_day / day_of_week / status. Action library (6 kinds): notify (inbox or v0.17 sink-routing via Hooks.Notifiers), assign, waive (single-approver default), comment, tag (record-only at v1.9.0), audit_only. /rules nav + visual builder with admin-only writes; Alpine `ruleEditor` factory in app.js reads initial state from data-* attrs (strict CSP intact); export.yaml for git versioning. Cron-driven scheduled rules (migration 0014 trigger='cron' + 30s `rules.CronLoop` using robfig/cron/v3; "never fired" anchor at now-24h so daily/weekly waits for next boundary, "* * * * *" fires on next tick). Migration 0015 multi-approver waivers (required_approvers/approvals_json/pending_since/status); `internal/rules/approvals` owns Approve/Reject transitions + ListPending. `internal/rules/expiry` Loop revokes expired waivers + fires waiver.expired onto the engine + drops inbox row. Conditional notification routing via `notify` action's `sink` param; Hooks.Notifiers map fans to v0.17 sink instances. `Engine.Simulate` 30-day replay returns {WouldFire, FindingsConsidered} per rule; persists detail to rule_runs with simulated=1; /rules/{id}/simulate POST surfaces the count via a flash. 2 new deps: github.com/robfig/cron/v3 (already vendored for v1.5.1 schedules) + no extra v1.9-only deps. Outbound v0.17 sink wiring into Hooks.Notifiers + cron-loop wire-into-daemon-boot deferred to v1.9.x — daemon-side hook injection is one CLI commit. | Automate the boring stuff your runbook used to do |
| ~~v1.10~~ ✅ | **Accessibility, i18n, keyboard excellence** (v1.10.0 shipped 2026-05-21, #42) — 10 phase commits. WCAG AA audit via @axe-core/cli in new `.github/workflows/a11y.yaml`; daemon boots in --demo mode and the gate fails on AA violations (login route covered at v1.10.0; full authenticated matrix in v1.10.x once cookie-bearing fetches land). Skip-to-content link + polite + assertive ARIA live announcers in base.html; focus-visible outline ring on every interactive element. New `internal/server/ui/src/a11y.js` owns skip-link wiring + global Escape dismiss + modal focus traps (data-ck-focus-trap auto-installs on htmx swaps) + inline help panel via `?`-key. Bulk aria-hidden on 28 templates' decorative SVGs + aria-current="page" on active nav. v1.6 SSE handlers route through window.ck.announce — critical-finding + scan-failed are assertive interrupts; scan-completed + webhook + reconnect-backlog are polite. Third palette (high-contrast) auto-selected via prefers-contrast: more or forced via the operator's contrast picker (auto/more/normal) — validated against WCAG AAA contrast ratios. prefers-reduced-motion zeros every CSS animation + transition. Severity + status pills get glyph prefix (‼/▲/◆/▼/· + ✓/✗/⚠/–) so colour never alone carries meaning. New `internal/i18n/` package wraps github.com/nicksnyder/go-i18n/v2 + golang.org/x/text/language; 6 locales (en/es/fr/de/ja/pt-BR) with ~75 keys each; LocaleFromRequest reads `ck-locale` cookie or Accept-Language; T(ctx, key) helper. Inline help (`?`-key) opens a right-docked dialog from <template id="ck-help-content">; topbar grows a help button. 2 new deps: github.com/nicksnyder/go-i18n/v2 v2.6.1 + (promoted to direct) golang.org/x/text. Mechanical sweeps deferred to v1.10.x: per-page help-content templates beyond the global default; authenticated axe-core matrix; native-language picker names (Español/Français/日本語); template-side T() wiring (passing the locale through every render). | Compliance for every operator, every language, every keyboard |
| ~~v1.11~~ ✅ | **Performance & scale** (v1.11.0 shipped 2026-05-21, #43) — 10 phase commits. Cursor pagination on /api/v1/scans + /findings + /resources via opaque base64-JSON `(sort_key, id)` token; legacy `?page=` OFFSET path coexists for one minor + removed at v1.12. content-visibility row windowing (.ck-vrow / .ck-vrow-sm / .ck-vrow-lg) lets the explorer scroll smoothly at 100k rows. Migration 0016 lays composite indexes (idx_findings_created_id, idx_findings_severity_created, etc.) so the cursor + filter compositions hit the index alone; internal/server/store/sql_perf.md docs the hot query paths + EXPLAIN snapshots + "when to add an index" guide. Migration 0017 materializes scans.resource_count + severity_breakdown_json computed at scan-completion; v1.10-era rows default 0/'{}' so the migration is zero-cost. New internal/server/compress brotli (preferred) + gzip + Vary middleware skips SSE / non-compressible / <1 KiB. New internal/server/etag weak-ETag + If-None-Match → 304 middleware (compress wraps inside etag so the hash is the uncompressed payload). New internal/server/respcache LRU (default 512 × 60s) with per-user-scope keys; respcache.Invalidator subscribes to the v1.6 bus + busts findings: / scans: / resources: prefixes on finding.created / finding.resolved / scan.completed / scan.failed. New internal/server/slowlog package with Recorder + per-request Tracker; TimeQuery helper logs >100ms queries with redacted SQL + groups by sha256(normalized SQL). v1.11 phase 8 adds compliancekit_worker_queue_depth Prometheus gauge + autoscaling burst-pool (1min median >5 → +1 worker, 5min median <1 → -1, cap at Concurrency+4); Server.QueueDepthObserver returns the gauge as a structural worker.DepthObserver so cmd/serve avoids the circular dep. New /api/v1/findings.ndjson streaming export — json.Encoder + Flush every 100 rows; cache-no-store + etag-skip. `make bench-server` benchmarks (100k findings / 10k resources / 1k scans) target p95 <50ms cursor / <100ms filter-cursor / <30ms scans-list; `make test` adopts -short so the bench seed doesn't slow normal runs. 2 new deps: github.com/andybalholm/brotli v1.2.1 + github.com/hashicorp/golang-lru/v2 v2.0.7. No pkg/compliancekit surface change. | Designed for one team's fleet, performs like it's for ten |
| ~~v1.12~~ ✅ | **Admin & RBAC** (v1.12.0 shipped 2026-05-22, #43) — 11 phase commits. Migration 0018 lays roles + role_permissions + user_roles with 4 built-in roles (admin/editor/viewer/auditor) seeded; pkg/compliancekit/rbac is the new public surface (Resource + Action enums, Role, Permission, Set). /settings/roles permission-matrix UI (admin-only) creates custom roles, edits the Resource × Action grid, assigns/revokes users; every mutation is audit-logged. scopeGate refactored: session-auth requests prefer the role-derived permission set; user with zero roles falls back to v1.5.1 IsAdmin behavior for bootstrap compatibility. SAML 2.0 SSO via crewjam/saml — operators configure IdPs (Okta / Azure AD / Google Workspace / OneLogin / Auth0) via CK_SAML_<TAG>_* env vars; SP-initiated + IdP-initiated flows both work; auto-provisions a local user on first sign-in. SCIM 2.0 server (/scim/v2/Users + /Groups) implemented hand-rolled vs elimity dep; SCIM Groups map 1:1 onto RBAC roles. /settings/sessions admin lists every active session across the directory with revoke (stolen-laptop response); self-revoke is blocked at handler. /audit gets filter bar (q + actor + entity + since/until) and admin-only NDJSON + CSV exports up to 100k rows. POST /settings/yaml/import round-trips compliancekit.yaml — export → wipe → import → re-export is byte-stable per TestYAMLRoundtrip. Migration 0019 + internal/server/backups owns SQLite VACUUM INTO + pg_dump wrappers + a catalog; /settings/backups admin UI; restore is documented as a manual step. /settings/tokens admin UI for API token CRUD + zero-downtime rotate (issue replacement with same scopes + 7-day grace logged) + scope picker + expiry picker; plaintext shown once. Migration 0020 adds prev_hash + row_hash on audit_log; every AuditLog call SHA-256(prev || canonical-json(row)) chains; compliancekit serve audit verify walks the chain and exits 1 + reports broken row IDs on tamper. Audit timestamps switched to RFC3339Nano so rapid-fire inserts chain deterministically. 3 new direct deps: github.com/crewjam/saml v0.4.14 + transitive (beevik/etree, mattermost/xml-roundtrip-validator, russellhaering/goxmldsig, golang-jwt/jwt). New pkg/compliancekit/rbac subpackage covered by api-check. Cmd+K settings search / settings auto-save / per-token rate limit / SAML+SCIM live IdP harnesses deferred to v1.12.x. | Admin a fleet, not a single instance |
| ~~v1.13~~ ✅ | **Plugin SDK + marketplace prep** (v1.13.0 shipped 2026-05-25, #45) — 10 phase commits. New pkg/compliancekit/plugin subpackage (Manifest + Kind enum + Plugin + Catalog interface + Validate with typed sentinel errors); api-check covers it. compliancekit checks new <id> scaffolder generates a runnable plugin directory (Rego-default or --go subprocess) with manifest + README + sample check body; ID validated against ^[a-z0-9][a-z0-9.\-]{1,58}[a-z0-9]$ before any filesystem write. internal/server/plugins.Catalog walks $XDG_DATA_HOME/compliancekit/plugins/ (or --plugins-dir override); per-directory load errors split from hard errors so partial-failure surfaces without blocking healthy packs. CosignVerifier validates manifest.yaml against sibling signature.sig under operator-supplied PEM pubkey (ECDSA P-256 default + Ed25519); signature.sig may be base64 or raw; keyless Sigstore deferred to v1.13.x. Sandbox.HTTPClient returns a *http.Client whose net.Dialer.Control hook rejects any host outside the manifest's DeclaredEgress; rule shapes: exact / host:port / *.subdomain (single label). Watcher debounces fsnotify events (500ms default) into Catalog.Refresh calls + bumps Plugin.Generation so in-flight scans can cache the policy version they started with. Migration 0021 lays notify_templates(kind, name, body); /settings/notify-templates admin UI ships a Go text/template editor with htmx live preview against a canned finding payload (300ms debounce, upper/lower/title funcs). compliancekit plugins install/list/update/remove/verify CLI surface against the same XDG dir the daemon discovers from; install validates the freshly-copied pack via Catalog.Refresh + rolls back on failure. /settings/plugins UI shows installed plugins (signature status + hot-reload generation) + a static community-packs tab (hello/aws-iam-strict/slack-rich); v2.9 swaps that for a registry feed. examples/plugins/hello/ is the canonical starter pack referenced by the docs; TestReferencePlugin_HelloDiscoverable smoke-tests the install → refresh round-trip. Total schema migrations through v1.13: 21. 1 new direct dep: github.com/fsnotify/fsnotify v1.10.1 (promoted from indirect). OCI / registry plugin pull, WASM runtime, plugin payment all deferred to v2.9 per ADR-016. | Your checks. Your remediation. Your distribution. |
| ~~v1.14~~ ✅ | **Reporting renaissance** (v1.14.0 shipped 2026-05-25, #46) — 10 phase commits. Migration 0022 lays dashboards + dashboard_widgets (12 widget kinds: score_gauge / severity_donut / framework_bar / framework_radar / finding_list / resource_table / sparkline / heatmap / treemap / sankey / markdown / executive_summary) + dashboard_layouts (per-user overrides). New internal/server/dashboards package: Store with full CRUD + grid clamping (1..12 cols, 1..24 rows) + SaveLayout validation + team-wide-vs-private visibility filter. /dashboards index + per-dashboard canvas (12-col CSS grid, ?edit=1 toggles palette + delete affordances); admin-or-owner edit gate. Four built-in templates (exec / aws / k8s / soc2) cloneable via Store.CloneTemplate with rollback on partial-failure. internal/report/chart.go ships hand-rolled vanilla-SVG heatmap (intensity ramp), treemap (squarified greedy worst-aspect), sankey (two-column with cubic-bezier links), radar (4 concentric gridlines + even-spaced spokes); every drawer pre-wires v1.18 hooks (data-ck-bucket + data-ck-tooltip + <title>). internal/report/summary.go renders the executive-summary markdown body (score / delta / top findings / wins / regressions / framework headline / timestamp footer) — pure templating, no LLM. /scans/compare 3-up multi-scan view reuses the v1.5 diff picker. Migration 0023 + ScheduledReport storage with cron-validated CreateScheduledReport + RunDueReports (Dispatcher interface; stamps last_status + advances next_run_at on every tick whether dispatch succeeded or failed). Migration 0024 + SharedLink with 256-bit token, TradeShare gated by revoked_at + expires_at (single ErrShareGone for all three failure modes so live tokens aren't fingerprintable), WatermarkText helper for per-recipient "for X — YYYY-MM-DD". Migration 0025 + AuditPackProfile records canonical-artifact picks (closed set: findings.csv / vulnerabilities.csv / secrets.csv / poam.oscal.json / waivers.json / scan.json / summary.md) + dashboard PDF IDs. PrintDocument + RenderPrintHTML with @page CSS (header / footer / page-numbers / TOC leader dots) + rotated watermark overlay; PDFRenderer interface with HTMLOnlyRenderer (no-Chrome fallback) + ChromedpRenderer (page.PrintToPDF). 1 new direct dep: github.com/chromedp/chromedp + transitive cdproto. Total schema migrations through v1.14: 25. No pkg/compliancekit surface change. Drag-handle persistence (HX-Request layout save), audit-pack assembly, scheduled-report admin UI, /settings/shared-links revoke UI, registry-side templates-as-code deferred to v1.14.x. | From findings.html to a board deck — without leaving the app |
| ~~v1.15~~ ✅ | **Deploy & operate** (v1.15.0 shipped 2026-05-25, #47) — 10 phase commits + doc sweep + cosign-pin CI fix. **Helm chart** at `oci://ghcr.io/darpanzope/compliancekit-chart` (every knob documented; `helm lint` clean; SQLite default + `ha.enabled` toggle). **Kustomize** base + dev/staging/prod overlays (prod swaps SQLite PVC → Postgres `Secret` via `$patch:delete`). **K8s operator** with `ComplianceSchedule` + `ScanJob` CRDs (hand-rolled DeepCopy, no `controller-gen` build-time dep); install bundle in `deploy/operator/`. **Terraform modules** for AWS / GCP / DO / Hetzner — compute + Postgres + LB+TLS + DNS per cloud. **Distroless multi-arch image** (`gcr.io/distroless/static-debian12:nonroot`, amd64 + arm64) + 30 MiB image-size budget via crane. **HA Postgres + leader election** via `pg_advisory_lock` (key `0x636B5F6C656164` "ck_lead", disjoint from migration lock); session-scoped via `*sql.Conn`; SQLite short-circuits leader=true; worker pool drain gated on `leader.IsLeader()`. **systemd unit + NixOS module** with full hardening (`NoNewPrivileges`, `ProtectKernel{Tunables,Modules,Logs,ControlGroups,Clock,Hostname}`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `SystemCallFilter=@system-service ~@privileged @resources`, empty `CapabilityBoundingSet` + `AmbientCapabilities`; `systemd-analyze security` < 2.0 target). **Deep `/health/ready`** with `ReadinessRegistry` + per-probe Timeout; JSON 200 all-pass / 503 any-fail; three checks wired (db, migrations, leader). **Grafana dashboard bundle** — `deploy/grafana/dashboards/{operations,findings,worker-pool}.json` (schemaVersion 39, `$instance` template var); README with Prometheus scrape config + starter alerts. **One-line installer** at `deploy/install.sh` (232-line POSIX-bash; resolves latest via GH API, verifies sha256 + cosign keyless via Fulcio cert + Rekor, installs to `/usr/local/bin`, optionally wires systemd; canonical URL `raw.githubusercontent.com/darpanzope/compliancekit/main/deploy/install.sh` — vanity `compliancekit.dev` shortcut deferred). **CI fix**: pinned `cosign-release` to v2.6.3 after the installer fell back to `@main` and sigstore bundle policy tightened mid-day. 1 new direct dep: `sigs.k8s.io/controller-runtime` v0.24.1 (operator only). Total schema migrations through v1.15: 25 (unchanged from v1.14). No `pkg/compliancekit` surface change. | Production-ready from clone to systemd |
| ~~v1.16~~ ✅ | **Mobile / PWA** (v1.16.0 shipped 2026-05-27, #56) — 8 phase commits. **PWA manifest** at `/manifest.webmanifest` (standalone display, theme_color matching app.css indigo-700, start_url=/scans, 3 icons + 3 shortcuts) + procedural icon generator under `cmd/genicons` shipping 5 PNGs (192/512/maskable-512/apple-touch-180/favicon-32). **Service worker** at `/sw.js` (hand-rolled, no Workbox build dep): stale-while-revalidate for `/assets/*`, network-first for `/api/v1/*`, offline-fallback page for navigations; versioned cache name (`ck-cache-v1.16.0`) so deploys invalidate cleanly; precaches the UI shell + manifest + icons + /offline during install. **Install banner** with two flows (Chromium captures `beforeinstallprompt` → native install UI; iOS Safari shows Share-sheet copy); `display-mode: standalone` suppresses on installed PWAs; `ck-install-dismissed` localStorage suppresses on dismissed. **Mobile-first responsive sweep** — `xs:` breakpoint at 400px (iPhone-SE viewport), `.ck-table-cards` utility turns horizontal tables into stacked cards at <640px via `data-label` attrs, `pb-safe`/`pt-safe` env(safe-area-inset-*) shims for iOS PWA mode. Applied to scans + findings tables; pattern documented for incremental adoption. **VAPID Web Push** — `internal/server/push/` package, migration 0026 (push_subscriptions + app_kv), 4 API endpoints (`/api/v1/push/vapid-public-key`, `/subscribe`, `/unsubscribe`, `/subscriptions`), `/settings/notifications` UI with pushSubs() Alpine factory, sw.js push + notificationclick handlers, VAPID keypair generated + persisted at first boot (reused forever — rotation invalidates subs, future v1.16.x concern). Wire-into-finding-producer (fire on critical severity) deferred to v1.16.x. **Quick-scan flow** at `/quick-scan` — single-tap mobile-optimized scan trigger (provider card grid → SSE progress bar → top-5 actionable findings inline; no nav escape between "kick scan" and "see what's wrong"). **1-handed UX + swipe gestures** — bottom action bar (mobile-only, 5 thumb-reachable actions: Scans, Quick scan, Findings, Inbox, Menu; pb-safe for iOS home-indicator clearance), swipe gesture wiring via `data-ck-swipe` (80px horizontal threshold, ≤40px vertical wiggle; emits `ck:swipe-left` / `ck:swipe-right` custom events; re-installed after every htmx swap; touch-only — desktop unaffected); finding rows emit `ck-finding-action` window events on swipe (action sink wires at v1.16.x). **Offline mode polish** — sw.js broadcasts `ck:offline` postMessage on cached-fallback fire; src/app.js renders a top-of-viewport warning banner with Retry button; auto-clears on `online` event. 1 new direct dep: `github.com/SherClockHolmes/webpush-go` v1.4.0 (+ `golang-jwt/jwt/v5` transitive). Total schema migrations through v1.16: 26. No `pkg/compliancekit` surface change. | Compliance you can check in line at the coffee shop |
| ~~v1.17~~ ✅ | **Data warehouse bridges** (v1.17.0 shipped 2026-05-27, #57) — 8 phase commits. New `internal/warehouse` package: Writer/Loader/Source interfaces + SchemaFor() canonical 4-table schemas (findings, resources, scans, audit_log) at SchemaVersion=1; **ParquetWriter** via apache/arrow-go/v18 (pqarrow.FileWriter, Snappy, 8192-row batches, KV metadata stamps schema+table); **NDJSONWriter** (one JSON line per row, leading `_meta` for DuckDB read_ndjson_auto); DBSource with optional SnapshotCursor for v1.17 phase 6 immutable reads; Exporter orchestrates Writer-per-table. **CLI**: `compliancekit warehouse export --format={parquet,ndjson}` + `compliancekit warehouse load --to={bigquery,snowflake,redshift}`. **BigQueryLoader** via cloud.google.com/go/bigquery with ADC + ensure-dataset + auto-create-table from SchemaFor() + stable per-row InsertID for 1-min dedup. **SnowflakeLoader** snowsql-style PUT-to-user-stage + COPY INTO with MATCH_BY_COLUMN_NAME via gosnowflake; CREATE TABLE IF NOT EXISTS with VARCHAR/NUMBER/FLOAT/BOOLEAN/TIMESTAMP_TZ mapping. **RedshiftLoader** S3-stage via PutObject + COPY via Redshift Data API with FORMAT AS JSON 'auto'; polls DescribeStatement until Finished/Failed; standard AWS SDK auth chain. **OpenLineage emit** — hand-rolled 4-field event POST (no OL Go client dep); EmitScanStart/EmitScanComplete/EmitScanFail on the RealRunner; CK_OPENLINEAGE_URL env opts in (empty = no-op). **Snapshot API** — migration 0027 + 5 routes (POST/GET list/GET one/GET findings/DELETE) on `/api/v1/snapshots`; captures max(id) per table at create; content_hash = SHA-256 of joined cursors; composes with the warehouse loaders for "load the q1-2026 snapshot to BigQuery" workflow. **Scheduled warehouse sync** — migration 0028 warehouse_schedules + Schedule/ScheduleStore/Scheduler in internal/warehouse; 30s cron-driven loop; per-target hook factory + daemon-side scheduler boot deferred to v1.17.x. **Webhook fan-out via v1.9 rules action** also deferred to v1.17.x. **docs/warehouse-schema.md** is the loader contract document. New direct deps: apache/arrow-go/v18 + cloud.google.com/go/bigquery + snowflakedb/gosnowflake + aws-sdk-go-v2/service/redshiftdata + aws-sdk-go-v2/service/s3. Total schema migrations through v1.17: 28. No `pkg/compliancekit` surface change. | Your warehouse already runs the reports — feed it |
| v1.18 | **Design system & visual polish** — `internal/server/ui/design/` formalized (tokens.css for colors / spacing / radii / shadows / typography / motion + a `<component>.html` library + `/design` live docs route), loading skeletons everywhere (spinners eliminated for >200ms ops), page-top nprogress bar, 6 vendored Framer-style easing curves + 4 standard durations, toast queue with slide+fade+stack, optimistic UI on every form (assign/waive/comment/ack), ~30 vanilla-SVG empty-state illustrations theme-aware across light/dark/high-contrast, micro-interactions audit (every hover/focus/active/press), Linear-style initials-gradient avatars, status-pill system, card depth tokens (flat / raised / floating / glass), sprite expanded 22 → 100 symbols, chart interactivity (rich hover tooltips, click-to-drill, waiver/baseline annotations, brushing), magic moments (zero-critical-findings confetti, score-improved celebration card, weekly streak badges bronze/silver/gold), brand kit per org (logo + favicon + primary-color override with contrast validation). ~12 phases; new ADR-017 codifies the design-system contract. | Every pixel feels intentional — Linear-tier polish |
| v1.19 | **Onboarding 2.0 + global search + table excellence** — feature-tour overlay system ("Press . to try the new ..." — vanilla, no Shepherd.js), changelog modal on first login after upgrade with deep links to touched UI areas, in-app feedback widget (bug / feature / love note → daemon admin queue + optional webhook), first-run product tour (post-wizard orientation), empty-state coaching v2 (illustration + 3-step CTA on every empty), screenshot-grade demo seed data layered on the v1.4 `--demo` flag (~500 findings × ~150 resources × multi-week trend), global Cmd-K / `/` search (findings + resources + scans + users + waivers + settings + docs), Sublime-style fuzzy ranking, recent + suggested searches, sticky search bar in nav, discovery surfaces (home "Did you know..." auto-rotating cards), table 2.0 (drag to resize / drag to reorder / pin left or right columns + visibility menu + saved column sets), inline edit (notes / tags / assignee), bulk-actions toolbar (multi-select → waive/ack/assign/export), detail-panel polish (resizable + detachable + j/k item nav), keyboard-shortcut discoverability badges next to every clickable action. ~10 phases. | First 10 minutes feel guided; daily search is instant; tables feel modern |
| v2.0 | Next API surface refinement (`pkg/compliancekit` v2 if needed; otherwise reserved) | Held for the next breaking-change cycle |
| v2.1 | Multi-tenant / organizations | MSP-friendly: one binary, many clients |
| v2.2 | Trust Center generator | Your public security page, generated |
| v2.3 | GRC layer — risk register, vendor register, CAIQ/SIG templates, training tracking (ADR-004 re-slotted from v1.8) | Risk + vendors + questionnaires in repo |
| v2.4 | Auditor portal (auth-gated, time-boxed, watermarked exports) | Give your auditor read-only access |
| v2.5 | macOS + Windows + BSD hardening | Hardening for every machine you own |
| v2.6 | **Tail clouds — deep coverage of every SaaS surface a modern company touches** (~26 phases) — shared `internal/collectors/saascommon` foundation (HTTP client + OAuth + rate-limit awareness + token-rotation hooks + per-vendor health probe + retry-with-backoff + secret-handling parity with v0.14 ADR-010). Per-vendor deep packs: **Cloudflare** (zones+DNS, R2, Workers + Workers AI, Tunnels, Access/Zero Trust, WAF + Bot Management, Pages, D1+KV+Queues, Stream + Images, Email Routing, Magic Transit; ~80 checks); **GitHub** (org settings, repo settings, branch protection, secrets + dependabot, code scanning, GitHub Advanced Security, actions runners + workflow security, audit log retention, packages + releases signing, environments + reviewers, OIDC trust policies, copilot org policy; ~100 checks); **Google Workspace** (Admin SDK posture, Drive sharing, Gmail security, Vault retention, Endpoint Management, OAuth apps inventory, Alert Center, Context-Aware Access; ~60 checks); **Microsoft 365 + Entra ID** (Defender for Office/Endpoint, Purview DLP + records management, Sentinel, Intune compliance policies, conditional access, audit log retention, app consent; ~80 checks); **Vercel** (project settings, env vars + sensitive flag, deployments hygiene, log drains, OIDC token issuance, team SSO + SAML, build env isolation, edge config, env-protection rules; ~30 checks); **Linode / Akamai Cloud** (compute, NodeBalancers, Object Storage, Cloud Firewalls, VLANs, LKE, DNS, longview agents; ~40 checks); **Vultr** (instances, block storage, VKE, firewall groups, object storage, DNS, reserved IPs, snapshot retention; ~30 checks); **Fastly** (services, ACLs, dictionaries, TLS subscriptions, log streaming endpoints, image optimizer, compute@edge; ~25 checks); **Slack workspace** (SCIM, app inventory + OAuth scopes, DLP, channel retention, IdP enforcement, audit log streaming; ~25 checks); **Atlassian Cloud** (Jira / Confluence org settings, app inventory, SSO + SCIM, audit log, OAuth grants, anonymous-access posture; ~30 checks); **Okta** (admin posture: sign-on policies, factor enrollment policy, app catalog hygiene, log streaming, behavior detection, system log retention; ~25 checks); **Zoom** (security policies, recording retention, SSO config, App Marketplace approvals, meeting defaults, webinar perms; ~15 checks); **Stripe** (restricted keys, webhook signing, IP allowlist on dashboard, Radar fraud rules, team perms + audit, sigma data retention; ~20 checks); **HubSpot + Salesforce** (data perms + sharing, OAuth connected apps, integration hygiene, IP restrictions, password policy, audit trail retention; ~25 checks); **Notion** (workspace admin, integrations inventory + scopes, sharing perms, page-share-with-link audits; ~15 checks); **1Password + Bitwarden** (vault sharing audit, SCIM, recovery policy, breach Watchtower posture, login policies; ~20 checks); **Tailscale** (ACL posture, MagicDNS hygiene, key expiry policy, device posture rules, SSO, tagged-server lifecycle; ~20 checks); **Observability vendor posture — Datadog / New Relic / PagerDuty** (API key hygiene + scopes, integration inventory, log retention, sensitive-string scrubbing rules, SSO + SCIM, audit log retention; ~25 checks); **Transactional email — Postmark / SendGrid / Mailgun** (DMARC + SPF + DKIM alignment per sending domain, webhook signing, suppression list hygiene, log retention, IP reputation surfacing, API key scopes; ~20 checks); **Modern PaaS — Render / Fly.io / Railway** (env vars + secrets, IP allowlist, build cache poisoning posture, audit log, custom-domain TLS posture, log drains; ~30 checks); **Discord** (server hardening — bot perms, audit log, member screening, AutoMod posture, channel perms hygiene; ~15 checks); **iPaaS — Zapier / n8n / Make** (connection inventory + OAuth scope sprawl, retention, IP allowlist, secret-handling per step; ~15 checks); **Legacy platform — Heroku** (app config, add-on security, dyno hardening, build pack pin posture; ~15 checks). Framework wiring: **CIS SaaS Benchmarks** for the big-3 (Google Workspace / M365 / GitHub) + custom **"SaaS-Hardening v1"** framework spanning the whole tail + ATT&CK-for-SaaS coverage. Tail-cloud aggregator dashboard + cross-vendor identity map (links OAuth app ↔ vendor + person ↔ vendor for sprawl auditing). Phase 0 lays primitives; phases 1–24 are per-vendor; phases 25 + 26 are framework + aggregator. | Every SaaS surface your SaaS touches — properly, not superficially |
| v2.7 | OSCAL ecosystem (catalogs in, assessment results out) + SCAP DataStream import | FedRAMP-curious? OSCAL in, OSCAL out |
| v2.8 | Risk score + executive risk PDF + time-series dashboard | One number for your board |
| v2.9 | Plugin marketplace — federation layer on top of v1.13 SDK (registry, ratings, discovery), cosign-verified | Install a check pack with one command |
| v2.10 | K8s operator — full reconciler (CRDs `ComplianceScan`, `ComplianceProfile`, `ComplianceWaiver`); extends v1.15 basic | Reconcile compliance from a CRD |
| v2.11 | Auto-remediation (opt-in, dry-run default, full audit log) — ADR-006 unchanged | Fix it for me — if you really want |
| v2.12 | **UI/UX 3.0 — Studio-grade interactions** — command palette everywhere (every page accepts Cmd-K, every list filters live), drag-drop everywhere (dashboards / saved views / column order / waiver bulk move / Kanban-style finding triage), real-time collab cursors + presence chips + selection broadcasting (built on the v1.6 SSE bus), chart library refresh (interactive Sankey + sunburst + risk heatmap + bullet + waffle with cross-filter brushing), motion language v2 (Framer-grade choreography — staggered list reveals, FLIP for layout transitions, shared-element across pages), illustration catalog (60+ vanilla-SVG empties tuned per theme), theme builder + brandable white-label (per-org logo + favicon + 3-color picker + dark-mode override + custom font), in-app changelog + spotlight tours (auto-triggered after every minor upgrade), Smart Empty States 2.0 (per-page coaching + 1-click "show me an example"), micro-animations on every CTA (button press depth, focus ring spring, optimistic state lift) | Linear / Vercel / Wiz-tier polish on every page |
| v2.13 | **Documentation 2.0** — `docs.compliancekit.io` static-site (Hugo + a vendored theme) with multi-version selector (v1.x current / v0.x archived) + Algolia-quality client-side search (lunr or pagefind) + dark mode + mobile-first; full **handbook** (architecture deep-dives, threat model, ops runbooks, on-call playbook, post-mortem template); per-framework playbooks ("SOC 2 in 30 days with compliancekit", "PCI v4 in 60 days", "HIPAA in 45 days"); 20+ video walkthroughs (asciinema for CLI flows, Loom for UI flows, hosted on YouTube + linked from docs); cookbook 2.0 (50+ end-to-end recipes — from "monitor my homelab" to "ship a Trust Center"); interactive API explorer (Swagger UI for `/api/v1` + Try-It on the live demo daemon); embedded LLM doc-search (local Ollama-friendly + OpenAI-compatible, opt-in); changelog-as-blog (every minor gets a launch post with screenshots) | Docs that contributors fork from, not just read |
| v2.14 | **Zero-trust deploy** — mTLS everywhere (daemon ↔ daemon, daemon ↔ Postgres, daemon ↔ webhook receivers; auto-renewing via cert-manager or built-in CSR loop), SPIFFE/SPIRE identity (workload attestation; SVIDs for every daemon replica), secrets via Vault / Infisical / SOPS / sealed-secrets / external-secrets-operator (no plaintext env vars in HA), NetworkPolicy + Cilium L7 templates shipped, seccomp + AppArmor profiles + landlock LSM on Linux, SLSA L4 build provenance + attestations published to Sigstore, hardware-attested boot docs (Secure Boot + TPM + measured boot), BYOK customer-managed encryption keys (envelope encryption for sensitive columns), IP allowlist + geo-fencing middleware, OWASP ASVS L3 self-audit + report committed quarterly | Defense-grade defaults out of the box |
| v2.15 | **Code health pass** — full surface-area audit (`internal/` package boundaries reviewed, ~20% dead-code elimination expected via `unused` + `deadcode` analyzers in CI), dependency minimization (drop transitives where direct alt exists; bin-size budget reduced from 25 MB → 20 MB target), performance budgets in CI (`go test -bench` regression gate: p95 query / startup time / RSS / goroutines-at-rest), allocation regression tests (`-benchmem`), structured logging audit (every package uses `slog` with stable attribute names; structured-log schema documented), error-handling consistency pass (every external boundary returns typed sentinels via `errors.Is/As`; `fmt.Errorf` audited for `%w`), removal of `interface{}`/`any` where a concrete type fits (generics where helpful), doc comments to 100% public API + `golint`/`staticcheck` ST1020 gate, golangci-lint v2 enabled with `gocritic` + `revive` + `prealloc` + `errchkjson` | A codebase that reads like it was reviewed line-by-line |
| v2.16 | **Test pyramid maturity** — fuzz testing on every parser (`go test -fuzz` corpus checked in for SARIF / OCSF / OSCAL / Trivy / Grype / Checkov / gitleaks / yaml / rego / API request bodies), property-based tests (`pgregory.net/rapid`) for ResourceGraph + Engine + Rules, mutation testing (`go-mutesting` baseline + CI gate at >80% mutation kill rate on core packages), chaos engineering (toxiproxy fault injection on Postgres + webhook receivers + SSE clients; expected DLQ + retry behavior asserted), snapshot tests covering every HTML route + every reporter format (gotest.tools golden), golden-file coverage 100% across `internal/report/` + `internal/checks/`, weekly integration-test fleet on every cloud (AWS / GCP / DO / Hetzner / K8s — burns ephemeral accounts, posts SLO report), e2e Playwright matrix (chromium + firefox + webkit; touches every primary user journey), perf regression gate blocks PRs above a budget | The bug you'd ship lands as a test you're proud of |
| v2.17 | **Developer experience** — `.devcontainer/` (codespaces-ready Go + Node + cosign + grafana-cli + all CLI deps), `make bootstrap` + `make smoke` scripts for first-90-seconds, video onboarding ("zero to first PR" walkthrough), Plugin SDK 2.0 (richer scaffolder — Rego / Go-subprocess / WASM blueprints, codegen for boilerplate, runnable starter pack repo template), CI templates for plugin authors (`.github/workflows/check-pack.yaml` published as a re-usable action), opt-in anonymous telemetry (PostHog self-hosted; what version + which provider counts + which CLI commands, never finding bodies), ADR generator (`make adr` opens `$EDITOR` with the template + auto-increments), public RFC process (`/rfcs/` directory + `gh issue create` template + 14-day comment window), public roadmap board (GitHub Projects v2 mirroring milestones), contributor portal (`docs.compliancekit.io/contribute` with good-first-issue feed + maintainer-status criteria) | Make it 10× easier to ship a 1-line PR or a 1000-line plugin |
| v2.18 | **GitOps compliance** — ArgoCD ApplicationSet + Flux Kustomization templates published in `deploy/gitops/`; daemon learns to **open a PR** instead of just notifying on drift (config-as-code waivers + remediations); weekly compliance digest auto-PRed against `compliance/` repo (snapshots + score-over-time committed); dashboards-as-code (`*.dashboard.yaml` declarative spec → DB hydration via `compliancekit dashboards apply`); scan-as-CRD (Kubernetes-native scan trigger via the v1.15 / v2.10 operator); profile-as-config (`compliance/profiles/<name>.yaml` source-of-truth; UI is a read+suggest layer for non-Git users); waiver-as-PR with required-reviewers rules (org-coded YAML config matches v2.9 marketplace's signing model); compliance posture surfaced inside ArgoCD UI via custom health check | The compliance source-of-truth is your git repo, not the daemon |
| v2.19 | **i18n 2.0** — full translation coverage in 10 languages (en / es / fr / de / ja / zh-Hans / pt-BR / ko / it / ar) — every template, every email, every notification body, every CLI string, every framework name; RTL layout (Arabic + Hebrew foundations); locale-aware dates / numbers / currency / time-zones (CLDR via `golang.org/x/text/message` + `display`); translator workflow (Weblate-compatible PO files + Crowdin-compatible JSON; CI gate blocks untranslated key adds beyond a threshold); per-tenant + per-user locale + per-notification-channel override (Slack DM honors recipient's locale, not poster's); on-the-fly language switch (no reload); automated translation-completeness badge in README; community-contributed language packs as v1.13 plugins | A genuinely-global compliance dashboard |
| v2.20 | **Enterprise polish** — SSO MFA enforcement policy (per-role + per-org + step-up auth on sensitive ops), audit immutability (WORM storage adapter: S3 Object Lock + Azure Immutable Blob + GCS Bucket Lock; per-row hash-chain extended to per-second Merkle root anchored to public ledger optionally), retention policies (per-data-type TTL: findings 7yr / audit 10yr / sessions 90d; customizable + GDPR delete-on-request workflow), data residency selector (per-tenant region pin; cross-region replication off by default), session intelligence (anomaly detection on geo / device / hour; risk-scored login w/ step-up MFA), IP allowlist + geo-fencing per-org, customer-managed encryption keys (KMS adapters: AWS / GCP / Azure / HashiCorp Vault Transit), contract-grade SLA documented (99.9 uptime target, 24h RPO, 4h RTO) + status page generator, paid support tier (incident response runbook + 24/7 escalation contract template — not a SaaS pivot, just doc + tooling so an org can buy support from a vendor) | Ready for the Fortune-500 procurement review |

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
- **Account / region resource scope** added to `compliancekit.Resource`:
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

- AWS Organizations multi-account traversal (lands at v1.4 with
  multi-tenant).
- Inspector / Macie / Security Hub *ingest* (lands at v0.13 alongside
  OCSF).
- EKS-specific checks (land at v0.11 with the K8s arc).

---

### v0.8 — GCP ✅ shipped

**Goal:** GCP at the same depth as AWS at v0.7. The SDK pattern is
identical so the second cloud is much cheaper than the first.

**Scope: 25 GCP checks**

| Service | Checks |
|---|---|
| IAM | 6 (no primitive roles, no broad token-creator, audit logging, SA-key age, no user-managed SA keys, no default SA in use) |
| Compute Engine | 5 (no default network, no SSH from 0.0.0.0/0, OS Login enforced, shielded-VM, no broad SA scopes) |
| GCS | 4 (uniform bucket-level access, public-access prevention, versioning, access logging) |
| Cloud SQL | 3 (no public IPv4, automated backups, deletion protection) |
| Cloud Logging | 2 (long-term sink exists per project, log bucket retention ≥365d) |
| KMS | 2 (encrypt/decrypt key rotation ≤90d, admin/user role separation) |
| BigQuery | 3 (no public datasets, no allAuthenticatedUsers, default CMEK) |

**Plumbing**

- New collector at `internal/collectors/gcp/` using
  `cloud.google.com/go`. Per-API client pooled per project.
- Authentication: `gcloud` ADC, explicit service-account JSON,
  Workload Identity Federation when running in the Action. Same
  shape as AWS — env-first, file fallback, federated for CI.
- Resource scope adds `project_id` to `compliancekit.Resource`. Fleet-wide
  scans against an organization happen via the `--projects` filter
  (defaults to "all visible to the credential"), not a special
  org-traversal mode (which lands at v1.4).
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

- Organization-policy ingestion (v1.4).
- GKE-specific checks (v0.11).
- Security Command Center ingest (v0.13).

---

### v0.9 — DigitalOcean depth pass ✅ shipped

**Goal:** the most comprehensive OSS DigitalOcean security scanner.
Cover every DO surface except DOKS (which lands as part of the v0.11
K8s arc to ride one shared codebase across AWS / GCP / DO Kubernetes).
No current OSS tool ships first-class DigitalOcean hardening —
Prowler / ScoutSuite / CloudSploit all skip DO entirely; v0.9 fills
the gap. ADR-007 set the slot at "DO deepening, 25 checks"; the
scope was expanded to ~75 during the v0.8 → v0.9 transition because
the cloudcommon abstractions from v0.7-v0.8 mean each additional DO
check costs ~50-60% of what it would have at v0.7.

**At v0.5 (launch):** 5 DO checks — droplets-no-firewall, ssh-from-any,
backups-disabled, no-tags, old-image. **Shipped at v0.9: 74 DO checks
across 20 service families.**

| Surface | New | Notes |
|---|---:|---|
| **Account / team hardening** | 3 | MFA, recovery email, billing alerts |
| **Droplets** (deepening) | +4 | monitoring + droplet agents, VPC membership, public-IP discipline |
| **Firewalls** (deepening) | +5 | RDP, ANY/ANY ingress, default-deny outbound, broad port ranges, orphans |
| **VPCs / peering / NAT gateways** | 4 | no default VPC, orphan, cross-region peering, NAT presence |
| **Load Balancers** | 5 | HTTPS redirect, TLS ≥1.2, healthchecks, sticky-session security, allowlist |
| **Domains / DNS** | 4 | DNSSEC, CAA, SPF, DMARC |
| **Certificates** | 2 | expiry threshold, deprecated key types |
| **Managed Databases** | 8 | public access, trusted sources, TLS required, backups, version EOL, eviction policy, replicas, private network |
| **Spaces** (S3-compatible object storage; aws-sdk-go-v2/s3 with DO endpoint) | 6 | public ACL, versioning, lifecycle, CORS wildcard, default encryption, access logging |
| **Spaces access keys** | 2 | age, scope |
| **Container Registry** | 3 | private visibility, garbage collection enabled, quota |
| **App Platform** (PaaS) | 5 | env vars marked secret, custom-domain TLS, source repo visibility, alerts, deployment history |
| **Functions** (serverless) | 3 | namespace region, public trigger surface, env-var secrets |
| **CDN endpoints** | 2 | custom cert, TLS version |
| **Block volumes** | 2 | orphan, snapshot recency |
| **Snapshots** (droplet + volume) | 2 | age, public visibility |
| **Reserved + floating IPs** | 2 | orphan IPv4, orphan IPv6 |
| **Account-level SSH keys** | 2 | age, deprecated algorithm |
| **Custom images** | 2 | public visibility, age |
| **Monitoring + uptime checks** | 2 | basic alerts present, uptime checks on public droplets |
| **Projects + tagging** | 2 | default project not used for prod, untagged resources |

Plus existing v0.5 checks: 5. **Total shipped: 74.**

**Plumbing**

- Collector restructure (phase 1): per-service files in
  `internal/collectors/digitalocean/`, per-service errors emit
  `digitalocean.collect_error` placeholders rather than aborting
  the entire scan. Same pattern AWS / GCP use today.
- `cloudcommon.Stamp` applied to every DO resource:
  `AccountID = team-uuid`, `Region = region-slug`. Brings DO
  parity with the AWS / GCP attribution.
- godo SDK client reused (no new dep). Spaces is the one outlier:
  no godo bucket API — uses `aws-sdk-go-v2/s3` (already in dep
  tree at v0.7) with a custom endpoint resolver pointing at
  `<region>.digitaloceanspaces.com`. Auth via `SPACES_KEY` /
  `SPACES_SECRET` env-var pair, mirroring the `DO_API_TOKEN`
  pattern.
- godo pagination already in place from v0.1; reused everywhere.

**Framework mappings**

The CIS Controls v8 + SOC 2 TSC + ISO 27001:2022 Annex A catalogs
already absorb 74 DO checks without expansion. Each check maps to
all three frameworks. No new framework yaml needed.

**Definition of done**

- 74 DO checks, every check framework-mapped, every check
  fixture-backed (graph-test pattern from v0.7/v0.8).
- `cloudcommon.Stamp` on every DO resource; account_id + region
  populated in the evidence pack `control-mapping.csv`.
- Smoke run against a real DO test account with droplets, a LB,
  a managed DB, a Spaces bucket, an App Platform app, and a
  registry, all in a non-default project under a non-default VPC.
- README provider table updated to "DigitalOcean | v0.9 ✅ | 75".
- Companion blog post pitched to the DO community team —
  "the OSS DO posture scanner the ecosystem was missing."

---

### v0.10 — Hetzner Cloud ✅ shipped

**Goal:** the indie-cloud completion. Hetzner is the cheapest
serious-cloud option for the audience; pairing DO + Hetzner gives a
real choice within the same indie-SaaS demographic.

**Shipped at v0.10: 15 Hetzner checks**

| Surface | Checks |
|---|---|
| Servers | 5 (no-backups, rescue-enabled, old-image, not-running, locked) |
| Firewalls | 3 (ssh-from-any, any-port-from-any, orphan) |
| Networks | 2 (orphan, non-RFC1918 IP range) |
| Load Balancers | 2 (no-https-listener, http-not-redirected) |
| Volumes | 2 (orphan, unformatted-orphan) |
| Floating IPs | 1 (orphan) |

**Plumbing**

- New collector at `internal/collectors/hetzner/` using
  `github.com/hetznercloud/hcloud-go/v2` v2.40.0 (+2 MB binary).
- Hetzner has no multi-project surface in the cloud API; one
  token = one project. The collector emits a singleton
  `hetzner.project` anchor with a token-fingerprint AccountID so
  the evidence pack's `control-mapping.csv` stays consistent
  without leaking the full token.
- Per-service-error placeholders (`hetzner.collect_error`) match
  the AWS/GCP/DO pattern; one failing service doesn't lose the
  others.

**Definition of done (delivered)**

- ✅ 15 Hetzner checks, all framework-mapped (SOC 2 + ISO 27001 + CIS v8).
- ✅ Doctor probe verified; smoke-tested in CI.
- ✅ README "Providers" table flipped Hetzner from planned to ✅.

---

### v0.11 ✅ — Kubernetes + EKS / GKE / DOKS-deep (shipped 2026-05-14)

**Goal:** Kubernetes posture across the four clouds we ship — generic
K8s (works on any cluster) plus EKS/GKE/DOKS enrichment so each
cluster's cloud-side configuration is in scope.

**Scope expansion:** the original ~35-check target was expanded to
**139 checks** during implementation — production-grade depth
comparable to kubescape + Trivy K8s combined. No new ADR; the
expansion matches the inline-in-ROADMAP precedent of v0.7-v0.10.

**Shipped (139 checks across 11 phases):**

| Phase | Theme | Checks |
|---|---|---:|
| 0 | Foundations — kubeconfig fanout + cluster anchor + collect_error pattern | 0 |
| 1 | Pod Security (privileged, host-ns, capabilities, run-as-root, RO-rootfs, seccomp, resource limits, image-tag pin, automount-sa-token, hostPath, hostPort, liveness probe) | 18 |
| 2 | Controllers + Jobs (Deployment min-replicas / RollingUpdate / PDB / anti-affinity, StatefulSet PDB, DaemonSet control-plane, Job backoffLimit, CronJob concurrency / history / startingDeadline) | 10 |
| 3 | RBAC + ServiceAccounts (wildcard verbs/resources/apiGroups, full-wildcard, secrets read/write, pods/exec + pods/portforward, impersonate/escalate/bind, create pods, CSR approve, tokenrequest, cluster-admin bindings, anonymous bind, stale role-ref, empty subjects, User subject, default SA automount/used/orphan, image-pull-secrets) | 23 |
| 4 | Network + Ingress + NetworkPolicies (LB source-ranges, no-TLS, externalIPs, NodePort, public-no-NP, Ingress TLS / default-backend / class / dangerous annotations, default-deny ingress + egress, namespace coverage, allow-all ingress/egress, from-all-namespaces, empty selector) | 16 |
| 5 | Secrets + Storage (Secret-via-env, orphan, too-large, immutable, ConfigMap secret-shaped keys, ConfigMap too-large, StorageClass default-multiple / encryption / reclaim, PV reclaim / encryption / orphan, PVC not-bound / orphan / RWX) | 15 |
| 6 | Namespaces + Cluster + Admission (default-workload, ResourceQuota / LimitRange missing, PSA label, stuck terminating, policy-engine present, ValidatingWebhook failurePolicy, MutatingWebhook side-effects, webhook namespace-selector, RQ pod-limit / compute-limit / object-counts, LimitRange container-defaults) | 13 |
| 7 | Nodes (Ready, Disk/Memory/PID pressure, unschedulable, container runtime, OS image age, zone / region labels, control-plane taint) | 10 |
| 8 | EKS enrichment (public endpoint open, private endpoint, secrets KMS, control-plane logging, IRSA OIDC, auth mode, status, version, NG amiType / SSH / version-skew / launch-template) | 12 |
| 9 | GKE enrichment (private cluster, master authorized networks, Workload Identity, Binary Authorization, network policy, shielded nodes, release channel, legacy ABAC, logging + monitoring, NP auto-upgrade / auto-repair / COS / default-SA) | 13 |
| 10 | DOKS enrichment (HA control plane, auto-upgrade, surge-upgrade, maintenance window, VPC attached, registry integration, cluster running, NP autoscale / min-nodes) | 9 |

**Plumbing delivered:**

- New collector at `internal/collectors/k8s/` using `k8s.io/client-go`
  v0.32.1. Kubeconfig-driven discovery — explicit path or KUBECONFIG
  env or `~/.kube/config`. Per-context fanout; `k8s.cluster` anchor
  per context with cloudcommon AccountID = context name, Region =
  parsed API server host. Per-service `k8s.collect_error` placeholders
  on partial failures, matching the v0.7-v0.10 pattern in
  [[reference-collector-patterns]].
- Cloud enrichment via the existing AWS / GCP / DO collectors —
  `aws.eks.*`, `gcp.gke.*`, `digitalocean.doks.*` resources land
  alongside their cloud's other resources. DOKS specifically was held
  back from v0.9 to land here.
- `internal/cli/scan.go` `buildKubernetesCollector` + `doctor` probe.
- `internal/config/config.go` — KubernetesConfig with `kubeconfig`,
  `contexts`, `namespaces`, `exclude_namespaces`.

**Dependencies added (sized in BINARY.md):**

- `k8s.io/client-go v0.32.1` (+ `k8s.io/api`, `k8s.io/apimachinery`)
- `github.com/aws/aws-sdk-go-v2/service/eks v1.83.0`
- `cloud.google.com/go/container v1.51.0`
- godo already shipped DOKS support; no new DO dep.

**Final catalog:** 159 (v0.10) → **298 (v0.11)** = +139 K8s checks.

**Definition of done:**

- ✅ 139 K8s checks total (vs ~35 target); every check framework-
  mapped (SOC 2 + ISO 27001 + CIS Controls v8). CIS Kubernetes
  Benchmark v1.x mappings land at v0.12 (framework expansion).
- ✅ Per-service-file pattern preserved; collector + check files
  named by area (workloads, controllers, rbac, network, storage,
  cluster, nodes, eks, gke, doks).
- ✅ buildXCollector slice pattern reused — kubernetes is one more
  entry in the scan.go buildCollectors slice.
- Pending: end-to-end demos against real EKS / GKE / DOKS / kind
  clusters land in the launch broadcast workflow.

---

### v0.12 ✅ — Framework expansion + tailoring + evidence-pack depth (shipped 2026-05-15)

**Goal:** seven shipping frameworks (up from three) plus auditor-
honest tailoring plus deeper evidence-pack rendering. The original
ROADMAP target was four new frameworks; the implementation expanded
the existing three to their full catalogs as well, and the evidence
pack now surfaces every framework's family/tag metadata in the
summary HTML and control-mapping CSV.

**Shipped (10 phases):**

| Phase | Theme | Output |
|---|---|---|
| 0 | Schema scaffolding | Framework.Category/Source/Tactics; Control.Family/Tags/References; frameworks.TailoringRule + Tailoring; Config.Tailoring |
| 1 | SOC 2 TSC full | 60 controls (CC1-CC9 + A1 + C1 + PI1 + P1-P8) |
| 2 | ISO 27001:2022 Annex A full | 93 controls across 4 themes |
| 3 | CIS Controls v8 full + IG taxonomy | 153 safeguards × IG1/IG2/IG3 |
| 4 | NIST SP 800-53 r5 cloud subset | 131 controls × 14 families |
| 5 | HIPAA Security Rule | 50 implementation specs (required/addressable) |
| 6 | PCI DSS v4.0 cloud subset | 61 sub-requirements × 12 themes |
| 7 | MITRE ATT&CK Enterprise | 12 tactics + 50 techniques (first `category=threat_model`) |
| 8 + 9 | Evidence-pack enrichment + tailoring wiring | tailoring.json; control-mapping.csv +5 columns (framework_name, control_family, control_tags, tailored, tailoring_justification); summary.html re-templated with tailoring section + threat-model split + per-row family/tag/tailored chips |
| 10 | Wrap (this section) | ROADMAP / README / CONFIGURATION / examples / memory sweep |

**Aggregate:** 548 controls across 7 frameworks. No SDK pulls, no
binary size impact (~+30 KB of embedded YAML).

**Tailoring deliverable:**

```yaml
# compliancekit.yaml
tailoring:
  - framework: pci-dss-v4
    control: "10.6.1"
    justification: |
      Out of scope — no PAN data. All payments tokenized via Stripe.
```

  `compliancekit evidence --config compliancekit.yaml --out pack/`
loads + validates rules, writes `tailoring.json` to the pack root,
adds `tailored` + `tailoring_justification` columns to the
control-mapping CSV, and surfaces the operator's full record in
the auditor's summary HTML.

**Definition of done — met:**

- ✅ 4 new framework YAMLs land with sourced + attributed catalogs.
- ✅ Existing 3 frameworks expanded to full catalogs.
- ✅ Loader handles 7 frameworks at 548 controls; all existing check
  mappings continue to resolve (no breakage).
- ✅ ATT&CK renders as a kill-chain "Technique" view via
  Framework.IsThreatModel() routing in the evidence pack.
- ✅ Tailoring round-trips end-to-end: config → validation →
  evidence pack JSON + CSV column + summary chip + justification.
- ✅ `docs/checks.md` regenerated; per-control framework tables now
  show every applicable framework with family + tags.

---

### v0.13 ✅ — IaC / OCSF / OSCAL ingest + emit (shipped 2026-05-15)

**Goal:** compose with the rest of the security stack instead of
competing with it. v0.12 left compliancekit with breadth (7
frameworks × 548 controls); v0.13 lets every external scanner's
findings land in the same evidence pack with framework attribution
applied uniformly. The composition story: native scan + Trivy +
Checkov + AWS Security Hub all merge into one findings.json, one
evidence pack, one OSCAL Assessment Results document — no SaaS
shuttle layer, no per-tool integration glue.

**Shipped (10 phases + audit):**

| Phase | Theme | Output |
|---|---|---|
| 0 | Ingest scaffolding | `internal/ingest/` package, `Ingester` interface, concurrent-safe registry, `compliancekit ingest` CLI, `compliancekit.Finding.Source` provenance field, `config.Ingest[]` block |
| 1 | SARIF 2.1.0 | Adapter + 4 embedded mapping tables (Trivy / Checkov / KICS / Terrascan); 62 starter rule mappings; tool auto-detection; CVSS-to-severity |
| 2 | OCSF 1.x | Adapter + 3 embedded mapping tables (AWS Security Hub / GCP SCC / Defender for Cloud); 39 starter rule mappings; auto-detect array/JSONL/single-object shape; ARN-to-graph projection |
| 3 | OCSF emit polish + round-trip | Reporter enriched with `finding_info`, `compliance.standards/requirements`, `cloud.account`, `unmapped.compliancekit_source`; ingest → emit → ingest is lossless on CheckID / Severity / Status / Resource / Source / Fingerprint |
| 4 | OSCAL Catalog ingest | Hand-rolled JSON + YAML + XML parser; group hierarchy collapses to Control.Family; runtime framework registration via new `frameworks.Register` API; embedded + runtime frameworks coexist via merged-map `All()` |
| 5 | OSCAL Assessment Results emit | `assessment-results.oscal.json` in the evidence pack; deterministic v5-shaped UUIDs; one finding per (control, finding) pair; tailoring carries through as findings with `compliancekit-tailored="true"` props |
| 6 | OSCAL Profile emit | `profile.oscal.json` alongside AR; one Import per assessed-or-tailored framework with `include-all` + per-framework `exclude-controls` reflecting operator scope-outs |
| 7 | Mapping CLI | `compliancekit mapping list / show / validate / diff`; cross-registry validation (framework + control existence); unified MappingProvider registry across SARIF + OCSF subpackages |
| 8 | Provenance + config-driven ingest | `control-mapping.csv` gains `finding_source` + `finding_tool` columns; `scan --config=...` runs every `ingest:` entry after the native pipeline and merges findings + phantom resources into the live graph |
| 9 | Integration tests | End-to-end coverage of `runIngestSources` — multi-format merge, unknown-format errors, file-not-found errors, empty-config no-op |
| 10 | Wrap (this section) | ROADMAP / README / ADR-003 (Resolved) / ADR-018 (composition principle) / memory updates |

**Aggregate:** 3 ingest formats, 2 OSCAL emit shapes, 1 OCSF emit
upgrade, **106 starter rule mappings** spanning 7 external tools,
**1 new CLI surface** (`mapping`). No new external dependencies —
the OSCAL parser is hand-rolled, every adapter ships with embedded
mapping tables, every SARIF / OCSF / OSCAL document type uses the
standard library `encoding/{json,xml}` + `go.yaml.in/yaml/v3`
already in the module.

**Composition recipe:**

```yaml
# compliancekit.yaml
project: acme-saas
providers:
  digitalocean: { enabled: true, token_env: DO_API_TOKEN }
  kubernetes:   { enabled: true }

ingest:
  - format: sarif
    file: ./out/trivy.sarif
    tool: trivy
  - format: ocsf
    file: ./out/security-hub.json
    tool: aws-security-hub
  - format: oscal-catalog
    file: ./catalogs/acme-baseline.oscal.json
```

`compliancekit scan --config=compliancekit.yaml --evidence true`
runs the native DigitalOcean + Kubernetes scan, then merges in
Trivy's container-image findings and AWS Security Hub's compliance
findings, then registers the operator's custom OSCAL Catalog as a
runtime framework — and the evidence pack produced contains an
OSCAL Assessment Results document, an OSCAL Profile, the tailored
control-mapping.csv with provenance columns, and per-control
folders that mix native + ingested findings under the same framework
attribution.

**Definition of done — met:**

- ✅ All three ingest formats (`sarif`, `ocsf`, `oscal-catalog`)
  round-trip vendor fixtures.
- ✅ OSCAL Assessment Results emit is byte-stable across re-runs
  (UUID determinism via SHA256-of-content).
- ✅ OCSF emit → ingest → re-emit is lossless on every load-bearing
  Finding field (including Source provenance).
- ✅ README + CONFIGURATION + memory all sync'd in the wrap commit.
- ✅ ADR-003 (OCSF) closed as Resolved.
- ✅ ADR-018 (vulnerability composition principle) authored.

---

### v0.14 ✅ — Vuln / secret / SCA ingest (shipped 2026-05-15)

**Goal:** every CVE tied to a real resource in the graph. v0.14 layers
on top of v0.13's generic SARIF/OCSF ingest paths with four
purpose-built native-JSON adapters, typed Vulnerability + Secret
metadata blocks on compliancekit.Finding, and an image-SHA correlation pass
that maps a CVE-on-an-image onto every running K8s Deployment / DO
App Platform service / ECS task that references the same SHA.

**Shipped (11 phases):**

| Phase | Theme | Output |
|---|---|---|
| 0 | Schema scaffolding | `compliancekit.Finding.Vulnerability` + `Secret` typed blocks; default CVE/GHSA → vuln-mgmt framework mapping (SOC 2 CC7.1 / NIST SI-2 / ISO A.8.8 / PCI 6.3 / CIS 7.1) retroactively lights up the v0.13 SARIF path for advisory-shaped rules |
| 1 | Trivy native JSON | `--format=trivy-json` — per-package CVE / PURL / fixed-version / CVSS vector / image SHA. NVD-preferred CVSS scoring; auto-redacted secret detector output |
| 2 | Grype ingest | `--format=grype-json` — sibling tool, distinct schema, same Vulnerability shape |
| 3 | Checkov native JSON | `--format=checkov-json` — richer than SARIF (per-resource graph projection, file_line_range, guideline URL) |
| 4 | gitleaks ingest | `--format=gitleaks-json` — Secret block with auto-redacted Fingerprint, commit+author metadata for revocation routing |
| 5 | Image-SHA graph join | `internal/ingest/correlate.go` — when a Trivy image scan reports CVE on `container-image://<sha>` and a K8s/DO/ECS resource in the live graph references that SHA, clone the finding onto the running instance with a "running-on" tag. Bidirectional. |
| 6 | `vulnerabilities.csv` | New evidence-pack artifact — one row per (CVE, resource, framework) with cve_id / cvss / package_purl / fixed_version / source_tool columns. Directly importable into vuln-mgmt tools |
| 7 | Reporter updates | Markdown emits per-finding CVE subbullets + Secret lines; SARIF result.properties gains cve_id + GitHub-recognized security-severity; OCSF emit routes Vulnerability + Secret through `unmapped.compliancekit_{vulnerability,secret}` |
| 8 | ADR-010 secret-redaction | `ingest.RedactSecret` is the single canonical helper; per-adapter copies aliased to it. ADR-010 codifies the "raw secret value never enters the data plane" policy with the algorithm + threshold rationale + rejected alternatives |
| 9 | Integration tests | End-to-end pipeline test — Trivy fixture + K8s deployment in graph → correlated finding lands on the deployment with all metadata preserved + Trivy+Grype dual-source additivity test |
| 10 | Wrap (this section) | ROADMAP / README / examples / memory sweep |

**Aggregate:** 4 new ingest formats (`trivy-json`, `grype-json`,
`checkov-json`, `gitleaks-json`), 2 typed metadata blocks on
`compliancekit.Finding`, 1 new evidence-pack artifact, 1 new graph-correlation
pass, 1 new ADR (ADR-010 secret redaction). Zero new external
dependencies — every parser hand-rolled against `encoding/json`.

**Composition recipe:**

```yaml
# compliancekit.yaml
providers:
  kubernetes: { enabled: true }

ingest:
  - format: trivy-json
    file: ./out/trivy-image.json
    tool: trivy
  - format: grype-json
    file: ./out/grype-image.json
    tool: grype
  - format: gitleaks-json
    file: ./out/gitleaks.json
    tool: gitleaks
```

`compliancekit scan --config=... --evidence true` runs the native
K8s scan, ingests Trivy + Grype + gitleaks output, runs the image-
SHA join (Trivy's CVE on image X cross-references every Pod /
Deployment in the K8s graph referencing X), and writes an evidence
pack containing `vulnerabilities.csv` plus the existing
`control-mapping.csv` + per-control folders mixing native + ingested
findings.

**Definition of done — met:**

- ✅ One ingest fixture per tool (Trivy / Grype / Checkov / gitleaks).
- ✅ A CVE found by Trivy on a container image used by a K8s
  Deployment appears in `findings.json` linked to both the image
  AND the Deployment (tested in `internal/cli/vuln_pipeline_test.go`).
- ✅ Vulnerability blocks expose CVE-ID + CVSS + PURL + fixed-version
  + image identifier in every reporter format.
- ✅ Secret blocks carry redacted-only fingerprints (ADR-010); test
  fixtures verify "AKIAIOSFODNN7EXAMPLE" never substring-matches output.
- ✅ Evidence pack ships `vulnerabilities.csv` whenever CVE findings
  exist (skip when zero).
- ✅ ADR-010 codifies the redaction policy with algorithm rationale.

---

### v0.15 ✅ — Remediation generators (shipped 2026-05-15)

**Scope expanded from the original ROADMAP:** ten output formats
(not four), per-format strategy packages (not per-check methods),
RiskClass-gated bulk apply, OSCAL POA&M emit, and Jira + Linear
ticket integration for manual items. Architectural shape codified
in ADR-011.

**What shipped (13 phases, 35 files, ~10k LOC)**

- **Strategy registry + 10 Formats.** `internal/remediate` defines
  the `Strategy` interface, `Snippet` shape, and `Format` /
  `RiskClass` enums. Each format gets a subpackage that registers
  strategies in `init()`:
    - `terraform` (35 strategies — AWS, GCP, DigitalOcean, Hetzner)
    - `kubectl` (30+ — pod security context, NetworkPolicy, RBAC,
      PSA, PDB, Ingress, Service)
    - `awscli`, `gcloud`, `azcli`, `doctl`, `hcloud` — one-liner
      cloud-CLI commands paired with the IaC strategies
    - `helm` — values.yaml overlays for Helm-deployed K8s workloads
    - `ansible` — playbook tasks for Linux/CIS findings
    - `bash` — POSIX-sh fallbacks + the WILDCARD ("*") strategy that
      catches every CheckID with no specific renderer
- **140 strategies covering 127 CheckIDs.** Each declares:
  - RiskClass (safe / review / manual)
  - Idempotent flag
  - VerifyCmd (run after apply to confirm)
  - RollbackCmd (where the inverse is a single command)
  - Notes (operator-facing caveats)
  - Refs (authoritative doc URLs)
- **`compliancekit remediate` subcommand.** Reads findings JSON
  (envelope or bare-array), runs the registry, emits:
    - `remediation.md` — runbook grouped by risk class with TOC +
      catalog-resolved titles + per-format code fences + inline
      Verify / Rollback
    - `remediate.sh` — single bash script bundling RiskSafe snippets
      (cloud-CLI + bash flavors only — IaC formats need their own
      apply step)
    - `remediate-<format>/` — one directory per Format with raw
      snippet files per resource
    - `poam.oscal.json` — OSCAL v1.1.2 POA&M; one item per manual
      or unmatched finding with deterministic UUIDs (via the same
      SHA-256-prefix algorithm as the AR + Profile emitters)
- **Jira + Linear ticketing (optional).** Env-driven (JIRA_HOST /
  JIRA_EMAIL / JIRA_TOKEN / JIRA_PROJECT, LINEAR_API_KEY /
  LINEAR_TEAM_ID). Missing creds → that provider is skipped silently.
  Per-provider failure doesn't block the others.

**Architectural decisions (ADR-011)**

- Per-format Go strategy packages, hand-written, generate-only.
- Risk classified at strategy authorship time so v2.x's `--apply-fix`
  cannot accidentally promote a manual fix.
- Findings without a strategy never silently drop — they flow to
  the POA&M emitter via the wildcard fallback strategy.

**Definition of done — what was actually shipped**

- ✅ Terraform, kubectl, awscli, gcloud, azcli, doctl, hcloud, helm,
  ansible, bash generators — 10 formats, not 4.
- ✅ `compliancekit remediate --in=findings.json --out=./remediation`
  emits the runbook + bulk script + per-format directories + POA&M.
- ✅ Determinism: re-rendering the same findings produces byte-
  identical artifacts (no timestamps in snippet bodies; sort orders
  stable on (Risk, CheckID, Resource.ID, Format)).
- ✅ Wildcard fallback strategy in `internal/remediate/bash` ensures
  every finding produces at least one Snippet — auditor-visible.
- ✅ OSCAL POA&M emit completes the evidence-pack story (alongside
  AR + Profile from v0.13).
- ✅ Jira + Linear integration; both ship with httptest-backed
  contract tests.

---

### v0.16 ✅ — Rego policy DSL (shipped 2026-05-17)

**Scope expanded from the original ROADMAP:** ten Format names is
the cloud-CLI plumbing; for Rego the expansion was three-fold —
custom built-ins (originally "wait for community demand"), the
`policy test/validate/fmt` CLI surface for a local authoring
workflow, and **15** side-by-side reimplementations (3× the
original "5" floor). Architectural shape codified in
[ADR-012](DECISIONS.md#adr-012--rego-is-embedded-via-opas-go-library-not-shelled-out).
[ADR-002](DECISIONS.md#adr-002--policy-dsl-is-rego-landing-at-v016)
is now Resolved.

**What shipped (7 phases, 7 commits, ~3.5k LOC)**

- **`internal/policy/policy.go` + loader.** Rego evaluator that wraps
  `rego.New(...).Eval` into the existing `compliancekit.CheckFunc` signature.
  Modules parse + compile at load time (syntax errors surface at
  startup, not at first scan). Per-rule `metadata := {...}` constant
  lifts onto a typed `compliancekit.Check` with required-field guarding.
- **OPA embedded** via `github.com/open-policy-agent/opa/v1/rego`
  v1.16.2. ~15MB binary cost accepted because (a) Rego is
  pure-functional with no I/O — sandboxing is free; (b) byte-
  identical Findings without serialization round-trips; (c) one
  distribution story instead of "install OPA separately."
- **4 custom built-ins** under the `compliancekit.` prefix:
  `has_tag(resource, name)`, `attr_str(resource, key)`,
  `attr_bool(resource, key)`, `cvss_band(score)` — eliminate the
  boilerplate every policy would otherwise repeat. Stable surface
  per ADR-012; adding a fifth is a SemVer 2.0 change.
- **Registry mirror.** Rego modules register into the same
  `compliancekit.DefaultRegistry` as Go checks via `policy.RegisterModule`;
  mutual-exclusion enforced at registration (duplicate IDs are
  programmer errors caught at startup, not silent overwrites).
- **`compliancekit checks list/show` annotation.** New SOURCE column
  ("go" or "rego"); `checks show <id>` prints the Rego source file
  path + body inline so operators audit without digging.
- **`compliancekit policy test/validate/fmt` subcommand.** Closes
  the authoring loop: `policy test fixture.json policy.rego` for
  instant pass/fail; `policy validate dir/` as a CI gate;
  `policy fmt` (with `--check`) wraps OPA's canonical formatter.
- **15 side-by-side Rego reimplementations** under
  `examples/policies/<provider>/`, three per provider lane
  (AWS / GCP / DigitalOcean / Kubernetes / Linux). Every shipped
  policy exercises at least one custom built-in.
- **Semantic validation test** (Phase 6) — table-driven, one row
  per shipped policy, asserts the produced findings flag exactly
  the expected resources against a fixture matching the policy's
  declared shape.

**Definition of done — what was actually shipped**

- ✅ `internal/policy/` package with evaluator + loader + builtins
  + registry mirror.
- ✅ 15 reimplementations (vs the issue's 5-check floor).
- ✅ `compliancekit policy test/validate/fmt` for local authoring.
- ✅ `checks list/show` surface Rego-backed checks with source.
- ✅ All 15 policies pass `policy validate` + the per-policy
  semantic test.
- ✅ ADR-012 codifies embedded OPA. ADR-002 flipped to Resolved.

**Deferred to a future milestone**

- Embedding policies under `internal/policies/` and auto-loading
  at startup. Phase 5 ships demonstration twins in `examples/` so
  the contribution path is clear without polluting the user's
  scan output with duplicate findings.
- Byte-identical Go ↔ Rego parity. The Go checks read collector-
  native shapes (container slices, nested config blobs); the Rego
  reimplementations declare a simpler resource schema. True parity
  needs a canonical JSON-stable resource shape both sides target —
  a collector-side refactor for a later milestone.

---

### v0.17 ✅ — Notifications (shipped 2026-05-17)

**Scope expanded from the original ROADMAP:** 8 sinks instead of 7
(PagerDuty Events v2 added because operational escalation is the
"production-grade" story the indie-SaaS audience needs). Mirrors
the v0.13 ingest + v0.15 remediate architecture: one Notifier
interface, one Default registry, per-sink env-driven configuration,
no telemetry / no phone-home.

**What shipped (11 phases, 11 commits, ~3k LOC)**

- **`internal/notify/notify.go` — foundation.** Notifier interface
  (Name / Configured / Threshold / Send), Notification struct
  (Finding + pre-rendered Title + CommonMark Body + deep-link URL +
  Tags + dedup Fingerprint), Result accumulator, Registry +
  Default + Register pattern.
- **`BuildNotifications + Dispatch`.** Builder filters non-actionable
  findings + renders the canonical title/body once; dispatcher fans
  out to every Configured sink whose Threshold permits the
  notification. Per-sink errors wrap with the sink name and DON'T
  block siblings — one failing channel never silences the rest.
- **8 sinks**, each in `internal/notify/<sink>.go` with an httptest
  contract test:
  - **slack** — Block Kit payload, both incoming-webhook + bot-token
    paths supported in one type; parses both Slack response shapes
    (webhook plain-text "ok", API `{"ok": true/false}`).
  - **discord** — embed payload with severity-mapped 24-bit color.
  - **teams** — MessageCard payload (legacy connector); bullets
    converted to "•" glyph for mobile/desktop consistency.
  - **webhook** — generic JSON POST with `compliancekit.
    notification.v1` schema + optional `X-CompliancekitSignature:
    sha256=<hex(HMAC-SHA256(secret, body))>` header.
  - **email** — SMTP with auto-selected TLS mode (port 465 → tls,
    587 → starttls, 25 → none); PLAIN auth optional; multipart
    MIME with text/plain only (HTML deferred).
  - **github-pr** — single summary comment per dispatch (not per
    finding — avoids PR-comment spam) as a Markdown table.
  - **jira** — thin adapter over the v0.15 `tickets.Jira` client;
    `JIRA_NOTIFY_*` env falls back to `JIRA_*`.
  - **pagerduty** — Events v2 enqueue with `dedup_key` =
    notification.Fingerprint so re-firing findings update existing
    incidents. Defaults to critical-only threshold (don't wake on-
    call on noise).
- **`compliancekit notify` CLI.** `--in` findings JSON, `--baseline`
  for only-new-findings mode (subtracts by Finding.Fingerprint),
  `--severity` global floor (stacks with per-sink threshold;
  strictest wins), `--project` + `--url-prefix` for body rendering,
  `--dry-run` for the per-sink plan, `--list` for the
  Configured/Threshold table.
- **`compliancekit doctor` integration.** New "notify:" line prints
  `N sink(s) registered, M configured` plus a per-sink Configured +
  Threshold breakdown. Runs unconditionally (no provider config
  required) so operators can verify sink credentials independently
  of scan config.

**Definition of done — what was actually shipped**

- ✅ 8 sinks, each ≤300 LOC including tests.
- ✅ Per-sink severity threshold + global `--severity` floor.
- ✅ Only-new-findings mode reads `compliancekit baseline` output.
- ✅ Rate-limit + dedup via Finding.Fingerprint (PagerDuty `dedup_key`
  + only-new subtraction; finer rate-limit deferred until a sink
  reports the need).
- ✅ Doctor reports per-sink configuration status.
- ✅ No telemetry / no phone-home — every target is operator-
  configured via env vars.

**Deferred to a future milestone**

- Mattermost / Rocket.Chat — Slack-webhook-compatible, add when
  someone asks.
- Adaptive Card Teams payload — wait for the October 2026 MessageCard
  retirement deadline.
- HTML email — overkill until someone reports plain-text rendering
  is a problem.
- Per-sink rate limit — only PagerDuty has a real rate concern today,
  and its `dedup_key` covers that. Add when a sink complains.

---

### v0.18 ✅ — Waivers + in-code skip annotations (shipped 2026-05-17)

**Scope expanded from the original ROADMAP:** glob matching on both
CheckID + ResourceID (originally exact-only), 6 file types for
in-code annotations (.tf .tfvars .yaml .yml .sh .bash .py .go +
Dockerfile/*.dockerfile), CLI surface with 4 subcommands (list /
show / validate / check), evidence-pack `waivers.json` artifact
plus 4 additive control-mapping.csv columns, full doctor
integration. Architectural shape codified in
[ADR-013](DECISIONS.md#adr-013--waivers-vs-baselines-distinct-concerns-distinct-mechanisms).

**What shipped (8 phases, 8 commits, ~3k LOC)**

- **`internal/waivers/` foundation** — Waiver struct + WaiverList +
  validating loader. Per ADR-013: every waiver REQUIRES expiry (no
  permanent waivers — they degrade into hidden ignore-lists);
  reason floor of 16 non-whitespace chars (catches "OK" / "see
  ticket" without rejecting real prose); duplicate (CheckID,
  ResourceID) rejected because it hides which approver authorized.
- **`compliancekit.WaiverRef`** typed metadata block on `compliancekit.Finding`
  (joins Vulnerability + Secret from v0.14). Auditor-visible by
  design — a waived finding flows through every reporter as
  StatusSkip with WaiverRef populated, NOT hidden.
- **Loader + Matcher**: glob-based matching on both CheckID and
  ResourceID via `filepath.Match` (operators waiving a whole check
  family use `aws-s3-*`; a whole resource family uses
  `digitalocean.droplet.*`). First-match-wins; deterministic
  ordering across runs.
- **Apply + expired-waiver synthesis**: mutates findings in place
  (StatusSkip + WaiverRef + `waived` tag), AND synthesizes one
  info-level `compliancekit-waiver-expired` finding per lapsed
  waiver so the auditor sees the lapse as an explicit finding.
- **In-code annotation scanner** for 6 file types:
  `# compliancekit:waive <check-id> <resource-id> [reason="..."]
  [approver=...] [expires=YYYY-MM-DD]` (and `//` form for Go +
  HCL). Languages: Terraform/HCL, YAML, Bash, Python, Dockerfile,
  Go. Default expiry = now + 90 days (forces re-review); default
  approver = `@annotation`; default reason references the file +
  line so the auditor knows where to look. Skips .git / vendor /
  node_modules / .terraform / dist / build / .cache.
- **Scan engine integration**: `applyWaivers` hook in `runScan`
  loads + applies waivers right after ingest merge. Synthesized
  expired findings appended to result.Findings so reporters see
  them. Summary line "waivers: N active, M expired, K expiring
  within 30d — muted P finding(s)".
- **Evidence pack additions** (additive — v0.4+ CSV consumers
  reading by column name keep working):
  - 4 new columns on `control-mapping.csv`: `waiver_active`,
    `waiver_reason`, `waiver_approver`, `waiver_expires`.
  - New `waivers.json` artifact at the pack root with one entry
    per muted finding (cross-references the full `compliancekit.Finding`
    so an auditor can pivot from waiver → original finding).
- **`compliancekit waivers` CLI** — 4 subcommands:
  - `list` — tabulate active + expired with expiring-within-30d
    flagged; counts header.
  - `show <check-id> <resource-id>` — full detail for one waiver
    including multi-line reason + source path.
  - `validate` — schema + duplicate check; non-zero exit on errors
    (CI gate).
  - `check --in=findings.json` — non-zero exit if any actionable
    finding lacks a matching waiver (CI gate for "every fail-on=
    high finding must have a documented acceptance").
- **Doctor integration**: prints "waivers: <path> — N active, M
  expired, K expiring within 30d" line, with ⚠ icon when any
  waivers are expired or expiring-soon.

**Definition of done — what shipped**

- ✅ `waivers.yaml` schema with required {check_id, resource_id,
  reason ≥16 chars, approver, expires}.
- ✅ In-code annotations across 6 file types + auto-defaulting for
  reason/approver/expires when not specified.
- ✅ Expired waivers emit `compliancekit-waiver-expired` info
  findings so lapses are explicit, not silent.
- ✅ Evidence pack visibility: waivers.json + 4 new
  control-mapping.csv columns. Per ADR-013, waived findings stay
  visible to auditors with full justification + approver context.
- ✅ `compliancekit waivers list/show/validate/check` CLI surface.
- ✅ `compliancekit doctor` reports waivers health.
- ✅ ADR-013 codifies the waivers-vs-baselines boundary.

**Deferred to a future milestone**

- Broader scopes (per-framework / per-tag waivers) — narrow
  (CheckID, ResourceID) is the v0.18 unit. Add when narrow proves
  insufficient.
- Multi-approver chains for high-severity waivers — out of v0.18
  scope; the audit-log-via-evidence-pack covers basic accountability.
- Waiver application via Web UI / workflow integration — that's
  v1.4 Studio (web UI waiver manager) + v1.9 workflow automation
  (multi-approver flows + expiry); the GRC layer is at v2.3 and the
  auditor portal at v2.4 per ADR-016.

---

### v0.19 ✅ — DigitalOcean deepening (production grade) (shipped 2026-05-17)

**Shipped:** the most comprehensive open-source DigitalOcean security
scanner that exists. DO is the indie-SaaS audience the project was
built around; everything else is depth in service of that. v0.9
shipped 74 checks across 20 services; v0.19 took it to **144 checks
across 21 services** and turned every check into a fully-remediated,
fully-tested artifact (**432 bespoke remediation strategies** total —
Terraform + doctl + bash, one of each per check).

**Phases (each commit was its own gate-passing phase):**

- Phase 0 — DO parity ratchet test infrastructure (gates new
  checks; flips red on any DO check landing without all three
  formats).
- Phase 1 — Account/team governance deepening (+10 checks).
- Phase 2 — Spaces lifecycle/replication/object-lock (+10 checks +
  collector extension for lifecycle/logging/policy attributes).
- Phase 3 — DNS DMARC/SPF/DKIM/CAA/DNSSEC depth (+10 checks +
  collector extension for spf_records / dkim_selectors / ns_records).
- Phase 4 — DOKS add-on coverage (+10 checks under provider="kubernetes").
- Phase 5 — App Platform observability + deploy hygiene (+10 checks +
  collector extension for service / database summaries).
- Phase 6 — Functions runtime + env hygiene (+10 checks).
- Phase 7 — Network depth (VPC peering, firewall dedup, reserved-IP,
  LB SSL) (+10 checks).
- Phase 8 — Billing + project orphan/untagged sweep (+10 checks).
- Phase 9 — Remediation parity backfill — drove ratchet from 68/68/74
  to 0/0/0 by adding bespoke TF + doctl + bash for every v0.9-vintage
  check.
- Phase 10 — Test coverage push (checks: 93.4% → 96.1%; collectors:
  pure-helper layer fully covered).
- Phase 11 — Docs polish + `examples/quickstart-digitalocean-deep.yaml`.

**Deliverables (all shipped)**

- **74 → 144 checks** across every DO surface. New depth:
  - Account / team: MFA enforcement audit, named-team usage,
    API-key rotation tracking, billing-alert presence, owner+
    delegation review, audit-log retention.
  - Spaces: lifecycle policies (expiration / noncurrent versions),
    transfer acceleration, replication, server-access-logging,
    object-lock + retention modes.
  - DNS: complete DMARC dimensions (p=, sp=, pct=, rua/ruf), SPF
    record correctness, DKIM selector presence, CAA per-CA pinning,
    DNSSEC enablement.
  - DOKS: full add-on coverage (DO Container Registry integration
    depth, metrics-server, cert-manager presence, cluster-autoscaler
    config), control-plane logging destinations, node-pool
    upgrade-strategy validation, image-pull-secret governance.
  - App Platform: alert policy completeness, observability stack
    (logs forward / metrics forward), build-time secret scanning,
    deploy-on-push branch protection, custom-domain cert hygiene.
  - Functions: namespace tenancy, runtime EOL audit, env-var
    secrets-vs-plain audit, log-policy presence.
  - Network: VPC peering pair correctness, firewall rule
    deduplication, reserved-IP orphan audit, load-balancer SSL
    cipher / proto floor enforcement.
  - Billing + project: orphaned resources across all 20 services,
    untagged resources (cost-attribution hygiene), per-project
    resource caps.
- **Every check ships with three remediations:** Terraform block,
  doctl one-liner, bash fallback. Per ADR-011 + ADR-006, generation
  only. RiskClass classified at strategy authorship.
- **Per-check unit tests** with collector-shaped fixtures
  (`internal/checks/digitalocean/<service>_test.go`); integration
  tests in `internal/cli/scan_do_integration_test.go` against
  multi-service synthetic graphs.
- **Optional live-DO smoke** gated on `DO_API_TOKEN` env var:
  scan a known account, assert ≥N findings, no collector errors.
- **Final phase: docs polish + CLI help cleanup** for every new
  surface — `--help` strings precise, `compliancekit checks show`
  shows full prose for every shipped DO check, new
  `examples/quickstart-digitalocean-deep.yaml` walking through the
  comprehensive scan path.

**Definition of done — what actually shipped**

- ✅ 144 DO checks registered (planned 150+; the eight unshipped
  scope ideas were either folded into the existing surface or
  consciously deferred — see "Deferred" below).
- ✅ Every DO check carries Terraform + doctl + bash remediation
  strategies. CI gate: `TestParity_DigitalOcean` in
  `internal/remediate/parity_do_test.go` strict-equality enforces
  0 missing strategies across all three formats.
- ✅ Test coverage: `internal/checks/digitalocean/` reaches 96.1%.
  `internal/collectors/digitalocean/` pure-helper layer fully
  covered; the live-API integration paths sit at fixture-driven
  ~52% — pushing those to ≥85% requires significantly more fixture
  JSON and was deferred.
- ✅ `examples/quickstart-digitalocean-deep.yaml` walks through the
  end-to-end scan with every flag operators need.

**Deferred from the original v0.19 scope**

- ≥150 check count (shipped 144). Remaining 6 ideas either consolidated
  into existing manual-verify families or held back for v0.21 (DOKS
  + K8s deepening will own further DOKS-side checks).
- Per-file 85% coverage on the collectors package — collectors live-
  API path coverage requires fixture-server JSON for every godo
  endpoint we touch; a meaningful additional investment to ship
  separately.
- Live-DO smoke test in CI gated on `DO_API_TOKEN` — deferred to
  v0.21 alongside the DOKS smoke-test work.

---

### v0.20 ✅ — Linux hardening (production grade) (shipped 2026-05-17)

v0.5 shipped 15 Linux checks as a foundation; v0.20 took it to
**119 checks** spanning the CIS Linux Server Benchmark v8 surface
(kernel sysctl + filesystem + services + sshd + auditd + login.defs
+ PAM/sudo + packages/MAC + firewall depth), with **bespoke bash +
Ansible remediation for every check** (238 strategies total) and a
**parity ratchet gate** (`TestParity_Linux`) at strict 0/0 to keep
future Linux work compliant.

**Shipped**

- ✅ **119 Linux checks** (15 → 119, +693%) organized into 9
  data-driven spec frameworks: `sysctlSpec`, `mountSeparateSpec` +
  `mountOptionSpec`, `serviceMustRunSpec` + `serviceMustNotRunSpec`
  + `serviceMustAbsentSpec`, `sshdSpec`, `auditRuleSpec`,
  `manualVerifySpec`. Each spec is a struct literal; init() loops
  the slice + registers via per-shape closure — adding a new check
  is one struct literal.
- ✅ **Per-distro detection** via `internal/collectors/linux/
  osrelease.go` + 5 canonical fixtures (ubuntu 22.04, debian 12,
  rhel 9, alpine 3.19, amzn 2023). Family predicates
  (`IsDebianFamily`, `IsRHELFamily`, `IsAlpine`, `IsAmazonLinux`)
  drive per-distro gating — SELinux check fires only on RHEL,
  AppArmor only on Debian, nftables-on-RHEL only on RHEL.
- ✅ **Bespoke bash + Ansible for every check.** Parity ratchet
  `TestParity_Linux` (internal/remediate/linux_parity_test.go) at
  strict equality 0/0 — a single Linux check shipped without both
  formats fails pre-commit. 238 strategies total (119 × 2).
- ✅ **Bash strategies** use idempotent sed/grep/printf one-liners.
  sshd_config edits run `sshd -t` validate BEFORE reload so a
  broken edit cannot lock operators out. Firewall remediations are
  distro-aware (ufw / firewalld / nftables switch on /etc/os-release).
- ✅ **Ansible strategies** use lineinfile + ansible.posix.sysctl +
  ansible.builtin.systemd modules with `become: true`. sshd edits
  carry `validate: 'sshd -t -f %s'` for the same lockout protection.
- ✅ **CIS Linux Server Benchmark v8 framework catalog**
  (`internal/frameworks/cis-linux-server.yaml`) — 90+ sections
  organized into 6 families (initial-setup, services, network,
  logging-auditing, access-auth, system-maintenance) with Level 1
  / Level 2 tags. Wired into every v0.20 spec constructor — checks
  emit `cis-linux-server` alongside `cis-v8` in their framework map.
- ✅ **Test coverage** — `internal/checks/linux/` at **90.6%** (≥85%
  DoD target). Per-spec table-driven tests cover every cmp branch
  + skip-on-missing-attr + unreachable-host paths.
- ✅ **`examples/quickstart-linux-hardening.yaml`** walks through
  the end-to-end scan with inventory + bastion + waivers + Slack
  notification wiring.

**Deferred from the original v0.20 scope**

- 100+ count target was hit (shipped 119). STIG + ANSSI catalogs
  not shipped as separate framework yamls — the CIS Linux Server
  Benchmark control map is the primary v0.20 deliverable; STIG is
  largely a section-renaming exercise on the same underlying data
  and was held back to keep the release focused.
- Per-file 85% coverage on `internal/collectors/linux/` (shipped
  53.7%). The gap is dominated by the SSH transport layer
  (`gatherX` functions, `Dial`, `RunCommand` — all 0%) which would
  need a fake SSH server or interface refactor. Pure parsers
  (`ParseOSRelease`, `ParseSysctlOutput`, `ParseLoginDefs`,
  `parseSSHDConfig`, etc.) are at 90%+.
- Integration tests against per-distro rootfs JSON fixtures —
  the spec-driven check tests with constructed `compliancekit.Resource`
  literals cover the check logic exhaustively; rootfs fixtures
  would mostly re-exercise the collectors' SSH path which is the
  same gap as above.

**Definition of done — checklist**

- ✅ 100+ Linux checks registered (shipped 119).
- ✅ Every Linux check ships with bash + Ansible remediation
  (parity ratchet at strict 0/0).
- ✅ Per-distro detection + gating wired through every distro-
  specific check (SELinux → RHEL, AppArmor → Debian, nftables-on-
  RHEL → RHEL).
- ✅ Test coverage ≥85% on `internal/checks/linux/` (90.6%).
- ✅ README + ROADMAP updated with new check counts + framework
  catalog reference; `examples/quickstart-linux-hardening.yaml`
  exists.

---

### v0.20 — Linux hardening (original plan, kept for reference)

**Goal:** match the depth of OpenSCAP / Lynis on Linux server
hardening, with the same evidence-pack + remediation experience
operators get on cloud surfaces. v0.5 shipped 15 Linux checks as
a foundation; v0.20 takes that to full CIS Benchmark + STIG
coverage.

**Deliverables**

- **15 → 100+ checks** mapped to:
  - **CIS Benchmark Linux Server** (Level 1 + Level 2, with
    IG1/IG2/IG3 implementation-group taxonomy threaded through).
  - **STIG** Linux subset (the subset relevant to cloud servers).
  - **ANSSI** Linux Server hardening guide subset (French gov
    equivalent — broader audience signal).
- Coverage categories:
  - **Kernel sysctl** — full network + memory + filesystem +
    randomization knobs (~30 checks).
  - **Filesystem** — separate-partition checks (/tmp, /var,
    /var/log, /var/log/audit, /home), mount options (nodev,
    nosuid, noexec), permissions on system files.
  - **Services** — systemd unit hardening (PrivateTmp, NoNewPriv,
    ProtectSystem, CapabilityBoundingSet), enabled-services audit.
  - **Auth** — PAM stack (faillock, pwquality, lastlog), sudo
    (NOPASSWD audit, secure_path), sshd full coverage
    (HostKey rotation, MAC/Cipher floor, KexAlgorithms, AllowUsers).
  - **Audit** — auditd rules (CIS 4.1.x subset: identity, mac,
    perm, sudoers, mounts, time, network, login), journald
    persistent storage + forward-to-syslog, rsyslog config.
  - **Network** — iptables / nftables / ufw / firewalld depth,
    ICMP behavior, IPv6 hardening.
  - **Packages** — apt/dnf signing keys present, unused packages
    removed, prelink absent (kernel/CIS deprecates), aide presence
    + cron job.
  - **MAC** — SELinux enforcing / AppArmor enabled per-service
    profile audit.
- **Per-distro support:** Debian/Ubuntu (apt-based), RHEL/CentOS/
  Rocky/Alma (dnf), Alpine (apk), Amazon Linux 2 / 2023. Distro
  detected at collection time; per-distro test fixtures.
- **Every check with bash + Ansible remediation.** Idempotent
  Ansible tasks; bash one-liners safe to paste over SSH.
- **Integration tests** against rootfs fixtures (committed JSON
  representations of `/etc/sysctl.d`, `/etc/ssh/sshd_config`,
  `/etc/pam.d/*`, `/etc/audit/audit.rules` etc.) per distro.
- **Final phase: docs polish** — per-check remediation prose
  cleaned, `--help` polished, new `examples/quickstart-linux-
  hardening.yaml` walking through CIS Server Level 1.

**Definition of done**

- 100+ Linux checks registered with full per-distro coverage.
- Per-distro CIS Benchmark mapping coverage (which IG covers what).
- Every Linux check ships with bash + Ansible remediation.
- Test coverage ≥85% per file in `internal/checks/linux/` and
  `internal/collectors/linux/`.
- README + CHECKS.md updated with the new authoring conventions.

---

### v0.21 ✅ — Kubernetes + DOKS deepening (production grade) (shipped 2026-05-17)

v0.11 shipped 149 K8s checks (already strong); v0.21 took it to
**241 checks** across the pod-security / reliability / supply-chain
/ RBAC / network / admission / control-plane / managed-K8s surfaces,
with **bespoke kubectl strategy for every K8s check** (parity gate
at strict 0 — wildcard fallback no longer counted) and the NSA/CISA
Kubernetes Hardening Guide v1.2 framework yaml as the 9th catalog.

**Shipped**

- ✅ **241 K8s checks** (149 → 241, +61%) organized across 8 new
  spec-driven categories landing in distinct files to keep the
  v0.22 600-LoC invariant on each:
  - `pods_extra.go` (12) — pod-security deepening (shareProcessNamespace,
    dnsPolicy, hostUsers, fsGroup, runAsGroup, AppArmor, seccomp-not-
    unconfined, RuntimeClass, volume subPath, default SA,
    supplementalGroups)
  - `reliability.go` (12) — readiness/startup probes, ephemeral-
    storage limits, topology spread, image digest pinning, termination
    grace, preStop hook, owner-ref, init-container parity, host ports
  - `rbac_extra.go` (10) — escalation patterns (update clusterroles,
    patch nodes, pods/status, CSR create, mutating/validating webhook
    write, namespaces write, deletecollection pods, pods/eviction,
    pods/ephemeralcontainers) — each one a verbResourceCheck against
    a specific (apiGroup, resource, verbs) tuple
  - `network_extra.go` (10) — Ingress RCE annotations (CVE-2021-25742
    family), 0-CIDR source ranges, cloud-metadata egress, Lua plugins,
    publishNotReadyAddresses, broad selectors, no-rules ingresses,
    mixed TLS/plaintext ports
  - `supplychain.go` (10) — mutable tags, empty tags, trusted-registry
    allowlist, cosign signature verification, in-toto attestations,
    image-pull secret discipline, pull-policy consistency, base-OS
    EOL, registry TLS-only, vuln-scan freshness
  - `admission_extra.go` (8) — webhook timeout bounded, mutating
    sideEffects None, namespace exclusion, Gatekeeper / Kyverno
    installed, policy enforce mode, OLM installed, Subscription manual
    approval
  - `control_plane.go` (15) — CIS K8s Benchmark §1 manual-verify
    across apiserver / etcd / controller-manager / scheduler / kubelet
    flags, structured per the v0.20 manualVerifySpec pattern
  - `managed_extra.go` (15) — DOKS / EKS / GKE deepening manual-verify
    (private endpoint, KMS encryption, IRSA, IMDSv2, Workload Identity,
    Binary Authorization, etc.), 5 per vendor
- ✅ **Collector extensions** — `workloads.go` now emits 10 new
  pod-level attrs (share_process_namespace, dns_policy,
  priority_class_name, runtime_class_name, host_users, apparmor_profile,
  volume_subpath_mounts, termination_grace_period,
  topology_spread_constraints, init_container_count) + 4 new
  container-level attrs (has_readiness_probe, has_startup_probe,
  has_ephemeral_storage_limit, image_digest_pinned) + 3 new pod-level
  securityContext fields (run_as_group, fs_group, supplemental_groups).
- ✅ **Bespoke kubectl per check.** Parity ratchet
  `TestParity_Kubernetes` (internal/remediate/k8s_parity_test.go)
  at strict equality 0 — a single K8s check shipped without bespoke
  kubectl coverage fails pre-commit. Helm + Terraform deferred to
  per-check additions only where they're the natural fit (per
  pre-phase scope decision: most K8s findings — RBAC, secrets,
  pod-security on running pods — aren't naturally Helm-shaped).
- ✅ **kubectl strategy distribution** — 8 hand-authored extra
  files (pod_security_extra.go, reliability.go, rbac_extra.go,
  network_extra.go, supplychain.go, admission_extra.go,
  control_plane.go, managed_extra.go) + 11 backfill registrations
  distributed across new per-category files (doks.go, eks.go, gke.go,
  nodes.go, storage.go, secrets.go) + appends to existing extras
  files, all sharing a backfill_helper.go renderer that pulls the
  Check's own Remediation text. Drove the kubectl ratchet from
  baseline 102 → 0.
- ✅ **NSA / CISA Kubernetes Hardening Guide v1.2 framework yaml**
  (`internal/frameworks/nsa-cisa-k8s.yaml`) — 30+ chapter-section
  controls across 5 chapters (pod-security, network, auth, logging,
  upgrading). 9th shipping framework after the v0.20 cis-linux-server
  addition.
- ✅ **Test coverage** — `internal/checks/k8s/` at 52.4% (was 45.0%,
  +7.4pp). Per-source-file test split (`pods_extra_test.go`,
  `reliability_test.go`, `supplychain_test.go`, `control_plane_test.go`,
  `managed_extra_test.go`, shared `testhelpers_test.go`). Bug fixed
  in registryFromImage during test development.
- ✅ **examples/quickstart-kubernetes-deep.yaml** + **examples/
  quickstart-doks-deep.yaml** — end-to-end production scan configs
  exercising the full K8s + DOKS surface with Slack + waivers + 
  baseline diff wiring.

**Deferred from the original v0.21 scope**

- Helm + Terraform parity across every K8s check. Per-check decision:
  Helm template generation isn't naturally K8s-shaped (RBAC, secrets,
  pod-security on running pods), and 3-format strict parity at 250+
  checks would mean ~750 awkward template strategies. Helm/Terraform
  added per-check where they fit naturally; future deepening can lift
  ratchet ceilings as warranted.
- 250+ check count — shipped 241 (61% growth from 149; close to
  target). Remaining 9 ideas folded into v0.21.x manual-verify
  expansions or held for v0.22.
- **Integration tests against kind clusters** — same shape as v0.20
  Linux's fake-SSH-server gap. Closing collectors/k8s coverage to
  ≥85% needs a fake K8s API server (kube-apiserver-test-fixtures /
  envtest); scoped to v0.22 alongside the Linux SSH transport faking.
- **Per-check `nsa-cisa-k8s` Frameworks: mapping** — the framework
  yaml ships first; per-check mapping fills in as v0.22 refactor
  lifts the spec constructors to the spec-driven shape that makes
  multi-framework wiring cheaper.
- **Live-DOKS smoke test in CI** — gated on `DO_API_TOKEN` +
  `DOKS_CLUSTER_ID`; deferred to v0.22 alongside the action repo
  multi-provider work.

**Definition of done — checklist**

- ⚠️ 250+ K8s checks — shipped 241 (96%; close to target, defer to v0.21.x).
- ✅ NSA / CISA Hardening Guide framework catalog
  (`internal/frameworks/nsa-cisa-k8s.yaml`) shipped.
- ✅ Every K8s check carries bespoke kubectl (parity gate at strict 0).
- ⚠️ Test coverage ≥85% on `internal/checks/k8s/` — shipped 52.4%;
  collectors at 35.7%. Deferred to v0.22 alongside the fake K8s
  API server infrastructure work.
- ✅ README + ROADMAP updated; `examples/quickstart-kubernetes-deep.yaml`
  + `examples/quickstart-doks-deep.yaml` exist.

---

### v0.21 — Kubernetes + DOKS deepening (original plan, kept for reference)

**Goal:** the most comprehensive open-source Kubernetes security
scanner. v0.11 shipped 139 K8s checks (already strong); v0.21
takes that to full CIS Kubernetes Benchmark + NSA/CISA Kubernetes
Hardening Guide + PCI Kubernetes controls + supply-chain
verification (cosign / sigstore attestation).

**Deliverables**

- **139 → 250+ checks** covering:
  - **CIS Kubernetes Benchmark v1.x** — full Master + Worker +
    Policies sections.
  - **NSA / CISA Kubernetes Hardening Guide** — full coverage,
    mapped as a separate framework (`nsa-cisa-k8s`).
  - **PCI DSS Kubernetes** — the K8s-specific subset of PCI v4.0.
  - **Supply chain** — image signature verification (cosign),
    in-toto attestation presence, image source registry
    allowlist enforcement, base image age + EOL audit.
  - **Policy engine** — Gatekeeper or Kyverno presence, ConstraintTemplate /
    ClusterPolicy coverage audit, admission-webhook timing.
  - **Operator patterns** — Operator-Lifecycle-Manager presence,
    operator RBAC scope, CR completion tracking.
  - **RBAC graph analysis** — who can escalate to cluster-admin
    via what chain (currently flagged but not graphed).
  - **DOKS depth** — full add-on coverage, registry-integration
    completeness, node-image freshness, control-plane logging
    destinations.
  - **EKS + GKE depth** — match the DOKS depth.
- **Helm chart hardening** — checks for charts deployed via Helm:
  pinned versions, RBAC scope, secrets handling, hook usage,
  test-pod inclusion.
- **Every check with kubectl + Helm + Terraform remediation.**
  Per ADR-011 + ADR-006, generation only.
- **Integration tests against kind clusters** (committed kubeconfig
  + deployed-resource fixtures), plus optional **DOKS smoke**
  gated on `DO_API_TOKEN` + `DOKS_CLUSTER_ID`.
- **Final phase: docs polish** — per-check remediation prose,
  `--help` polished, new `examples/quickstart-kubernetes-deep.yaml`
  + `examples/quickstart-doks-deep.yaml` walking through full CIS
  + NSA coverage.

**Definition of done**

- 250+ K8s checks registered.
- NSA / CISA Hardening Guide ships as a new framework catalog
  (`internal/frameworks/nsa-cisa-k8s.yaml`).
- Every K8s check carries kubectl + Helm + Terraform remediation
  (CI gate).
- Test coverage ≥85% per file in `internal/checks/k8s/` and
  `internal/collectors/k8s/`.
- README + CHECKS.md updated.

---

### v0.22 ✅ — Internal refactor + toolchain refresh + action-repo polish (shipped 2026-05-17)

Structure debt paid down before v1.0 (#18). v0.22 shipped 8 of the
20 originally-drafted phases — the load-bearing refactor + toolchain
+ action work — and deferred spec-pattern lifts + fake-API-server
coverage + lint v2 + deep cookbook to v0.22.x point releases.

**Shipped**

- ✅ **600-LoC check-file CI gate** — new `internal/repocheck/`
  package with `TestCheckFilesUnderSizeLimit` (`file_size_test.go`).
  Walks `internal/checks/` + asserts every non-test `.go` file ≤
  600 LoC. Allowlist-based ratchet (same shape as parity tests) —
  closed empty after Phase 4 so future regressions fail pre-commit.
- ✅ **9 oversize files split** (was 6713 LoC over the ceiling
  across 9 files; now 0):
  - `k8s/rbac.go` (1045 → 486) → `rbac_roles.go` + `rbac_bindings.go`
  - `k8s/pods.go` (904 → 543) → `pods_resources.go` + `pods_volumes.go`
  - `k8s/network.go` (879 → 420) → `network_ingress.go` + `network_policies.go`
  - `k8s/cluster.go` (701 → 550) → `cluster_quotas.go`
  - `k8s/reliability.go` (671 → 466) → `init_containers.go`
  - `k8s/eks.go` (649 → 450) → `eks_nodegroups.go`
  - `aws/iam.go` (635 → 468) → `iam_policies.go`
  - `k8s/pods_extra.go` (627 → 581) → `pods_groups.go`
  - `digitalocean/tail.go` (602 → 506) → `projects_hygiene.go`

  11 new per-category sibling files; each file owns its own init()
  registering its own checks (no behavior change, no LoC growth).
- ✅ **Toolchain refresh**:
  - `runs-on: ubuntu-latest` → `runs-on: ubuntu-24.04` explicit pin
    in all three workflows (ci.yaml, release.yaml, govulncheck.yaml).
    `ubuntu-latest` already resolves to 24.04 since GHA Jan 2025;
    this prevents a future bump silently breaking builds.
  - `digitalocean/godo` + `spf13/cobra` + `spf13/viper` +
    `open-policy-agent/opa` + `k8s.io/{api,apimachinery,client-go}`
    (v0.34.1 → v0.36.0) bumped via `go get -u` + `go mod tidy`.
    Conservative — AWS SDK + GCP SDK majors held back for separate
    focused commits in v0.22.x.
- ✅ **compliancekit-action polish**:
  - **Multi-provider input** — old code silently dropped everything
    past the first comma-separated provider. New loop runs
    `compliancekit scan <provider>` per entry into per-provider
    sub-out-dirs + jq-merges findings.json arrays at the top-level
    out-dir. Worst-case exit code propagates so the action still
    fails on any provider's severity-floor breach.
  - **`upload-evidence-pack: true` input** — opt-in workflow-artifact
    upload via `actions/upload-artifact@v4`. New companion inputs
    `evidence-artifact-name` + `evidence-artifact-retention-days`.

**Deferred to v0.22.x point releases**

- **Spec-pattern lifts** — AWS IAM + GCP IAM + K8s pod-security
  onto the v0.20 spec shape. Value is real (~520 LoC cut targeted)
  but each lift is its own focused commit; running them under time
  pressure in the same milestone as the file splits would have
  conflated two diffs.
- **Fake K8s API server + fake SSH server** — closes the v0.20
  Linux collectors (53.7%) + v0.21 K8s collectors (35.7%) coverage
  gaps. Both need envtest / golang.org/x/crypto/ssh server-mode
  test-fixtures, scoped together as a focused commit.
- **golangci-lint v1.64.8 → v2.x migration** — config schema
  changed; needs careful per-linter reconciliation, brew formula
  pin update, lefthook config refresh.
- **Deep cookbook + docs pass** — 9 recipe playbooks
  (SOC2/ISO/PCI/HIPAA workflows) + 7 CI/CD integrations + ~50
  reference Rego policies + new CONTRIBUTING.md + ADR index +
  CHANGELOG.md (git-cliff) + SECURITY.md refresh. Scoped as its
  own milestone — the writing surface is large enough that
  combining it with the refactor would have produced a thin pass
  on both.
- **`internal/testutil/` extraction** — consolidate the
  `compliancekit.Resource` builder helpers. Cosmetic; ships with the
  spec-lift work.

**Definition of done — checklist**

- ✅ No check-registration file >600 LoC (CI-enforced).
- ⚠️ Spec-pattern lifts (AWS IAM + GCP IAM + K8s pod-security)
  — deferred to v0.22.x.
- ⚠️ golangci-lint v2 in CI + pre-commit — deferred to v0.22.x.
- ⚠️ `internal/collectors/linux/` + `/k8s/` coverage ≥85% —
  deferred to v0.22.x (fake API server work).
- ✅ All three GHA workflows pin `ubuntu-24.04` explicitly.
- ✅ Direct-dep sweep complete on the top-leverage subset.
- ✅ compliancekit-action accepts multi-provider input + offers
  evidence-pack workflow-artifact upload.
- ✅ Total Linux + CI test wall-clock not regressed >10% vs v0.21.
- ⚠️ Docs deep pass + cookbook — deferred to a focused milestone.

---

### v0.22 — Internal refactor + toolchain refresh + cookbook (original plan, kept for reference)

**Goal:** pay down accumulated structure debt before the v1.0 API
freeze (#18). v0.6 → v0.21 added 482 checks across 6 providers + 7
ingest adapters + 10 remediation formats + 8 notify sinks + waivers
+ policy DSL. The package boundaries are sound (kubescape / Trivy /
Prowler all settled on the same flat per-provider layout) so v0.22
is **deliberately not a directory rearrangement**. The win is in
file-level navigability, adopting the v0.20 spec-driven pattern
where it pays off, and getting the toolchain current before we
freeze the API surface.

Scoped tight to keep the milestone reviewable + to avoid blocking
v1.0 on refactor scope creep. **No new user-facing checks.**

**Why this slot and not a continuous refactor**

Three of the six providers (DigitalOcean v0.19, Linux v0.20,
Kubernetes v0.21) each shipped 90+ new files in a single milestone.
Refactoring mid-deepening means re-refactoring after each one. v0.22
runs *after* v0.21 closes for the same reason v0.20 ran after v0.19:
the spec-driven pattern only crystallizes after enough surface
exists to recognize the shape worth lifting out.

**Deliverables**

- **File split — 6 oversize files.** Mechanical split along
  existing logical boundaries; no behavior change. CI gate: no
  check-registration file >600 LoC after this milestone.
  - `internal/checks/k8s/rbac.go` (1045 LoC) → `rbac_roles.go` +
    `rbac_bindings.go` + `rbac_serviceaccounts.go`
  - `internal/checks/k8s/pods.go` (904 LoC) → `pods_security.go` +
    `pods_resources.go` + `pods_network.go`
  - `internal/checks/k8s/network.go` (879 LoC) → `network_policies.go`
    + `network_ingress.go` + `network_services.go`
  - `internal/checks/k8s/cluster.go` (701 LoC) → `cluster_admission.go`
    + `cluster_apiserver.go`
  - `internal/checks/k8s/eks.go` (649 LoC) → split by EKS family
    (control-plane / nodegroup / addons)
  - `internal/checks/aws/iam.go` (635 LoC) → split by IAM resource
    type (users / policies / roles / mfa)
- **Spec-driven pattern adoption.** The v0.20 spec-shape (struct
  literal slice + init() loop + per-shape closure) drove the
  Linux check surface from 15 → 119 with minimal LoC growth. Lift
  it into the providers where 50%+ of checks share a shape:
  - **AWS IAM** — policy-attached-to-user, password-policy, MFA-
    enforced, access-key-rotation all fit one spec; cuts ~150 LoC.
  - **GCP IAM** — same shape; cuts ~120 LoC.
  - **K8s pod-security** — runAsNonRoot, allowPrivilegeEscalation,
    readOnlyRootFilesystem, hostNetwork, hostPID, hostIPC all fit
    one `psSpec`; cuts ~250 LoC.
- **Lint + toolchain refresh.**
  - **golangci-lint v1.64.8 → v2.x.** Migration is non-trivial —
    config schema changed (`linters:` block restructured),
    `gocyclo` thresholds re-tune, removed linters need
    substitutes. Reconcile [`.golangci.yaml`](.golangci.yaml) +
    update [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) +
    [`feedback-collab`] memory + Homebrew formula pin.
  - **Go 1.27** when GA (currently 1.26.3); bump `go.mod`,
    `.github/workflows/*.yaml` `GO_VERSION`, Dockerfile, and the
    GoReleaser build matrix.
  - **Ubuntu runner pin.** `runs-on: ubuntu-latest` is already
    24.04 since GHA bumped the alias in Jan 2025. Pin explicitly
    to `ubuntu-24.04` in all three workflows (`ci.yaml`,
    `release.yaml`, `govulncheck.yaml`) so a future
    `ubuntu-latest` bump to 26.04 doesn't silently break builds.
  - **Dependency sweep.** `go list -u -m all` per phase; bump
    AWS / GCP / godo / hcloud / k8s.io / OPA / cobra / viper to
    their latest minor versions; `go mod tidy`. Per-bump test
    + lint + integration smoke before staging.
- **Test infrastructure.**
  - **Fake SSH server** for `internal/collectors/linux/` — closes
    the v0.20 deferred coverage gap (53.7% → ≥85%). The
    `gatherX` / `Dial` / `RunCommand` 0% blocks all gate on this.
  - **Test helpers consolidation** — `internal/testutil/` for
    the `compliancekit.Resource` builder helpers that have drifted into
    per-package `*_test.go` files (`hostWithSSHD`, `hostWithMAC`,
    `hostWithAuditRules` in checks/linux; equivalents in checks/k8s,
    checks/digitalocean). One canonical builder, per-provider
    convenience constructors.
- **compliancekit-action repo polish.**
  - **Multi-provider input.** Today `providers: digitalocean,linux`
    silently runs only the first (`scan` accepts one positional).
    Loop the comma-separated list + aggregate findings; backwards-
    compat with single-provider input.
  - **Version pinning.** `version: latest` resolves at job start —
    fragile against new releases mid-CI. Default to a pinned
    `latest-stable` (the latest non-prerelease tag at action
    build time); `latest` becomes opt-in.
  - **Output upload polish.** Optional `upload-evidence-pack:
    true` action input that uploads `evidence/` as a workflow
    artifact using `actions/upload-artifact@v4`.
  - **Node 20 → Node 22.** GitHub deprecated Node 16 in 2024;
    bump for the upload-sarif sub-action versions that depend on
    it (`github/codeql-action@v3` is already there; ensure other
    composite sub-actions are on `@v4`).
  - **Action test matrix.** `tests/` folder with workflow runners
    exercising every action input combination on `ubuntu-24.04` +
    `ubuntu-22.04` (back-compat) + `macos-14` (mac runners exist).
- **Docs polish (deep pass — first since v0.12).** Every shipping
  doc gets a reread + rewrite where it's drifted. Not surface
  edits — real restructure where v0.6 → v0.21 changed the shape
  of the project.
  - **README.md** — top-of-fold pitch tightened against the 482-
    check / 8-framework reality. "What's in the box" rewritten
    (the v0.6 table doesn't reflect spec-driven checks, waivers,
    Rego, notify, ingest, remediate). New "How auditors actually
    use this" section sourced from the v0.18-v0.20 evidence-pack
    work.
  - **docs/ARCHITECTURE.md** — §6 (Code organization) refreshed
    for the spec-pattern + 600-LoC invariant. §13 (Air-gapped
    operation) re-validated against the v0.13-v0.16 embed
    additions (frameworks, policies, mappings). New §X
    (Spec-driven check authoring) walks the pattern end-to-end.
  - **docs/DEVELOPMENT.md** — golangci-lint v2 config shape,
    spec-pattern authoring loop (struct → init() → register →
    test), the new `internal/testutil` helper API, the
    `*_<GOOS>_test.go` build-tag gotcha codified.
  - **CONTRIBUTING.md** — new, top-level. End-to-end "add a new
    check" walkthrough using the v0.20 spec-pattern; for each
    of the four provider archetypes (cloud-API, K8s-API,
    SSH-host, file-system) show the minimal struct + test +
    spec + remediation snippet to land a single check.
  - **ADR index consolidation.** docs/decisions/README.md (new)
    indexes ADR-001 → ADR-013 with status (Accepted / Resolved /
    Superseded / Revisited-at-v1.0). Retrospective table — which
    decisions held under load, which decisions need a second look
    before the v1.0 freeze.
  - **SECURITY.md** refresh — 2-year backwards-compat commitment
    language drafted ahead of v1.0. CVE-disclosure email + GPG
    key + 90-day disclosure window per industry norm.
  - **CHANGELOG.md** — new, auto-generated from conventional
    commit history via [git-cliff](https://git-cliff.org/) so it
    stays in sync. v0.1 → v0.20 backfilled from the existing
    tags + this ROADMAP.
  - **docs/checks.md** — regenerated (counts unchanged; remediation
    text changes for the AWS/GCP/k8s checks lifted into specs).
- **Deep examples — the "compliancekit Cookbook".** The
  existing `examples/quickstart-*.yaml` files are config-shape
  references. The Cookbook is the *workflow* layer — what
  auditors / SREs / security teams actually do with compliancekit
  over a quarter, not just "here's a config that scans X".
  - **`examples/recipes/`** — markdown playbooks, one per workflow:
    - `soc2-audit-pack.md` — SOC 2 12-week evidence collection
      timeline; what to capture each week; how to wire to your
      auditor's portal.
    - `iso27001-readiness.md` — ISO 27001:2022 Annex A readiness
      pass; control-by-control evidence checklist with which
      compliancekit checks satisfy what.
    - `pci-quarterly-scan.md` — PCI DSS v4.0 quarterly scan +
      waiver + POA&M emit flow; QSA-ready evidence pack.
    - `hipaa-baa-attestation.md` — HIPAA Security Rule §164.308/
      310/312 evidence walk with BAA-required artifact mapping.
    - `multi-cloud-fleet.md` — AWS + GCP + DO + Hetzner in one
      CI workflow with consolidated reporting + per-cloud waiver
      partitioning.
    - `k8s-pod-security-rollout.md` — applying CIS K8s benchmark
      + Pod Security Admission enforcement in stages, with
      waiver-based progressive rollout.
    - `linux-cis-l1-to-l2.md` — progressive CIS Linux Server
      hardening from L1 baseline → L2 high-security, leaning on
      the v0.20 tagged-section catalog.
    - `ci-gate-tuning.md` — composing `fail-on` × `severity-floor`
      × `baseline-diff` × `only-new-findings` for your team's risk
      tolerance; common pitfalls.
    - `evidence-pack-shipping.md` — what auditors actually want:
      OSCAL vs HTML vs CSV vs SARIF, redaction policies, raw-
      finding access via `--include-raw`, sha256 manifest
      verification.
  - **`examples/integrations/`** — end-to-end working configs for
    the toolchains people actually run:
    - `github-actions/` — multiple workflows: scheduled audit,
      PR-gate, baseline-diff, evidence-pack-on-tag, multi-cloud
      matrix.
    - `gitlab-ci/`, `jenkins/`, `circleci/` — equivalent shapes
      for non-GitHub teams.
    - `argocd/` — running compliancekit as an ArgoCD sync-wave
      pre-step so K8s deployments gate on compliance.
    - `datadog/` — forwarding `findings.json` to DD via fluent-bit
      so security teams see findings in the same UI as their
      observability data.
    - `splunk/` — same, for Splunk shops.
  - **`docs/cookbook.md`** — single-page index of every recipe
    + every integration, with a "use-case → recipe" navigation
    table so an SRE landing cold can find the right playbook in
    <30 seconds.
  - **`examples/policies/` extension** — the v0.16 Rego examples
    cover 15 reimplementations across providers. Extend with a
    full reference policy library (~50 policies) showing the
    canonical Rego pattern for each spec shape lifted in this
    milestone.

**Phase shape (estimate, per-commit-gate maintained)**

| Phase | Scope |
|---|---|
| 0 | Repo audit + file-size CI gate (fails pre-commit if any check file >600 LoC) |
| 1 | Split k8s/rbac.go (1045 → 3 files) |
| 2 | Split k8s/pods.go (904 → 3 files) |
| 3 | Split k8s/network.go + cluster.go + eks.go + aws/iam.go |
| 4 | AWS IAM spec-pattern lift |
| 5 | GCP IAM spec-pattern lift |
| 6 | K8s pod-security spec-pattern lift |
| 7 | Fake SSH server + collectors/linux coverage 53.7% → ≥85% |
| 8 | internal/testutil helpers extraction |
| 9 | golangci-lint v1 → v2 config migration + reconcile |
| 10 | Go 1.27 bump (gated on Go 1.27 GA — fallback: defer to v0.23) |
| 11 | Dependency sweep (AWS SDK / GCP SDK / godo / k8s.io / OPA / cobra / viper) |
| 12 | Ubuntu 24.04 pin + workflow YAML refresh |
| 13 | compliancekit-action multi-provider + version-pin + Node 22 + test matrix |
| 14 | README rewrite + ARCHITECTURE deep refresh |
| 15 | DEVELOPMENT.md + new CONTRIBUTING.md + ADR index consolidation |
| 16 | SECURITY.md refresh + CHANGELOG.md backfill (git-cliff) |
| 17 | examples/recipes/ — 9 workflow playbooks |
| 18 | examples/integrations/ — 7 CI/CD + observability integrations |
| 19 | examples/policies/ extension — ~50 reference Rego policies + cookbook index |
| 20 | Final docs/checks.md regen + ROADMAP polish |

**Definition of done**

- No check-registration file >600 LoC (enforced by CI gate).
- AWS / GCP IAM + K8s pod-security on spec-driven shape; net LoC
  decrease ≥400 across those areas.
- golangci-lint v2.x in CI + pre-commit; v1.64.8 references purged
  from docs.
- `internal/collectors/linux/` coverage ≥85% (closes v0.20 defer).
- All three GHA workflows pin `ubuntu-24.04` explicitly.
- `go list -u -m all` shows no minor-version drift on the top-15
  most-used deps.
- compliancekit-action accepts comma-separated `providers:` input
  + offers `version: latest-stable`.
- Total Linux + CI test wall-clock not regressed >10% vs v0.21.
- **Docs deep pass shipped:** README + ARCHITECTURE + DEVELOPMENT
  rewritten where drifted; new CONTRIBUTING.md + ADR index +
  CHANGELOG.md backfilled; SECURITY.md refreshed for v1.0 compat
  language.
- **Cookbook shipped:** 9 recipe playbooks + 7 integration configs
  + ~50 reference Rego policies + single-page cookbook index at
  `docs/cookbook.md`.

**Out of scope at v0.22 (explicit deferrals)**

- **New checks or new framework catalogs.** Goes to v0.21
  (K8s deepening) or v1.3+ (post-API-freeze and UX polish).
- **`pkg/compliancekit` extraction.** That's the v1.0 milestone
  (#18). v0.22 stays under `internal/`.
- **Multi-binary split** (`ck-collector`, `ck-emit`, etc.).
  No demand signal yet; revisit at v2.x if the plugin marketplace
  needs it.
- **Per-service subfolders under each provider.** Considered + ruled
  out — every comparable scanner (kubescape, Trivy, Prowler,
  steampipe) keeps flat per-provider packages because Go subpackage
  semantics impose more friction than the navigability win is worth.
- **macOS / Windows / BSD hardening.** Re-slotted to v2.5 per ADR-016 (v1.x reserved for server / UI / UX / backend / CLI polish; OS-coverage expansion is a v2.x scope-expansion concern).

---

### v1.0 — API stability — `pkg/compliancekit` frozen — ✅ shipped 2026-05-18

**Goal:** anyone embedding compliancekit gets a real contract.

**Shipped as 13 phase-per-commit commits over one weekend.** See
[ADR-014](DECISIONS.md#adr-014--v10-api-freeze-pkgcompliancekit-is-the-semver-surface)
for the full scope rationale + rejected alternatives. The actual
public surface is enumerated in
[`pkg/compliancekit/api.txt`](pkg/compliancekit/api.txt) and is
machine-enforced by the `make api-check` CI gate. Per-minor support
windows are in [SECURITY.md](SECURITY.md#two-year-compatibility-commitment-v10).

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

### v1.1 — Beautiful CLI

**Goal:** the CLI looks the part for the audience that lives in the terminal. v0.x shipped functional output; v1.1 makes the same output feel like the rest of the modern Go-tool ecosystem (k9s, glow, gh, lazygit) without sacrificing scriptability.

**Deliverables**

- **Severity-coloured output**, palette tuned for both light and dark terminals: `critical`=red, `high`=orange-bold, `medium`=yellow, `low`=blue, `info`=grey, `pass`=green-dim, `skip`=grey-italic. Status glyphs `✓ ✗ ⚠ –` paired with the colours so colour-blind readers and grep-pipelines still parse the output.
- **Unicode box-drawing tables** for the structured-list commands: `checks list`, `checks show`, `doctor`, `waivers list`, `mapping list`, `notify --list`, `policy validate`. Column widths auto-fit the terminal; long values get truncated with a final ellipsis. Plain ASCII fallback under `--plain`.
- **Scan progress bar** during `compliancekit scan`: live per-provider counter (`digitalocean (45/144)`), elapsed timer, current resource being evaluated. Replaces the v0.x newline-per-line `scanning digitalocean (574 checks)...` static text. Bubbletea-driven, redraws in-place via `\r`.
- **Diff colourisation** in `compliancekit diff`: new findings in green, resolved in dim-strikethrough, existing in grey, severity-coloured per-finding chip.
- **Doctor pretty-printer**: table view of every probe with status glyph + latency badge instead of the v0.x flat key=value lines. Failures sort to the top.
- **Help text styling**: `compliancekit --help` and every subcommand's `--help` renders with bold section headers, indented argument groups, and an `Examples:` block at the bottom. Cobra defaults replaced with a custom usage template (~50 LoC).
- **Shell completion**: `compliancekit completion bash|zsh|fish|powershell` writes a script per shell. Same shape as `kubectl completion`. Cobra's built-in generator wired in; brew/install.sh post-install hooks document the install path.
- **TTY auto-detection + NO_COLOR**: colour and progress-bar output gate on `isatty(stdout)` AND the absence of `NO_COLOR` (per the [no-color.org spec](https://no-color.org)). CI runs see the v0.x-style plain output unchanged; `--no-color` forces plain on a TTY for piping into `tee` / `less`.
- **`compliancekit motd`** (optional): single-screen "your fleet at a glance" — total findings, score, top-3 critical, baseline drift since last scan. The thing you `alias mc=compliancekit motd` and run after every coffee.

**Out of scope at v1.1**

- Full interactive TUI (k9s-style cluster browser). Promoted to v1.3+ if there's demand after `serve` lands and the daemon's REST surface gives the TUI something to fetch from.
- Theming / colour-palette config in `compliancekit.yaml`. The default palette is auditable + accessible; per-user theming is overkill for the v1.x audience.

**Dependencies added**

- `github.com/charmbracelet/lipgloss` for styled output — small, Go-idiomatic, no JS/Node dependency. Adds ~1 MB stripped to the binary.
- `github.com/charmbracelet/bubbletea` for the scan progress bar (interactive component). Lipgloss is the styling layer; bubbletea is the event-loop / state-machine for the progress component. Adds ~2 MB stripped.

**No API surface change** (pkg/compliancekit unchanged). Pure CLI presentation layer.

---

### v1.2 — HTML report overhaul

**Goal:** the HTML report goes from "a JSON dump rendered as a table" to "the artifact you screenshot for the board deck." Matches the v1.1 CLI polish energy in the browser.

**Deliverables**

- **Summary cards with charts**: at the top of `findings.html`, a row of cards — score (gauge), total findings (severity donut), framework coverage (horizontal bar). Pure SVG, no JS chart library; ~300 LoC of inline JS that draws to `<svg>` elements at render time. Charts honour the dark/light toggle.
- **Baseline-vs-current trend sparklines**: when `--baseline=path.json` is passed at render time, every per-check row + each summary card gains a 7-data-point sparkline showing the trend across the last week of baselines (if available). Sparklines render at 60×16px inline next to the headline number.
- **Filter chips at the top** (severity, status, provider, framework): clickable toggles that filter the finding list inline without a page reload. Multi-select OR within each chip group, AND across groups. URL fragment updates so a state is shareable.
- **Sticky resource sidebar**: left column lists every resource grouped by type/provider; click a resource to scroll to its findings block. Sidebar is sticky on scroll. Mobile layout collapses it into a hamburger menu.
- **Dark/light/system toggle**: three-state switch in the top-right; setting persisted to `localStorage`. CSS variables drive the palette; flips instantly without re-render.
- **Print stylesheet** (`@media print`): auditor wants to print the pack. Chrome's "Save as PDF" → readable A4 layout, no sidebar, no sticky chrome, charts rendered as static SVG that survives print conversion.
- **Mobile layout**: every section reflows to <=400px width. Severity chips, sparklines, and filter chips all stack vertically. Tested at iPhone-SE and standard tablet widths.
- **Deep-link share views**: the URL fragment encodes the current filter + dark-mode + sidebar state, so `findings.html#severity=critical,high&fw=soc2&dark=1` is a shareable bookmark. Operators paste these into Slack/PR comments to point reviewers at a slice.
- **Empty-state celebration**: when a scan produces zero actionable findings, the summary card renders a "All clear — 574 / 574 checks pass" panel with a small icon. The auditor's "nothing to see here" page should look intentional, not blank.
- **Embedded SVG icons** for provider logos (DO, AWS, GCP, Hetzner, K8s, Linux) and severity glyphs. No web font; no CDN call. Single-file output is preserved.

**Out of scope at v1.2**

- Server-rendered live dashboard. That's v1.3's `serve` mode.
- Per-finding deep-link permalinks (`#finding=do-spaces-public-acl-bucket-x`). Probably ships in v1.3 alongside the REST API.
- Comparison views (two HTML reports side by side). Same answer: v1.3+ with `serve`.

**No API surface change** (pkg/compliancekit unchanged). Pure reporter polish in `internal/report/`.

---

## v1.x — server / UI/UX / backend / CLI polish (v1.6 – v1.19)

After v1.5 ships the explorer + remediation studio, every v1.x slot
through v1.19 is deliberately scoped to **server, frontend, UI/UX,
backend, and CLI polish**. No new providers, no new frameworks, no new
GRC features in v1.x — those are reserved for v2.x. The thesis: a
world-class daemon experience is the moat. Multi-tenant, Trust Center,
GRC layer, auditor portal, tail clouds, OSCAL ecosystem, OS-coverage
expansion, and risk-score modelling all get re-slotted to v2.1–v2.8.

The lineup explicitly invests in the "magnificent dashboard" layer
that separates a functional admin UI from a Linear / Vercel / Wiz-tier
product: v1.18 owns the design system + motion + skeletons + magic
moments + chart interactivity; v1.19 owns onboarding 2.0 + global
fuzzy search + table 2.0; and v1.8 / v1.12 / v1.14 scope up to cover
notification inbox 2.0, settings UX excellence, and chart-interactivity
hooks respectively.

**Stack-independent visual ceiling.** ADR-015 commits the daemon UI to
htmx + Alpine + Tailwind + Preline + vanilla SVG (no React, no Node
runtime, contributors stay Go-only). That stack choice is **not** a
quality ceiling. The benchmark for v1.18 + v1.19 is what modern
React + shadcn/ui dashboards (e.g. Linear, Vercel, Wiz) achieve "for
free" via vendored component libraries — compliancekit invests the
equivalent effort in carefully crafted htmx + Alpine partials under
`internal/server/ui/design/components/` to hit the same visual +
interaction ceiling. If a design or interaction is achievable in the
React+shadcn world, it is in-scope for v1.18+; the htmx stack
constrains *how* we implement, never *what quality* we ship.

See [ADR-016](DECISIONS.md#adr-016--v1x-is-fully-scoped-to-server--uiux--backend--cli-polish) for the scope decision and the explicit deferral list.

---

### v1.6 — Live Operations

**Goal:** the daemon's UI moves from request/response polling to live, event-driven updates. Operators watching a scan run, watching critical findings come in, or watching webhooks fire shouldn't have to refresh.

**Deliverables**

- **SSE event bus** at `GET /api/v1/events`. Server-sent events with cursor-based replay (`?since=<cursor>`) so reconnecting clients don't miss events. Per-tenant when v2.1 lands; per-user for now. Event types: `scan.queued`, `scan.started`, `scan.progress`, `scan.completed`, `finding.created`, `finding.resolved`, `webhook.received`, `auth.session.created`.
- **WebSocket fallback** at `/api/v1/ws` for full-duplex (admin console live log tail, interactive scan-progress drill-down). Same event vocabulary; chosen when the client needs bidirectional.
- **Live dashboard cards**: home, scans list, findings list, providers status all subscribe to `/events` and update in place via Alpine.js stores. No `setInterval(fetch, 5000)` anywhere.
- **Scan-progress streaming**: per-resource granularity. `GET /api/v1/scans/{id}/stream` emits `resource.started`, `resource.completed`, `check.completed` events as the worker walks the tree. The UI renders a "now scanning: aws/iam/user/alice" status bar plus a per-provider progress bar.
- **Multi-tab BroadcastChannel sync**: state changes (filter selection, theme, notification reads) sync across browser tabs. Per-tab claim semantics so only one tab holds the live SSE connection for a given user (others mirror via BroadcastChannel) — saves daemon connection budget.
- **Toast system**: corner toast that pops on new critical-severity finding, new comment mention, webhook received. Click-to-dismiss; clicking opens the relevant detail panel.
- **In-UI log tail**: admin-only page streaming `daemon stderr` via WebSocket. Useful when "why is the worker stuck" can't wait for SSH.
- **Connection-loss UX**: reconnecting indicator in the nav bar; events buffered server-side per cursor for 5 minutes so a brief disconnect replays cleanly.
- **Activity timeline**: home page shows the last 50 server events in a vertical timeline. Filterable by event type.

**Out of scope at v1.6**

- Live collaboration cursors / presence indicators. That's v1.8 collaboration.
- Push notifications outside the browser tab. PWA push lands at v1.16.

**Dependencies added**

- `github.com/r3labs/sse/v2` for the SSE producer (small, idiomatic, supports replay).
- No frontend deps — Alpine + native EventSource handle SSE; native WebSocket handles WS.

**No API surface change to `pkg/compliancekit`**. New REST + WS endpoints under `/api/v1/`.

---

### v1.7 — TUI mode (k9s for compliance)

**Goal:** a Bubble Tea terminal UI that puts the v1.5 explorer in `tmux`. Operators who live in the terminal get the same density and interactivity without leaving the shell.

**Deliverables**

- **`compliancekit tui`** subcommand. Bubble Tea event loop. Two source modes:
  1. **Local**: `--findings=path.json` opens a static findings.json (offline).
  2. **Daemon**: `--server=http://localhost:8080 --api-token=ck_…` (or `$CK_API_TOKEN`) opens against a running daemon — subscribes to `/events` for live updates.
- **Multi-pane layout**: left tree (frameworks → providers → severities), middle finding list (paginated, virtualised), right detail panel. Resizable with `[` / `]`.
- **Vim keybindings**: `j/k`, `gg/G`, `/`-search, `n/N` next/prev match, `:command` for ad-hoc filters (`:fw=soc2`, `:sev>=high`, `:provider=aws`). All v1.5 explorer filter parity.
- **Live tail mode**: `:tail` enters live-tail; new events stream into the list with a green flash.
- **Resource-graph navigator**: `g` opens an in-terminal box-drawing graph of the dependency tree from the v0.x ResourceGraph. Navigate with arrow keys; Enter focuses a node and filters findings to it.
- **In-place actions**: `w` waive (prompts for reason + duration), `a` ack, `c` comment (opens `$EDITOR`), `r` remediate-preview (shows the v0.15 generator output in a side panel). When connected to daemon, actions hit the REST API; when local, prints a YAML patch suggestion.
- **Diff-vs-baseline**: `:diff path.json` overlays a previous baseline; new/resolved findings get colour-coded gutters.
- **Help overlay**: `?` opens a Karabiner-style keymap legend.
- **Theme matching v1.1 CLI**: the same `internal/ui` palette + glyphs + adaptive colours drive the TUI.
- **Headless test harness**: Bubble Tea's `teatest` package drives golden snapshots of every screen.

**Out of scope at v1.7**

- Inline charts / sparklines (the terminal canvas is the limit). Score and trend numbers shown numerically.
- Writing back arbitrary structural changes — TUI edits are limited to waive/ack/comment. Anything else punts to the web UI.

**Dependencies added**

- `github.com/charmbracelet/bubbletea` (already added at v1.1 for the scan progress bar).
- `github.com/charmbracelet/bubbles` for stock list + viewport + textinput components.

**No API surface change to `pkg/compliancekit`**. `internal/tui/` is the new home for the TUI code.

---

### v1.8 — Collaboration & workflow

**Goal:** findings stop being a wall of read-only text and become a conversation. Comments, assignees, mentions, and two-way sync with the systems your team already lives in.

**Deliverables**

- **Per-finding markdown comments**: thread on every finding. Edit history (Linear-style "edited 3m ago"). Rich-text via simple markdown subset (bold, italic, code, lists, links — no HTML).
- **Assignees / ownership**: per-finding `assignee` + per-resource `owner`. Auto-assign rules layer on at v1.9 (e.g. "AWS IAM findings → @security-team").
- **Activity stream**: every finding gets a chronological activity log — state changes, comments, waivers, scan re-runs that touched it, webhook events that referenced its resource.
- **Mentions**: `@user` and `@team` autocompletes in comment editor; triggers in-UI notification + email/Slack via v0.17 sinks.
- **Slack/Teams reply-in-thread**: when v0.17 posts a finding to a Slack thread, the thread accepts replies that the daemon ingests as comments. Slash-actions `/ack`, `/waive <reason>`, `/assign @user` work in-thread.
- **GitHub PR-comment two-way sync**: when a finding has an associated PR (v1.3 webhook receiver), comments on that finding mirror to the PR; PR-comment replies mirror back.
- **Jira / Linear two-way**: issue status changes (Done / Closed) mirror finding state (Resolved); finding state changes mirror back. Mapping configurable per-sink.
- **Team management UI**: create teams, assign members, set notification preferences per team.
- **Followers per resource**: subscribe to "any finding on `aws/iam/user/alice` notifies me".
- **Email digest builder**: configurable daily/weekly summaries (which findings, which resources, which frameworks).
- **Notification inbox 2.0**: builds on the v1.4 inbox (which is a flat list + read/unread) — snooze (revisit in 1h / 4h / tomorrow / next week), mark-all-read, filter by event type (finding / scan / webhook / mention / system), per-event-type preferences (notify-here vs. email-only vs. silent), quiet hours / DND with timezone-aware schedule, "muted threads" so a single noisy finding doesn't drown the inbox.

**Out of scope at v1.8**

- Real-time presence (who's viewing this finding right now). Premature; punt to v2.x if demand surfaces.
- Voice / video. Out of scope forever.

**Dependencies added**

- `github.com/yuin/goldmark` for markdown rendering (server-side, sanitised).
- No new external sink integrations — uses the v0.17 notification clients for two-way.

**API surface additions**: `Finding.Comments`, `Finding.Assignee`, `Finding.Followers` added under `pkg/compliancekit`. Backwards-compatible: new fields are pointers/slices, omitted when empty.

---

### v1.9 — Workflow automation / rules engine

**Goal:** the runbook moves from "post-it on the monitor" to "if-this-then-that rules the daemon enforces." Conditional notifications, expiring waivers, multi-approver flows, and rule simulation against historical scans.

**Deliverables**

- **Rules engine UI**: visual if-this-then-that builder. Conditions composed AND/OR.
- **Condition library**: severity, framework, provider, resource type, resource tag, finding age, drift-delta from baseline, time-of-day, day-of-week.
- **Action library**: notify (any v0.17 sink, with custom template), assign (user / team / round-robin), waive with auto-expiry, open issue (Jira / Linear / GitHub), run remediation script (audit-only — v2.11 lifts the audit gate for `--apply-fix`).
- **Scheduled actions**: cron-style schedules (timezone-aware) — "every Monday 9am, summarise unresolved high+critical to #compliance".
- **Multi-approver waiver flows**: waivers above a configurable severity threshold require N approvers before becoming active. Approver list configurable per rule.
- **Exception expiry automation**: when a waiver's `ExpiresAt` passes, the daemon automatically re-opens the finding + fires a notification.
- **Conditional notification routing**: same finding routes to different sinks based on conditions (e.g. critical → PagerDuty, high → Slack, medium → digest).
- **Rule simulator**: pick a rule + a 30-day window; the daemon replays past scans against the rule and shows what would have triggered. Catches over-eager rules before they fire in production.
- **Audit log**: every rule action lands in the v1.12 hash-chained audit log (rule_id, trigger event, action, outcome).

**Out of scope at v1.9**

- Arbitrary code execution as a rule action. Rules call named built-in actions only; custom logic lives in v1.13 plugins or v0.16 Rego.
- ML-driven anomaly detection. Out of scope forever.

**Dependencies added**

- None new — the rules engine is a pure-Go evaluator over the existing event bus from v1.6.

**API surface additions**: `Rule`, `RuleCondition`, `RuleAction` types under `pkg/compliancekit/rules`. New subpackage so the core surface stays clean.

---

### v1.10 — Accessibility, i18n, keyboard excellence

**Goal:** compliancekit is usable by every operator, in every language, on every input device. WCAG AA conformance audit + first non-English translations + keyboard parity with mouse.

**Deliverables**

- **WCAG AA audit**: third-party-style sweep (we'll run axe-core in CI). Fixes: colour contrast (already partial at v1.2), focus indicators, ARIA labels, skip links, heading hierarchy.
- **Full keyboard navigation**: every interactive element reachable via Tab. Skip-to-content link. Focus traps on modals. `Esc` always closes. Cmd/Ctrl-K command palette parity from v1.5.
- **Screen-reader pass**: tested under NVDA (Windows), VoiceOver (macOS / iOS), JAWS. Every chart has a textual alternative; every icon has an aria-label.
- **ARIA live regions**: SSE-driven updates announce ("New critical finding on aws/iam/user/alice") via `aria-live="polite"` regions.
- **High-contrast theme**: third palette (next to dark + light) for low-vision users; auto-selected when `prefers-contrast: more`.
- **Reduced motion**: `prefers-reduced-motion: reduce` honored — sparkline animations, toast slide-ins, page transitions all flip to instant.
- **Colour-blind safe glyph parity**: v1.1's status glyphs (`✓ ✗ ⚠ –`) extended into the UI so colour is never load-bearing.
- **i18n framework**: gettext-style JSON catalogs per locale. `internal/i18n/` package. Strings extracted via `xgettext`-equivalent Go tooling.
- **First translations**: Spanish (ES), French (FR), German (DE), Japanese (JA), Brazilian Portuguese (PT-BR). User chooses locale in profile; HTTP `Accept-Language` is the fallback.
- **Inline help / docs panel**: `?`-key opens a contextual side panel. Each page registers its own help content. Links into the v0.x docs site without leaving the app.
- **Empty-state coaching**: every empty list has a next-action hint ("No scans yet — try `compliancekit scan` or use the Scan Now button").

**Out of scope at v1.10**

- RTL languages (Arabic, Hebrew) — needs CSS logical-properties pass that's its own milestone.
- Voice control. Punted.

**Dependencies added**

- `golang.org/x/text` for locale-aware formatting (numbers, dates, plurals).
- `github.com/nicksnyder/go-i18n/v2` for the message catalog runtime.

**No API surface change to `pkg/compliancekit`**. UI-only.

---

### v1.11 — Performance & scale

**Goal:** the daemon stops being "fine for a small team" and starts being "fine for an SI managing 50 customers' fleets." Cursor pagination, virtualised lists, caching, and a 100k-findings benchmark harness.

**Deliverables**

- **Cursor-based pagination**: replace OFFSET/LIMIT across every list endpoint (findings, scans, resources, audit log). Cursor is `(sort_key, id)`-encoded.
- **Virtualised scroll**: every long list uses windowing (visible rows + buffer). Smooth scroll for 100k+ findings.
- **Covering indexes**: audited per query path. Slow-query log + EXPLAIN plans documented in `internal/server/store/sql_perf.md`.
- **Materialised counts**: per-scan `resource_count`, `finding_count`, `severity_breakdown`. Computed on scan completion, not on every dashboard load.
- **HTTP compression**: brotli (preferred) + gzip + `Vary: Accept-Encoding`. Done at the middleware layer.
- **ETag everywhere**: every GET sets a weak ETag (already at v1.3 for findings; v1.11 extends to all collections). `If-None-Match` short-circuits to 304.
- **In-memory LRU**: hot filtered finding lists cached for 60s per `(filter, cursor)` key. Cache busted on `finding.created`/`finding.resolved` events via the v1.6 SSE bus.
- **Query budget**: per-request CPU + row-scan budget; over-budget responses log slow-query with the offending query.
- **Queue-depth metrics**: `compliancekit_worker_queue_depth` Prometheus gauge. Autoscaling worker pool when queue depth exceeds N for M minutes (configurable).
- **Streaming NDJSON export**: `GET /api/v1/findings.ndjson` streams the full set without buffering — enables warehouse loaders (v1.17) and large client-side analyses.
- **Benchmark harness**: `make bench-server` seeds 100k findings / 10k resources / 1k scans into a SQLite + Postgres backend; CI runs perf-regression checks against tagged baselines.

**Out of scope at v1.11**

- Horizontal scaling / multi-replica daemon. That's v1.15 with leader-election; sharding lives at v2.1 multi-tenant.
- Materialised views for cross-scan analytics. Snapshot API at v1.17.

**Dependencies added**

- `github.com/andybalholm/brotli` for HTTP compression.
- `github.com/hashicorp/golang-lru/v2` for the in-memory cache.

**No API surface change to `pkg/compliancekit`**. Cursor format documented but not promised across minor versions — opaque-by-design.

---

### v1.12 ✅ Admin & RBAC

**Goal:** the daemon is administrable in the way operators expect from a production tool. Roles, SAML, SCIM, audit search, backup/restore, tamper-evident logs.

**Deliverables**

- **Roles & RBAC**: built-in roles — `admin`, `editor`, `viewer`, `auditor`. Plus custom roles via a permission matrix UI.
- **Permission matrix**: per-resource grid (Scans / Findings / Settings / Users / API Tokens / Plugins / Audit Log) × (Read / Write / Delete / Admin). Custom roles compose these.
- **SAML 2.0 SSO**: in addition to v1.3 OIDC. IdP-initiated + SP-initiated flows. Tested against Okta, Azure AD, Google Workspace.
- **SCIM 2.0 user provisioning**: `/scim/v2/Users` + `/Groups` endpoints so admins manage users in their IdP, not in compliancekit.
- **Active sessions admin**: list every active session per user; revoke individually. Useful after a stolen laptop.
- **Audit log search**: full-text + structured filters (user, action, resource, time range). Export to NDJSON / CSV.
- **Settings export/import**: full daemon config (providers, frameworks, rules, notification sinks, custom roles) round-trips through YAML. Enables config-as-code in git.
- **Backup/restore UI**: scheduled SQLite dumps + `pg_dump` wrappers (run as daemon worker jobs). Restore from a backup ID with a one-click UI flow.
- **API token UI polish**: zero-downtime rotation (issue new, leave old active for N days, revoke). Scope picker. Last-used timestamp + last-used IP. Per-token rate limits.
- **Tamper-evident audit log**: each entry hashes the previous (`prev_hash` column). `compliancekit serve audit verify` validates the chain.
- **Settings UX excellence**: builds on the v1.4 settings page — settings search via Cmd+K (jumps to the right setting + scrolls + highlights), settings change diff/audit (every settings change recorded in the v1.12 hash-chained log with before/after), settings deep links (every setting has a stable anchor URL for runbook references), settings recommendations ("you haven't configured X yet" surfaced contextually), auto-save (no Save button — debounced commit + visible "saved" indicator).

**Out of scope at v1.12**

- WebAuthn / passkeys (modern auth). Worth a dedicated milestone or v1.12 sub-phase if user demand surfaces.
- Time-boxed read-only auditor exports — that's v2.4's auditor portal.

**Dependencies added**

- `github.com/crewjam/saml` for SAML 2.0.
- `github.com/elimity-com/scim` for SCIM 2.0 server-side.

**API surface additions**: `Role`, `Permission` types under `pkg/compliancekit/rbac` subpackage.

---

### v1.13 ✅ Plugin SDK + marketplace prep

**Goal:** the runway for v2.9's plugin marketplace. SDK + sandbox + signing + discovery — everything the marketplace needs to be a distribution layer, not a security risk.

**Deliverables**

- **Scaffolder**: `compliancekit checks new <id>` generates a starter check (Go + Rego variants) with manifest, tests, README.
- **Hot-reload Rego**: daemon watches `$XDG_DATA/compliancekit/plugins/*/rego/*.rego`; reload without restart. Bumps a plugin generation counter; in-flight scans use the version they started with.
- **Notification template editor**: in-UI editor with live preview against a test payload (Slack / Teams / Email / Webhook / Jira / Linear / PagerDuty templates).
- **Provider plugin discovery**: daemon enumerates `$XDG_DATA/compliancekit/plugins/`. Each plugin is a directory with `manifest.yaml` + `checks/` + optional `assets/`.
- **Plugin manifest schema**: name, version, kind (`check-pack` | `provider` | `notifier` | `reporter`), required-scopes, declared-egress-hosts, author, signature.
- **Cosign signature verification**: every plugin install requires a cosign-keyless signature; the daemon refuses unsigned plugins by default (`--allow-unsigned-plugins` is an explicit opt-out).
- **Plugin sandbox**: per-plugin egress allow-list. Plugin tries to dial a host outside its declared allow-list → connection refused + audit log entry.
- **CLI subcommands**: `compliancekit plugins install <ref>`, `list`, `update`, `remove`, `verify`. `<ref>` accepts a local path, a `ghcr.io/...` OCI ref, or a registry name when v2.9 lands.
- **Embedded catalog browser**: in-UI page lists installed plugins + a "browse community packs" tab (static list shipped with the binary in v1.13; backed by v2.9 registry later).

**Out of scope at v1.13**

- The registry itself (search, ratings, ownership). v2.9.
- WASM plugin runtime — Go subprocess gRPC is the v1.13 ABI; WASM is a v2.9 escape hatch.

**Dependencies added**

- `github.com/sigstore/cosign/v2` for signature verification.
- `github.com/hashicorp/go-plugin` for the subprocess gRPC plugin protocol.

**API surface additions**: `Plugin`, `PluginManifest` types under `pkg/compliancekit/plugin` subpackage. Stable so v2.9 doesn't break the ABI.

---

### v1.14 ✅ Reporting renaissance

**Goal:** the v1.2 HTML report was the "share with the board" artifact. v1.14 makes it composable — drag widgets onto a dashboard, schedule it to a stakeholder's inbox, watermark it for the auditor.

**Deliverables**

- **Dashboard builder**: drag-and-drop canvas; widget palette (score gauge, severity donut, framework coverage bar, finding list, resource table, sparkline, heatmap, treemap, sankey, free-form markdown). Save layouts per user / team.
- **Custom dashboards**: ship 4 built-in templates — "Executive overview", "AWS landing zone", "K8s-only", "SOC 2 readiness". Cloneable.
- **Scheduled email reports**: cron-style schedule + recipient list. Emits Markdown body + PDF attachment of any dashboard.
- **Executive-summary auto-gen**: GPT-free templated summary — "Score: 78 (+3 vs last week). Top 5 findings: ... Key wins: ... New regressions: ...". Pure templating over numbers from the v0.6 trend store.
- **Chart expansion**: heatmap (resource × severity), treemap (findings by service), sankey (drift sources → resolutions), radar (per-framework coverage). All vanilla-SVG, no chart library. **Designed with hover-tooltip / click-drill / annotation / brushing hooks pre-wired so v1.18 visual polish can flesh them out without re-shaping the SVG output.**
- **Multi-scan compare**: 3-up side-by-side dashboard view. Pick any 3 historical scans.
- **Watermarked exports**: per-recipient watermark ("for auditor@firm.com — 2026-08-15") in PDF + HTML exports.
- **Audit-pack profile builder**: pick which artifacts (findings.csv, vulnerabilities.csv, poam.oscal.json, waivers.json, dashboards) compose the v0.4 evidence pack. Save profiles per audit.
- **Live-share link**: shareable URL to a filtered dashboard view. Expires; watermarked; revocable from a "shared links" admin page.
- **PDF polish**: TOC with page anchors, page numbers, header/footer per page, page-break-friendly layout.

**Out of scope at v1.14**

- LLM-generated summaries. Static templating only — keeps the no-phone-home invariant safe.
- Dashboards as code (HCL / YAML). Possible v1.14 sub-phase; lower priority than UI builder.

**Dependencies added**

- `github.com/chromedp/chromedp` for headless-Chrome PDF rendering (also deferred from v1.5).

**No API surface change to `pkg/compliancekit`** (reporter contract unchanged). All new work in `internal/server/dashboards/` and `internal/report/`.

---

### v1.15 ✅ — Deploy & operate (shipped 2026-05-25; v1.15.1 patch shipped 2026-05-26)

**Goal:** the daemon goes from "build from source" to "kubectl apply -f". Helm, Kustomize, operator, Terraform — every deployment pattern operators expect.

**v1.15.1 patch (2026-05-26)** — eight-phase patch chain closing the audit findings against v1.15.0. The v1.15.0 deploy artifacts shipped with five image-pull-blocking bugs (Helm `appVersion` + Kustomize hardcoded tags + operator install.yaml all referenced `v1.15.0`, but goreleaser publishes as `1.15.0`; the operator binary was never added to `.goreleaser.yaml` so its image never existed; the DigitalOcean terraform module had an HCL string-concat-with-`+` syntax error that failed `terraform validate`) plus six UX gaps (the `--demo` seeder inserted scans without findings or resources; `render --format=ocsf` was rejected because the constant is `json-ocsf`; `checks list --provider=k8s` returned 0 because the tag is `kubernetes`; `plugins list` silently filtered unsigned packs without a hint; `/settings` returned 404; `scripts/install.sh` was a stale v0.5-era duplicate of `deploy/install.sh`). v1.15.1 fixes all eleven + bumps the image-size budget from an unreachable 30 MiB to a measured-ceiling 60 MiB + wires the budget script into the release workflow as a post-publish gate (it had been a hand-tool only). Patch tag is the same Helm chart version (`1.15.1`) so the chart and image stay in lockstep.

**Deliverables**

- **Helm chart**: published to `oci://ghcr.io/darpanzope/compliancekit-chart`. Defaults to single replica + SQLite; HA Postgres mode toggleable via values.
- **Kustomize overlay**: community-template-style. Base + overlays for dev / staging / prod.
- **K8s operator** (basic): `ComplianceSchedule` CRD reconciles cron schedules (replaces in-daemon cron when running in K8s — schedule-as-Kubernetes-resource); `ScanJob` CRD for ad-hoc one-shot scans (creates a Pod with the right config). Full reconciler with CRD-driven profiles + waivers is the v2.10 milestone.
- **Terraform modules**: `terraform-aws-compliancekit`, `-gcp-`, `-do-`, `-hetzner-`. Provisions a VM / managed service + Postgres + reverse proxy + DNS in each cloud.
- **Distroless multi-arch image**: `linux/amd64` + `linux/arm64`. `gcr.io/distroless/static-debian12:nonroot` base. ~45 MiB compressed published (measured at v1.15.0). The "~25 MB" target the original deliverable specified turned out to be aspirational — the daemon bundles Go + K8s SDKs + OPA + chromedp + crewjam/saml + Preline + i18n which all roll into a single ~45 MiB gzipped layer. CI gate at 60 MiB enforced via `deploy/scripts/image-size-budget.sh` (v1.15.1 phase 3 wired it into `.github/workflows/release.yaml`; before that it was a hand-tool only). v2.15 code-health pass may shrink toward the original aspiration by moving chromedp + OPA to v1.13 plugins.
- **HA Postgres docs**: replica setup, leader election via `pg_advisory_lock` (already used at v1.3 for migrations; extended to worker leader-election).
- **systemd unit + NixOS module**: ship-with templates for the two most-requested non-K8s deploy patterns.
- **Deep healthchecks**: `/health/ready` checks DB writable + migrations current + queue alive + leader-elected. `/health/live` is the cheap one.
- **Grafana dashboards**: JSON bundle in `grafana/dashboards/` — "Compliancekit Operations", "Findings Overview", "Worker Pool". Import into any Grafana.
- **One-line installer**: `curl -sSf https://raw.githubusercontent.com/darpanzope/compliancekit/main/deploy/install.sh | sh` parity with brew (chooses the right binary + drops a systemd unit / launchd plist). A vanity `compliancekit.dev/install.sh` shortcut may land later if the domain is acquired; the raw GitHub URL is the canonical install endpoint.

**Out of scope at v1.15**

- Full operator reconciliation of profiles + waivers from CRDs — v2.10.
- Helm chart for monitoring (Prometheus + Grafana). Deploy those separately; we ship the dashboards.

**Dependencies added**

- `sigs.k8s.io/controller-runtime` for the basic operator.
- `helm.sh/helm/v3` patterns for the chart (no library dep — chart is YAML).

**No API surface change to `pkg/compliancekit`**.

---

### v1.16 ✅ — Mobile / PWA (shipped 2026-05-27)

**Goal:** the UI works on a phone. Stand-ups, on-call check-ins, coffee-shop sanity glances all stop requiring a laptop.

**Deliverables**

- **PWA manifest** + service worker: installable on iOS / Android. App icon, splash screen, theme colour.
- **Service-worker caching strategy**: stale-while-revalidate for assets, network-first for `/api/v1/`, offline fallback page.
- **Install prompts**: handled native-style. iOS uses the share-sheet "Add to Home Screen"; Android uses `beforeinstallprompt`.
- **Mobile-first responsive sweep**: every page redesigned for <=400px width. Header collapses to hamburger, finding list collapses to card layout, filter chips stack vertically. Tested at iPhone-SE + standard tablet.
- **Push notifications via VAPID**: no third-party push provider (Firebase / OneSignal). VAPID keys generated by the daemon; users opt in per device. Push payload encrypted (per the Web Push spec).
- **Mobile-optimized "quick scan"**: a stripped-down flow — "Run AWS scan" → progress → top-5 findings — for the in-line scan-then-go pattern.
- **1-handed UX**: bottom-of-screen action bar (instead of top-of-screen); thumb-reachable.
- **Swipe gestures**: swipe-left to ack, swipe-right to waive (with confirm). Power-user accelerator.
- **Offline mode**: when daemon unreachable, the service worker shows the last-cached scan view (read-only) with an "offline — showing cached" banner.

**Out of scope at v1.16**

- Native iOS / Android apps. PWA only — the maintainer surface stays Go + static assets.
- Background sync (silent push). Future PWA milestone or v2.x.

**Dependencies added**

- No new server-side deps; Web Push is a server-side encrypted POST.
- `github.com/SherClockHolmes/webpush-go` for VAPID + Web Push encryption.

**No API surface change to `pkg/compliancekit`**.

---

### v1.17 ✅ — Data warehouse bridges (shipped 2026-05-27)

**Goal:** the daemon's findings + resources + history become first-class warehouse citizens. Parquet exports, BigQuery / Snowflake / Redshift loaders, OpenLineage events, point-in-time snapshots.

**Deliverables**

- **Parquet export**: `compliancekit warehouse export --format=parquet --out=path/`. Files per table — `findings.parquet`, `resources.parquet`, `scans.parquet`, `audit_log.parquet`. Schema versioned + documented.
- **BigQuery loader**: `compliancekit warehouse load --to=bigquery --project=... --dataset=...`. Streaming inserts or batched, configurable.
- **Snowflake loader**: similar shape; uses snowsql-style stage upload + COPY.
- **Redshift loader**: S3-stage + COPY pattern.
- **DuckDB-friendly NDJSON**: lossless NDJSON export designed to round-trip via `read_ndjson_auto`.
- **OpenLineage events**: every scan emits an OpenLineage `START` + `COMPLETE` event with input/output datasets. Marquez / DataHub compatible.
- **Snapshot API**: `POST /api/v1/snapshots` creates an immutable, named, point-in-time read-only view (cursor + content-hash). `GET /api/v1/snapshots/{name}/findings` queries the snapshot. Snapshots compose with the v1.17 warehouse loaders ("export the 2026-Q1 snapshot to BigQuery").
- **Webhook fan-out polish**: a single inbound webhook can route to N outbound notification sinks via the v1.9 rules engine — formalised in v1.17.
- **Scheduled warehouse sync**: daemon worker runs nightly warehouse loads; status visible in the v1.6 activity timeline.

**Out of scope at v1.17**

- ETL transformations beyond schema-shape (we ship the raw shape; transformations are dbt's job).
- Custom warehouse targets beyond BigQuery / Snowflake / Redshift / DuckDB. Operators with another warehouse use Parquet + their own loader.

**Dependencies added**

- `github.com/apache/arrow/go/v17/parquet` for Parquet writes.
- `cloud.google.com/go/bigquery` for the BigQuery loader.
- `github.com/snowflakedb/gosnowflake` for the Snowflake loader.
- `github.com/aws/aws-sdk-go-v2/service/redshiftdata` for the Redshift loader.

**No API surface change to `pkg/compliancekit`**. New CLI subcommand + new `/api/v1/snapshots` route.

---

### v1.18 — Design system & visual polish

**Goal:** the layer that separates a functional admin UI from a Linear / Vercel / Wiz-tier product. Every pixel feels intentional; every interaction has motion; every empty state has an illustration; every magnificent moment gets a celebration. ADR-017 codifies the design-system contract so v2.x can build on it without re-deriving the tokens.

**Deliverables**

- **Design tokens**: single source of truth for color, spacing, radii, shadows, typography, motion durations + easings. Lives in `internal/server/ui/design/tokens.css`. Three palettes (dark / light / high-contrast) all reference the same token names. **Per-domain palettes**: `--severity-{critical,high,medium,low,info}` + `--severity-*-bg`; `--status-{open,acknowledged,resolved,running,completed,failed,pending,false-positive}`; `--resource-{droplet,database,kubernetes,spaces,load-balancer,firewall,vpc,domain,ec2,s3,iam,rds,gcs,compute,...}` extended for every provider compliancekit ships (DO / AWS / GCP / Hetzner / K8s / Linux); `--sidebar-*` palette family.
- **Gradient utility tokens**: `--gradient-primary`, `--gradient-critical`, `--gradient-high`, `--gradient-medium`, `--gradient-low`, `--gradient-success` (linear-gradient 135deg). Drives the hero MetricCard variants. The thing that makes a dashboard look modern vs. flat.
- **Component library**: 20–25 carefully crafted htmx + Alpine partials under `internal/server/ui/design/components/*.html`, modeled on the shadcn/ui *API shape* (variant + slot + tooltip + clean prop set) but vendored as server-rendered partials. Target breadth covers what compliancekit will actually use; we don't ship shadcn's full 50+ (carousel / OTP / drawer / hover-card etc. wait for demand).
- **MetricCard component spec**: hero metric primitive — `title`, `value`, `subtitle`, `icon`, `variant` (`default` / `critical` / `high` / `medium` / `low` / `success` / `primary` / `warning`), `tooltip`, optional `trend` (up/down + value, color-coded). Icon in rounded-bg corner; gradient variants apply to the whole card; subtle decorative circle in the top-right of colored variants. Named v1.18 deliverable.
- **InfoTooltip-on-every-card-title pattern**: every Card title surface gets a small `?` icon with a hover-tooltip explaining "what this is and why it matters." Replaces docs-elsewhere with in-context discovery — the highest-leverage polish pattern in the magnificent-dashboard layer. Applied to every dashboard surface as a v1.18 audit task.
- **Named shadow scale**: `--shadow-soft` (`0 4px 16px -4px rgba(0,0,0,0.08)`), `--shadow-elevated` (`0 10px 30px -10px rgba(99,102,241,0.2)`), `--shadow-floating` (deeper), `--shadow-glass` (with backdrop-blur companion). Token-driven, theme-aware.
- **Design system docs page**: `/design` route renders the live component zoo — every button variant, every card depth, every status pill, every empty-state illustration, every MetricCard variant, the full per-domain palette swatches. Internal contributor onboarding artifact + visual regression target.
- **Loading skeletons everywhere**: every list, card, chart, table renders a skeleton during fetch. Spinners only acceptable for sub-200ms operations.
- **Page-top progress bar**: nprogress-style, driven by HTMX request-lifecycle events. Subtle, themed, dismissible.
- **Motion design tokens**: 6 vendored Framer-style easing curves as CSS variables (`--ease-in-out-cubic`, `--ease-out-quart`, `--ease-spring`, etc.). Four standard durations: 75ms (quick), 150ms (snap), 250ms (confident), 400ms (storytell).
- **Toast queue**: slide-in from corner, auto-stack, fade-out. Click-to-dismiss, swipe-to-dismiss on touch. Severity-coded.
- **Optimistic UI**: every form mutation (assign, waive, comment, ack, settings save) updates locally on submit, reconciles on server response, rolls back on error.
- **Empty-state SVG illustrations**: ~30 hand-drawn-style vanilla-SVG illustrations across "no findings", "all clear", "configure a provider", "no scans yet", "search no matches", "permission denied", etc. Theme-aware across dark / light / high-contrast.
- **Micro-interactions audit**: every hover / focus / active / press state on every interactive element. Subtle scale (0.98 on press), color shift, focus rings tuned with the design tokens.
- **Avatar generation**: hash-from-name initials gradient avatars (Linear-style). Per-user, per-team, per-bot. No third-party avatar service.
- **Status pill system**: severity / state / framework pills with consistent shape (pill + small icon + label), built from design tokens.
- **Card depth system**: `flat` / `raised` / `floating` / `glass` variants from shadow tokens.
- **Iconography expansion**: sprite grows from 22 (v1.2) to ~100 symbols (severities, statuses, providers, file types, actions, framework logos, sources, action chips).
- **Chart interactivity**: hover tooltips with rich content (multi-value, formatted), click-to-drill into filtered views, waiver-marker + baseline-shift annotations, time-series brushing.
- **Magic moments**: confetti animation on a scan that closes with zero critical findings; score-improved celebration card; weekly improvement streak badges (3 weeks = bronze, 6 = silver, 12 = gold).
- **Brand kit per org**: even single-tenant operators get a `Brand kit` page — upload logo, set favicon, override primary color (with contrast-against-tokens validation), set page-footer copy.

**Out of scope at v1.18**

- 3D / WebGL effects. Stays out forever — performance + a11y cost too high.
- Custom font face. System fonts only; no CDN, no FOUC.
- Cursor-following live presence. That's a v2.x collaboration concern.

**Dependencies added**

- `github.com/tabler/tabler-icons` SVGs vendored for the sprite expansion. MIT-licensed, ~5000 source icons; we cherry-pick ~100.
- No JS animation library — every motion uses CSS transitions / Web Animations API.

**API surface**: `pkg/compliancekit` unchanged. ADR-017 codifies the design-system contract so the tokens + component shape are a documented internal API.

---

### v1.19 — Onboarding 2.0 + global search + table excellence

**Goal:** every operator's first 10 minutes feel guided; every operator's daily search is instant; every table feels modern. The "I just opened this for the first time and immediately knew what to do" experience.

**Deliverables**

- **Feature tour overlays**: Linear-style "Press . to try the new ..." overlay system. Per-feature, dismissible, re-launchable from `/onboarding`. Vanilla — no Shepherd.js, no Intro.js.
- **Changelog modal**: on first login after a daemon upgrade, a modal surfaces the changelog highlights with deep links into the touched UI areas. Closes the gap where new features ship but nobody discovers them.
- **In-app feedback widget**: corner button (companion to the `?`-key help) opens a modal — bug / feature / love note. Posts to a daemon admin queue + optionally relays to a configured webhook (GitHub Issues / Linear).
- **First-run product tour**: 5-step interactive walkthrough triggered after the v1.4 first-run wizard. The wizard is *task*; the tour is *orientation* — they complement.
- **Empty-state coaching v2**: every empty state gets the v1.18 illustration plus a 3-step CTA (e.g. "1. Add a provider → 2. Run a scan → 3. View findings"). Each step deep-links into the right page.
- **Screenshot-grade demo seed**: layered on top of the v1.4 `compliancekit serve --demo` flag — ~500 findings across all severities, ~150 resources spread across providers, multi-week historical trend so charts look real.
- **Global search**: invokable via `/` or `Cmd+K` from anywhere. Single index across findings + resources + scans + users + waivers + settings + docs.
- **Fuzzy ranking**: Sublime-style — sub-string fuzzy plus recency weighting. Persisted recent searches + suggested searches from operator history.
- **Sticky search bar**: floating bar in the nav. Result panel shows grouped results with keyboard navigation (j/k + Enter).
- **Discovery surfaces**: home page "Did you know..." cards (auto-rotate, dismissable, never repeat). Surface features the operator hasn't used yet.
- **Table 2.0**: drag-to-resize columns, drag-to-reorder columns, pin-left / pin-right, column-visibility menu, saved column sets (per-table, per-user).
- **Inline edit**: where applicable (notes, tags, assignee). Click → edit in place → blur to save (optimistic from v1.18).
- **Bulk actions in page header**: when selections > 0, action buttons (Acknowledge `(N)`, Resolve `(N)`, Waive `(N)`, Assign `(N)`, Export `(N)`) appear in the page header next to the existing actions, not as a floating toolbar. Cleaner; matches the rest of the chrome.
- **Detail panel polish**: resizable side panel (drag border), detachable to new tab, j/k or arrow keys to navigate through items without closing.
- **Keyboard shortcut discoverability**: `?`-key overlay (already at v1.10) gets per-page contextual shortcuts. v1.19 adds small "kbd hint" badges next to every clickable action so shortcuts surface in-context, not just in the overlay.
- **Filter card convention**: a single `Filters` Card sits above every long list (findings, resources, scans, audit log). Inside: search input with leading magnifier glyph + N Select dropdowns + optional date-range, laid out as a responsive grid. One pattern, used everywhere — no bespoke filter chrome per page.
- **Page header convention**: every page is `<h1>Title</h1>` + muted subtitle paragraph + right-aligned action buttons (primary action solid + secondary actions outlined). Codified in the v1.18 component library + audited across every page at v1.19.

**Out of scope at v1.19**

- AI-driven recommendations. Honors the no-phone-home invariant.
- Voice search. Punted.
- Live-presence cursors. v2.x collaboration concern.

**Dependencies added**

- `github.com/lithammer/fuzzysearch` for fuzzy ranking on the server side.
- No new frontend deps — search index served from the daemon; client just renders.

**API surface**: new `GET /api/v1/search?q=...&types=findings,resources,scans,...` endpoint with cursor pagination. Documented but not promised across minors. `pkg/compliancekit` unchanged.

---

## v2.x — depth, breadth, and the long tail (v2.0 – v2.20)

Post-v1.x, the roadmap shifts from polish to expansion. The pre-existing 12 rows (v2.0–v2.11) cover platform expansion (multi-tenant, GRC, auditor portal, tail clouds, OS expansion, OSCAL, risk score, plugin marketplace, K8s operator, auto-remediation). The v2.12–v2.20 expansion adds a dedicated bar-raising arc: UI/UX 3.0, Documentation 2.0, zero-trust deploy, code health, test maturity, developer experience, GitOps, full i18n, and enterprise polish. Tail clouds (v2.6) gets deep-pack treatment with 26 phases.

See [ADR-019](DECISIONS.md#adr-019--v2x-expansion--bar-raising-arc-v212v220--tail-cloud-deep-pack-v26) for the scoping rationale.

The v2.6 (tail clouds deep) and v2.12–v2.20 sections below are pinned in detail because the user explicitly asked for depth at scoping time. Other v2.x rows (v2.0–v2.5, v2.7–v2.11) stay in table form per the "post-launch feedback is the right input" convention noted at the top of this document — they'll get detail sections as their kick-off approaches.

---

### v2.6 — Tail clouds (deep coverage of every SaaS surface)

**Goal:** every SaaS your SaaS actually touches — not just the cloud providers — gets first-class, audit-grade compliance coverage. 26 phases, ~800 net-new checks, one shared collector foundation. The thesis: most compliance violations live in the long tail of SaaS apps (oversharing in Drive, scope-creeping OAuth in HubSpot, stale Slack apps, GitHub branch-protection drift), not in the IaaS layer the security team already monitors.

**Phases**

- **Phase 0 — Foundation**: `internal/collectors/saascommon` shared primitives — OAuth client (PKCE + refresh-token rotation), rate-limit-aware HTTP client (per-host buckets + retry with exponential backoff + jitter), token-rotation hooks (so daemon-mode handles expiry without restart), per-vendor health probe ("am I authenticated, and what's my quota left?"), secret-redaction parity with [ADR-010](DECISIONS.md#adr-010--secrets-in-ingest-are-redacted-not-stored), per-vendor `cloudcommon.Stamp` equivalent for resource provenance metadata. No new checks — just the runway.
- **Phase 1 — Cloudflare deep**: 8 sub-services + ~80 checks. Zones + DNS (DNSSEC enforced, SPF/DKIM/DMARC alignment, no dangling CNAMEs to deactivated services), R2 (public-bucket detection + signed-URL TTL + lifecycle policy), Workers (secrets in env vars detection + tail logs + outbound destination allowlist + binding hygiene), Tunnels (cloudflared version drift + ingress policy), Access / Zero Trust (policy posture + identity provider config + service-token rotation), WAF + Bot Management (rule set enabled + custom-rules audit + bot challenge threshold), Pages (build-config + env-var sensitivity + preview-deploy gating), D1+KV+Queues (encryption-at-rest defaults + per-namespace ACL), Stream + Images (signed-URL TTL + token-restricted playback), Email Routing (catch-all detection + forwarding-address audit), Magic Transit (BGP session security + ACL policy).
- **Phase 2 — GitHub deep**: 12 surfaces + ~100 checks. Org settings (2FA required, base perms, dependency insights enabled, security advisories on), repo settings (default-branch + visibility audit + force-push gate + delete-branch policy), branch protection (required reviewers count, required status checks, signed commits, linear history, conversation resolution), secrets (org + repo + env + dependabot secret inventory; rotation cadence; never logged), code scanning (CodeQL or third-party SAST enabled per default-branch repo), GitHub Advanced Security (push protection for secret scanning, dependency review on PRs), actions runners (self-hosted runner posture, group isolation, never-on-public-repos rule), workflow security (`permissions:` at workflow root, third-party-action SHA-pinning audit, OIDC trust policy least-privilege, reusable-workflow allowlist), audit log retention (streaming endpoint configured + integrity verification), packages + releases (signed releases via cosign or sigstore, package visibility), environments (required reviewers, wait timers, deployment branches policy), OIDC trust policies (sub-claim specificity audit, audience pinned), copilot org policy (data-retention opt-out + suggestion matching gates).
- **Phase 3 — Google Workspace deep**: 8 surfaces + ~60 checks. Admin SDK posture (super-admin count, recovery info per admin, MFA enforcement), Drive sharing (external sharing per-OU policy, link-sharing audit, file lifecycle policy, DLP rules), Gmail security (S/MIME + IRM + content compliance + spam policy + attachment scanning), Vault retention (default + legal-hold posture per OU), Endpoint Management (managed-device enrollment % + screen-lock + encryption posture), OAuth apps inventory (third-party-app trust + scopes audit + impersonation grants), Alert Center (rules enabled + delivery destination + acknowledgement SLO), Context-Aware Access (rules enabled + risk-signal coverage + per-app conditional rules).
- **Phase 4 — Microsoft 365 + Entra ID deep**: 7 surfaces + ~80 checks. Defender for Office (anti-phishing policy, Safe Links, Safe Attachments, ATP policy), Defender for Endpoint (device-onboarding %, EDR posture, AV exclusions audit), Purview (DLP policies, sensitivity-label adoption, records management, eDiscovery hold posture), Sentinel (data connectors enabled, scheduled rules count, automation playbooks wired), Intune (compliance policies per platform, conditional-access integration, app-protection policies), conditional access (block-legacy-auth, MFA-required, device-compliance-required, location-based rules, sign-in risk gating), audit log retention + app consent (admin consent workflow + per-app permission audit + risky-OAuth detection).
- **Phase 5 — Vercel deep**: 9 surfaces + ~30 checks. Project settings (production-branch lock, deployment protection), env vars (sensitive flag set on secrets, scope split prod/preview/dev, unused-var detection), deployments hygiene (preview deploys gated on auth, no auto-deploy from forks), log drains (configured + retention SLA), OIDC token issuance (audience pinned, sub-claim specific), team SSO + SAML (enforced, no email/password fallback), build env isolation (no leaked secrets in build logs, build-cache scope), edge config (read-only at runtime, write keys rotated), env-protection rules (required reviewers for prod env edits).
- **Phase 6 — Linode / Akamai Cloud deep**: 8 surfaces + ~40 checks. Compute (region + plan posture, backup enabled, watchdog on, image age), NodeBalancers (TLS-only, modern cipher suite, sticky-session SameSite, health-check policy), Object Storage (public-bucket detection, lifecycle, CORS policy), Cloud Firewalls (default-deny ingress, rule audit), VLANs (segmentation posture), LKE (control-plane version, audit log, network policy, RBAC posture), DNS (DNSSEC + SPF/DKIM/DMARC), longview agents (installed + reporting on production hosts).
- **Phase 7 — Vultr deep**: 8 surfaces + ~30 checks. Instances (region + plan, backup, auto-snapshot, OS age), block storage (encryption at rest, attached-VM-only access), VKE (version, network policy, audit log), firewall groups (default-deny, rule audit, unused-group cleanup), object storage (public-bucket, lifecycle, signed-URL TTL), DNS (DNSSEC + SPF/DKIM/DMARC), reserved IPs (geo + ownership audit), snapshot retention (TTL + encryption).
- **Phase 8 — Fastly deep**: 7 surfaces + ~25 checks. Services (TLS 1.3 + HSTS + modern cipher suite), ACLs (size + rotation + per-service scope), dictionaries (PII never stored, retention), TLS subscriptions (auto-renew, key-rotation cadence), log streaming endpoints (configured + integrity verification + retention), image optimizer (signed-token-restricted), compute@edge (binding hygiene + outbound allowlist + secret handling).
- **Phase 9 — Slack workspace deep**: 6 surfaces + ~25 checks. SCIM provisioning (enforced, deprovisioning latency SLO), app inventory + OAuth scopes (over-broad scope detection, unused apps), DLP (content rules + DM scanning posture), channel retention (per-channel TTL audit, default retention), IdP enforcement (SSO required, no email/password fallback), audit log streaming (Enterprise Grid endpoint configured + retention).
- **Phase 10 — Atlassian Cloud deep**: 7 surfaces + ~30 checks. Jira + Confluence org settings (sandbox vs prod posture), app inventory (Marketplace app scope audit + unused-app cleanup), SSO + SCIM (enforced, deprovisioning latency), audit log (retention + streaming), OAuth grants (org-level + user-level grant audit), anonymous-access posture (Confluence space anon-read detection), API token hygiene (admin API token inventory + rotation).
- **Phase 11 — Okta deep**: 6 surfaces + ~25 checks. Sign-on policies (per-app MFA + risk-based + IP-zone), factor enrollment policy (modern factors required, SMS deprecated), app catalog hygiene (unused-app cleanup, scope audit, SCIM where supported), log streaming (configured to SIEM + retention), behavior detection (rules enabled + risk-based MFA wiring), system log retention (per-tenant SLA + integrity verification).
- **Phase 12 — Zoom deep**: 6 surfaces + ~15 checks. Security policies (E2E meeting option per default, waiting-room default, passcode required), recording retention (TTL per OU, default-storage-location), SSO config (enforced + IdP allowlist), App Marketplace approvals (admin-approval flow + scope audit), meeting defaults (chat retention, attendee limits, screen-share host-only default), webinar perms (registration required, panelist promotion gating).
- **Phase 13 — Stripe deep**: 6 surfaces + ~20 checks. Restricted API keys (least-privilege + per-integration key + rotation cadence), webhook signing (secret rotation + replay-window enforcement), IP allowlist on dashboard (configured per env), Radar fraud rules (default rules enabled + custom-rules audit + 3DS thresholds), team perms + audit (role-least-privilege + 2FA enforced + audit log retention), Sigma data retention (PII-scrubbing posture, query log retention).
- **Phase 14 — HubSpot + Salesforce deep**: 7 surfaces + ~25 checks. Data perms + sharing (record-level sharing audit, profile + permission set hygiene), OAuth connected apps (scope audit + IP allowlist per app + admin-approval-required), integration hygiene (unused integration cleanup + API call quota), IP restrictions (per-user + per-profile + per-connected-app), password policy + MFA (enforcement per profile), audit trail retention (Salesforce field audit trail enabled on sensitive fields + retention SLA), event monitoring (Salesforce Shield posture if licensed).
- **Phase 15 — Notion deep**: 5 surfaces + ~15 checks. Workspace admin (enterprise plan posture, recovery info), integrations inventory + scopes (third-party-integration audit, internal-integration scope hygiene), sharing perms (public-page detection, link-with-edit audit, guest-user inventory), page-share-with-link audits (TTL + watermark per page), SCIM provisioning (enforced + deprovisioning latency).
- **Phase 16 — 1Password + Bitwarden deep**: 6 surfaces + ~20 checks. Vault sharing audit (per-vault membership + collection scope), SCIM (enforced + deprovisioning latency), recovery policy (org-wide recovery posture, recovery code rotation), Watchtower / breach posture (alerts enabled + remediation SLO), login policies (factor enforcement + master-password rotation cadence + session timeout), event log retention (export to SIEM + integrity verification).
- **Phase 17 — Tailscale deep**: 7 surfaces + ~20 checks. ACL posture (default-deny, tag-based policy hygiene, no wildcard sources), MagicDNS hygiene (split-DNS + per-tag DNS isolation), key expiry policy (per-user + per-tag-server ephemeral key enforcement), device posture rules (OS + browser + EDR posture as access prereq), SSO (enforced, no email/auth fallback), tagged-server lifecycle (auto-removal of stale-tagged servers), audit log streaming (configured + retention).
- **Phase 18 — Observability vendor posture (Datadog / New Relic / PagerDuty) deep**: 7 surfaces + ~25 checks per vendor (so ~75 total). API key hygiene + scopes (least-privilege, per-integration key, rotation cadence), integration inventory (unused-integration cleanup), log retention (per-data-type SLA + integrity), sensitive-string scrubbing rules (PII patterns enabled + custom regex audit), SSO + SCIM (enforced + deprovisioning), audit log retention (event-log streaming + retention), on-call rotation hygiene (PagerDuty-only — no single-point-of-failure schedules, escalation policy depth ≥2).
- **Phase 19 — Transactional email vendor (Postmark / SendGrid / Mailgun) deep**: 6 surfaces + ~20 checks per vendor (so ~60 total). DMARC + SPF + DKIM alignment per sending domain (relaxed vs strict posture, sub-domain delegation), webhook signing (secret rotation, replay-window), suppression list hygiene (export + retention + cross-vendor sync if multiple), log retention (per-message log SLA, integrity verification), IP reputation surfacing (per-dedicated-IP reputation polling, warmup status), API key scopes (least-privilege per integration).
- **Phase 20 — Modern PaaS (Render / Fly.io / Railway) deep**: 6 surfaces + ~30 checks per vendor (so ~90 total). Env vars + secrets (sensitive-flag, scope split prod/preview, never-in-build-log audit), IP allowlist (per-service + per-DB), build cache poisoning posture (cache scope + invalidation policy), audit log (admin event log + retention + streaming), custom-domain TLS posture (auto-renew, modern cipher suite, HSTS), log drains (configured + per-tenant scope + retention SLA).
- **Phase 21 — Discord deep**: 6 surfaces + ~15 checks. Bot perms (per-bot scope audit, admin-bot detection), audit log (retention + integrity, per-mod-action streaming), member screening (verification level + screening-questions enabled), AutoMod posture (block-spam + harmful-content + custom-rules audit), channel perms hygiene (no @everyone-write on announcements, no @everyone-mention on sensitive channels), webhook inventory (per-channel webhook audit + scope).
- **Phase 22 — iPaaS (Zapier / n8n / Make) deep**: 5 surfaces + ~15 checks per vendor (so ~45 total). Connection inventory + OAuth scope sprawl (per-connection scope audit, unused-connection cleanup, scope drift detection), retention (zap/scenario history retention, log retention), IP allowlist (per-account allowlist, webhook source verification), secret-handling per step (secret-flag set, no hard-coded credentials in step config), SSO + audit log (enforced + retention).
- **Phase 23 — Legacy platform (Heroku) deep**: 5 surfaces + ~15 checks. App config (config-var sensitive-flag, retention, never-in-release-log audit), add-on security (per-add-on plan posture + credential rotation), dyno hardening (stack version pin + runtime version pin + buildpack pin), Pipelines + Review Apps posture (production-branch protection, review-app gating, env-var inheritance hygiene), audit log (Enterprise feature posture + retention).
- **Phase 24 — Framework wiring**: Map every tail-cloud check to controls in: (a) **CIS SaaS Benchmarks** for the big-3 (Google Workspace v1.x + Microsoft 365 v3.x + GitHub v1.x) — formal CIS catalogs ingested as `frameworks/cis-saas-*.yaml` per the v0.12 framework schema; (b) custom **"SaaS-Hardening v1"** framework — net-new compliancekit framework spanning the entire tail with 10 control families (Identity / Access / Audit / Data / Network / Secrets / Supply Chain / Backup / Vendor Posture / Configuration Drift); (c) **ATT&CK-for-SaaS** coverage — every tail-cloud check tagged with applicable MITRE techniques (T1078.004 cloud accounts, T1098.001 additional cloud credentials, T1556 modify auth process, etc.).
- **Phase 25 — Tail-cloud aggregator dashboard**: net-new `/tail-clouds` UI route — vendor-grid heatmap (rows = vendors, cols = control families, intensity = failing-check density); per-vendor drilldown; cross-vendor "find me every place where OAuth scope X is granted" + "find me every place where person@example.com has admin"; integrates with v1.18 chart library (heatmap + sankey vendor → identity → permission).
- **Phase 26 — Cross-vendor identity map**: new `internal/identity` package — links OAuth app inventory across vendors (e.g. the same Notion integration that touches Slack, the same Datadog API key that's wired into GitHub Actions + Vercel) + cross-vendor person map (the same `darpan@example.com` is an Okta admin + GitHub org owner + Stripe admin + AWS root). Surfaces in `/identity-map` route. SaaS-sprawl-audit as a first-class artifact.

**Out of scope at v2.6**

- Vendor-side **remediation generators** beyond GitHub (branch-protection PR), Cloudflare (zone-config Terraform), and AWS-already-covered. Most tail vendors don't have stable IaC, so remediation stays "open a Jira ticket pointed at the runbook" via [v0.17 notifiers](#v017----notifications-shipped-2026-05-17).
- **OAuth-flow self-service** for these vendors. Operators wire vendor API tokens via the existing v1.4 settings UI; per-vendor OAuth dance lives at v2.6.x.
- **OS expansion beyond v2.5** (macOS / Windows / BSD hardening). Tail clouds is SaaS-only.

**Dependencies added (~22 new direct deps)**

Vendor SDKs vary in quality. Where the official Go SDK is well-maintained, we use it; otherwise we hand-roll a thin client on top of `saascommon`:

- `github.com/cloudflare/cloudflare-go/v4` (Cloudflare)
- `github.com/google/go-github/v68` (GitHub) — already vendored; deepened
- `google.golang.org/api/admin/directory/v1` + `drive/v3` + `gmail/v1` + `vault/v1` (Google Workspace)
- `github.com/microsoftgraph/msgraph-sdk-go` (Microsoft 365 + Entra ID)
- `github.com/vercel/vercel-go` (Vercel)
- `github.com/linode/linodego` (Linode)
- `github.com/vultr/govultr/v3` (Vultr)
- `github.com/fastly/go-fastly/v9` (Fastly)
- `github.com/slack-go/slack` (Slack)
- `github.com/ctreminiom/go-atlassian` (Atlassian Cloud)
- `github.com/okta/okta-sdk-golang/v3` (Okta)
- `github.com/himalayan-institute/zoom-lib-golang` (Zoom)
- `github.com/stripe/stripe-go/v77` (Stripe)
- `github.com/clarkmcc/go-hubspot` + `github.com/simpleforce/simpleforce` (HubSpot + Salesforce)
- `github.com/jomei/notionapi` (Notion)
- `github.com/1Password/connect-sdk-go` + `github.com/bitwarden/sdk-go` (1Password / Bitwarden)
- `github.com/tailscale/tailscale-client-go` (Tailscale)
- `github.com/DataDog/datadog-api-client-go/v2` + `github.com/newrelic/newrelic-client-go/v2` + `github.com/PagerDuty/go-pagerduty` (observability)
- Postmark / SendGrid / Mailgun official Go clients (transactional email)
- Render / Fly.io / Railway REST clients (hand-rolled on `saascommon`)
- `github.com/bwmarrin/discordgo` (Discord)
- Zapier / n8n / Make REST clients (hand-rolled on `saascommon`)
- `github.com/heroku/heroku-go/v5` (Heroku)

Net binary-size impact: ~25 MB → ~40 MB. Documented in the v2.15 code-health pass as the threshold to revisit (some vendor packs may move to v1.13 plugins to keep the core binary lean).

**API surface additions to `pkg/compliancekit`**: `Vendor` enum (one per phase 1–23), `IdentityRef` (cross-vendor person/app pointer for phase 26), `OAuthGrant` shape (for phase 26 inventory). Stable, additive — no v2 break required.

---

### v2.12 — UI/UX 3.0 — Studio-grade interactions

**Goal:** post-v1.18 design system + v1.19 onboarding, this is the milestone that takes us from "Linear-tier" to "every-interaction-feels-handcrafted." Every page accepts a command palette. Every list filters live. Every drag-target accepts drops. Every dashboard mutation animates. Real-time collab cursors make the daemon feel like a multiplayer product.

**Deliverables**

- **Command palette everywhere**: extend the v1.5/v1.19 Cmd-K from a global search to a per-page command surface (page-scoped commands like "filter by severity=critical" / "assign all selected to me" / "open in TUI" / "export view as PDF"). Backed by a `commands.Registry` per-page so plugins can register commands too.
- **Drag-drop everywhere**: dashboards (widget reorder + resize), saved views (column reorder), finding triage Kanban (drag finding between New/In-progress/Waived columns), waiver bulk-move, table column reorder + pin-left/pin-right (lifts the v1.19 table 2.0 affordances into every list).
- **Real-time collab cursors + presence**: WebSocket upgrade for ephemeral mouse-position broadcasting (separate channel from the SSE event bus so cursor traffic doesn't pollute durable events); per-finding presence chips ("3 people viewing"); per-text-field selection broadcasting (Linear / Notion style).
- **Chart library refresh**: interactive Sankey (drag to re-aggregate), sunburst (click to drill), risk heatmap (brush to filter), bullet chart for KPI vs target, waffle chart for compliance posture per framework. Cross-filter brushing: select on one chart, every other chart on the page filters.
- **Motion language v2**: Framer-grade choreography library (`internal/server/ui/src/motion.js`) with staggered list reveals, FLIP for layout transitions (smooth row-add/remove instead of jarring re-render), shared-element transitions across pages (clicking a finding card morphs into the detail panel).
- **Illustration catalog**: 60+ vanilla-SVG empty-state illustrations tuned per theme (light / dark / high-contrast); per-page coaching art; "no findings yet — here's how to add a provider" illustrated walkthrough.
- **Theme builder + brandable white-label**: per-org logo + favicon + 3-color picker (primary / accent / surface) + dark-mode override + custom font (Google Fonts allowlist + self-hosted toggle); WCAG AA contrast validator gates submit.
- **In-app changelog + spotlight tours**: auto-triggered after every minor-version upgrade; deep-link to touched UI areas; "What's new" carousel with replay.
- **Smart Empty States 2.0**: per-page coaching with "show me an example" 1-click that seeds the v1.4 demo data scoped to the empty page only.
- **Micro-animations audit**: button-press depth, focus-ring spring, optimistic state lift, toast queue slide+fade+stack, page-top nprogress (lifts/extends from v1.18 — every interaction polished to Linear-tier).

**Out of scope at v2.12**

- AI-driven UI suggestions ("you should probably look at this"). v2.x AI-native milestone, separate.
- Native iOS/Android app. PWA shipped at v1.16 is the maintainer surface.

**Dependencies added**

- No new server-side deps.
- Frontend: hand-rolled motion library (no Framer Motion dep — too heavy for a daemon UI); cytoscape.js *finally* lands for the v1.5.x graph escape hatch + sunburst drilldown.

**No API surface change**.

---

### v2.13 — Documentation 2.0

**Goal:** the docs site contributors fork from, not just read. Multi-version, searchable, dark mode, mobile-first; full handbook + per-framework playbooks + cookbook 2.0 + interactive API explorer.

**Deliverables**

- **`docs.compliancekit.io` static site**: Hugo (or Mkdocs + Material — decision in ADR-020 at kickoff) + a vendored theme matching the v1.18 design system; multi-version selector (v1.x current / v0.x archived); client-side search via pagefind or lunr (no SaaS dep); dark mode + mobile-first responsive.
- **Full handbook** (~50 pages of long-form):
  - Architecture deep-dives: collector → engine → reporter → ingest → remediate → notify pipeline; SSE event bus + worker pool + leader election; per-cloud SDK conventions; framework yaml shape + tailoring flow.
  - Threat model: STRIDE per component; data-flow diagram; supply-chain posture; tenant isolation (post-v2.1) story.
  - Ops runbooks: 20+ runbooks for the most common operator situations (DB full, leader stuck, webhook receiver lagging, OIDC IdP down, scan timeout, audit-chain broken, etc.).
  - On-call playbook + post-mortem template (Google SRE-style).
- **Per-framework playbooks**: "SOC 2 in 30 days with compliancekit" / "PCI v4 in 60 days" / "HIPAA in 45 days" / "ISO 27001 in 90 days" / "NIST 800-53 r5 from scratch" / "FedRAMP Low pre-flight" — each ~10 pages with screenshots, command sequences, expected timelines, common pitfalls.
- **20+ video walkthroughs**: asciinema casts for CLI flows (`scan` / `serve` / `remediate` / `policy validate` / `plugins install`); Loom recordings for UI flows (Studio onboarding / explorer / dashboard builder / audit pack); hosted on YouTube, linked from docs, transcripts committed for searchability.
- **Cookbook 2.0**: 50+ end-to-end recipes (from "monitor my homelab" to "ship a Trust Center to my biggest customer" to "wire CI/CD compliance gates" to "respond to a SOC 2 audit"). Each recipe is a single page with prerequisites + step-by-step + expected output + troubleshooting.
- **Interactive API explorer**: Swagger UI mounted at `docs.compliancekit.io/api/explorer` against the v1.x OpenAPI spec; "Try it" against the live `demo.compliancekit.io` daemon (the v1.4 demo mode in prod-hosted form); per-endpoint code samples in 6 languages (curl / go / python / typescript / ruby / php).
- **Embedded LLM doc-search** (opt-in): local Ollama-friendly + OpenAI-compatible; users bring their own model; no phone-home; documented integration.
- **Changelog-as-blog**: every minor gets a launch post on `docs.compliancekit.io/blog` with screenshots + diff + "what's new for operators" + "what's new for plugin authors" sections.
- **Contributor docs**: dedicated `/contribute` section — codebase tour, dev environment, RFC process, ADR conventions, release checklist, maintainer status criteria.

**Out of scope at v2.13**

- Docs translation. That's v2.19 i18n 2.0 territory.
- AI-generated docs. Operators write canonical text; LLM is search-only.

**Dependencies added**

- Hugo (or Mkdocs Material) build-time dep — not bundled in the binary.
- pagefind WASM at docs-site build time.

**No API surface change.**

---

### v2.14 — Zero-trust deploy

**Goal:** the most secure default deployment of any open-source compliance tool. Every connection mTLS-authenticated, every secret rotated, every workload identity-attested, every artifact verified.

**Deliverables**

- **mTLS everywhere**: daemon ↔ daemon (HA cluster), daemon ↔ Postgres (libpq sslmode=verify-full + client cert), daemon ↔ webhook receivers (mutual auth), daemon ↔ outbound (notify sinks); auto-renewing via cert-manager integration or a built-in CSR loop with configurable issuer (Vault PKI / step-ca / smallstep).
- **SPIFFE / SPIRE identity**: workload attestation; SVIDs for every daemon replica + every operator binary; `spiffe://compliancekit.example.com/daemon/<id>` identity URIs everywhere; SPIRE Agent helm chart + Kustomize overlay shipped.
- **Secrets via Vault / Infisical / SOPS / sealed-secrets / external-secrets-operator**: no plaintext env vars in HA mode; per-secret-backend driver in `internal/secrets/`; `sops` for git-stored encrypted YAML (operator workflow); ESO for K8s-native; Infisical for self-hosted; Vault for enterprise.
- **NetworkPolicy + Cilium L7 templates**: shipped in `deploy/networkpolicies/` — default-deny ingress, allowlist for Postgres + Prometheus + ingress; L7 templates restrict outbound to known notify-sink hosts.
- **seccomp + AppArmor profiles + landlock**: shipped in `deploy/seccomp/` and `deploy/apparmor/`; daemon runs with the minimum syscall surface needed; landlock LSM enabled on Linux ≥5.13 for filesystem isolation.
- **SLSA L4 build provenance**: GitHub Actions builds emit SLSA L4 attestations via slsa-framework/slsa-github-generator; attestations published to Sigstore; verifiable via `cosign verify-attestation`.
- **Hardware-attested boot docs**: docs and Helm-values templates for Secure Boot + TPM 2.0 + measured boot (IMA + EVM) on Linux hosts; tied to v2.5 OS hardening for the OS-side configuration.
- **BYOK customer-managed encryption keys**: envelope encryption for sensitive columns (PII, tokens, secrets-in-rest); per-tenant KMS reference; KMS adapters for AWS / GCP / Azure / HashiCorp Vault Transit (closes the loop with v2.20 enterprise polish).
- **IP allowlist + geo-fencing middleware**: per-route IP allowlist, per-org geo-fence, GeoIP database update job shipped.
- **OWASP ASVS L3 self-audit**: full audit committed quarterly; gap-tracker in `docs/security/asvs-l3-status.md`; ASVS L3 controls mapped to compliancekit's own checks where applicable (dogfooding).
- **Supply-chain hardening**: every Go dep verified via cosign + Sigstore (where available); Dependabot + Renovate config tightened (auto-merge security-only; major bumps require ADR); SBOM published per release with VEX statements for known-but-not-exploitable CVEs.

**Out of scope at v2.14**

- FIPS 140-3 mode. v2.20+ enterprise polish if demand surfaces (Go's BoringCrypto path is the lever).
- Confidential computing (SEV-SNP / TDX) workload attestation. v2.x+ if hardware penetration warrants.

**Dependencies added**

- `github.com/spiffe/go-spiffe/v2` for SPIFFE identity.
- `github.com/hashicorp/vault/api` for Vault secrets adapter.
- `github.com/getsops/sops/v3` for SOPS adapter.
- `github.com/external-secrets/external-secrets` types for ESO integration.
- KMS SDKs already vendored from v0.7/v0.8 (AWS KMS, GCP KMS).

**API surface additions**: `secrets.Backend` interface in a new `pkg/compliancekit/secrets` subpackage so plugins can register secret resolvers.

---

### v2.15 — Code health pass

**Goal:** a codebase that reads like it was reviewed line-by-line. Surface-area audit, dead-code elimination, dependency minimization, performance budgets, error-handling consistency, structured logging audit, doc-comment 100% coverage. No new features — pure quality work.

**Deliverables**

- **Surface-area audit**: every `internal/` package gets a 1-page README documenting its purpose + invariants + extension points; cross-package coupling reviewed (the goal: a contributor can change `internal/checks/aws/` without reading `internal/server/`); dependency graph snapshot in `docs/architecture/package-graph.svg`.
- **Dead-code elimination**: enable `deadcode` + `unused` analyzers (both Dominik Honnef's `staticcheck` and `unconvert` family) in CI as hard gates; ~20% removal expected (~30k LoC) based on current heuristic sweep; every unexported symbol that's unused gets removed.
- **Dependency minimization**: drop transitives where direct alt exists; consolidate logging libraries (only `log/slog`); consolidate CLI styling (only `internal/ui` + `charmbracelet/lipgloss`); audit `go mod why` on every direct dep; bin-size budget reduced from 25 MB → 20 MB target.
- **Performance budgets in CI**: `go test -bench` regression gate via [benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat) — fail PRs that regress p95 query / startup time / RSS / goroutines-at-rest beyond budget; per-package benchmark suite + per-handler request-budget; baseline committed to `bench/baseline.json`.
- **Allocation regression tests**: `-benchmem` on hot paths; per-allocation budget per request (e.g. `/api/v1/findings` ≤ 50 allocs/req).
- **Structured logging audit**: every package uses `log/slog` with stable attribute names; structured-log schema documented in `docs/architecture/log-schema.md`; CI gate (custom linter) rejects `fmt.Printf` / `log.Printf` outside `cmd/`.
- **Error-handling consistency pass**: every external boundary returns typed sentinels via `errors.Is/As`; `fmt.Errorf` audited for `%w`; `internal/errs/` ships canonical sentinels per subsystem (`errs.ErrNotFound`, `errs.ErrUnauthorized`, etc.); all handler error responses go through one path that maps sentinel → HTTP status code.
- **Remove `interface{}`/`any` where concrete fits**: type-set audit; generics where helpful (e.g. typed `lru.Cache[K,V]` over `interface{}`-based v1.11 cache).
- **Doc-comment 100% public API**: `golint` ST1020 gate; every exported func + type + method has a complete doc comment; package-level docs include canonical usage example.
- **golangci-lint v2 enabled**: full config with `gocritic` + `revive` + `prealloc` + `errchkjson` + `nilnesserr` + `protogetter` + `recvcheck`; existing v1.64 config retired; per-rule allowlist with justification comments.
- **`internal/repocheck` extension**: file-size budget extended to per-function complexity (cyclomatic) + per-file max imports + per-package max files; gate enforces budgets that we're already meeting today (lock the bar).

**Out of scope at v2.15**

- Architectural rewrites. Refactor inside the existing shape, don't restructure.
- API surface changes. Doc work only on `pkg/compliancekit`; no new types, no removals.

**Dependencies added**

- `golang.org/x/perf` for benchstat in CI.
- golangci-lint v2 — toolchain dep, not a binary dep.

**No API surface change** (the whole point).

---

### v2.16 — Test pyramid maturity

**Goal:** the test suite that catches the bug you would have shipped. Fuzz everywhere a parser exists, property-based for the engine, mutation testing for the core, chaos for the daemon, snapshot for every output, golden 100% for reporters + checks, weekly integration runs on every cloud, Playwright e2e matrix, perf regression gates.

**Deliverables**

- **Fuzz testing on every parser**: SARIF / OCSF / OSCAL / Trivy / Grype / Checkov / gitleaks / yaml (config) / rego / HTTP API request bodies — each gets a `FuzzXxx` + corpus committed to `testdata/fuzz/`; CI runs fuzz for 5 minutes per parser on every PR + 1 hour nightly per parser on `main`.
- **Property-based tests** (`pgregory.net/rapid`): ResourceGraph (round-trip invariants, query-equivalence), Engine (idempotency, ordering invariants), Rules (condition-evaluation determinism, action-dispatch effects), Waiver matching (glob expansion equivalence).
- **Mutation testing** (`go-mutesting`): baseline `mutation-score.json` committed; CI gate at >80% mutation kill rate on `internal/engine/` + `internal/checks/` + `internal/rules/` + `internal/policy/`; quarterly review of survivors.
- **Chaos engineering** (`toxiproxy`): fault injection on Postgres (50ms / 500ms / 5s latency, packet loss, connection reset), webhook receivers (slow client, partial body), SSE clients (slow consumer, mid-stream disconnect), notify sinks (slow / error / partial); expected DLQ + retry behavior asserted in tests under `tests/chaos/`.
- **Snapshot tests for every HTML route + reporter format** (`gotest.tools/v3/golden`): every page rendered against canonical fixture state; reporters (JSON / HTML / SARIF / OCSF / OSCAL AR + Profile / poam / Markdown / PDF) golden-tested for byte-stable output.
- **Golden-file coverage 100%** across `internal/report/` + `internal/checks/`: every check has a unit test against a recorded fixture (per-cloud SDK fixtures already vendored); every reporter has a per-format golden.
- **Weekly integration-test fleet**: ephemeral burst accounts on AWS / GCP / DO / Hetzner / K8s spun up Sunday 00:00 UTC; full provider-coverage scan runs; SLO report posted to `tests/integration/SLO.md` + PagerDuty if regression; accounts torn down.
- **e2e Playwright matrix**: chromium + firefox + webkit; touches login + onboarding wizard + finding explorer + dashboard builder + audit pack export + rule builder + plugin install; runs per PR (chromium-only on PR, full matrix nightly).
- **Perf regression gate**: blocks PRs above benchmark budget (lifts/extends v2.15 budgets into a hard gate); benchstat-driven; per-package thresholds.
- **Test-pyramid scorecard**: `docs/testing/scorecard.md` tracks unit / integration / e2e / fuzz / property / mutation / chaos coverage per package; updated quarterly.

**Out of scope at v2.16**

- Formal verification (TLA+ / Coq). Compelling for distributed systems work; out of scope for compliancekit's shape.
- Production traffic replay. Hand-rolled if needed; no canonical pattern yet.

**Dependencies added**

- `pgregory.net/rapid` for property-based.
- `github.com/zimmski/go-mutesting` for mutation (CI-side, not a binary dep).
- `github.com/Shopify/toxiproxy/v2` for chaos (test-only).
- `gotest.tools/v3` for golden assertions.
- `@playwright/test` (npm) for e2e.

**No API surface change**.

---

### v2.17 — Developer experience

**Goal:** make it 10× easier to ship a 1-line PR or a 1000-line plugin. Devcontainer ready, video onboarding, plugin SDK 2.0 with codegen, public roadmap + RFC process, contributor portal.

**Deliverables**

- **`.devcontainer/`**: Codespaces-ready Go + Node + cosign + grafana-cli + helm + kubectl + terraform + golangci-lint + lefthook + every CLI dep pre-installed; opens to a working test environment in <90s.
- **`make bootstrap` + `make smoke`**: first-90-seconds scripts — `bootstrap` installs all tooling, runs `make check`, seeds demo data; `smoke` runs a 30-second end-to-end happy-path against the demo daemon.
- **Video onboarding**: "zero to first PR in 15 minutes" walkthrough — fork → clone → devcontainer → make smoke → edit a check → run tests → open PR. Hosted on YouTube; linked from CONTRIBUTING.md.
- **Plugin SDK 2.0**: richer scaffolder (`compliancekit checks new --template=rego|go-subprocess|wasm` — three blueprints); codegen for boilerplate (`compliancekit codegen check <id>` emits manifest + tests + docs scaffold); runnable starter pack repo template at `darpanzope/compliancekit-plugin-template`; OCI registry push + cosign sign baked into the scaffold.
- **CI templates for plugin authors**: `.github/workflows/check-pack.yaml` published as a re-usable action at `darpanzope/compliancekit-action-pack-ci` — validates manifest, runs tests, signs with cosign, publishes to GHCR.
- **Opt-in anonymous telemetry**: PostHog self-hosted (we run the receiver, no third party); event payload: version + which providers configured + which CLI commands invoked (just the verb, never the args); never finding bodies, never tokens; opt-in only with `compliancekit telemetry enable`; documented in detail; aggregated stats published quarterly.
- **ADR generator**: `make adr` opens `$EDITOR` with the canonical template + auto-increments to next ADR number; lints for required sections.
- **Public RFC process**: `/rfcs/` directory + `gh issue create` template with RFC label; 14-day comment window; maintainer team triages; merged RFCs link out to tracking issues.
- **Public roadmap board**: GitHub Projects v2 mirroring the milestones in this ROADMAP.md; auto-synced via a `make sync-roadmap-board` script.
- **Contributor portal**: `docs.compliancekit.io/contribute` with good-first-issue feed (live from `gh issue list --label good-first-issue`); maintainer-status criteria explicit; mentorship pairing offered; per-area maintainers listed.
- **`compliancekit dev`** subcommand suite: `dev seed` (seed demo data), `dev reset` (wipe and re-seed), `dev replay <fixture>` (replay a recorded scan against the current code for regression hunting).

**Out of scope at v2.17**

- Paid tier or SaaS pivot. compliancekit stays Apache-2.0, self-hostable; v2.20 adds support tier doc only.
- Required telemetry. Opt-in forever per ADR-014 — no v2 break.

**Dependencies added**

- PostHog self-hosted receiver shipped as an optional Helm chart in `deploy/helm/telemetry/`.

**No API surface change** to existing `pkg/compliancekit`; `pkg/compliancekit/plugin` gets the SDK 2.0 additions (additive).

---

### v2.18 — GitOps compliance

**Goal:** the compliance source-of-truth lives in your git repo, not the daemon. ArgoCD / Flux native, drift opens a PR, weekly digest auto-committed, dashboards-as-code, waivers-as-PR.

**Deliverables**

- **ArgoCD + Flux templates**: `deploy/gitops/` ships ApplicationSet + Kustomization specs for both controllers; the daemon syncs `compliance/` directory from a designated git repo.
- **Drift → PR**: daemon detects drift (new finding crosses severity threshold, baseline regression) and opens a PR against the `compliance/` repo with the proposed remediation (waiver add or remediate snippet); per-finding PR author = `compliancekit-bot`; required-reviewer rules per repo config.
- **Weekly compliance digest auto-PRed**: every Monday 00:00 UTC, daemon opens a PR with snapshot under `compliance/snapshots/YYYY-WW.json` + a markdown summary; auditor reviews + merges.
- **Dashboards-as-code**: `compliance/dashboards/*.dashboard.yaml` declarative spec → DB hydration via `compliancekit dashboards apply`; reverse direction via `compliancekit dashboards export`; CI gate validates schema.
- **Scan-as-CRD**: Kubernetes-native scan trigger via the v1.15 / v2.10 operator (`ComplianceScan` CRD); operator reconciles scan results back into the cluster as ConfigMaps; ArgoCD shows compliance posture inline with app health.
- **Profile-as-config**: `compliance/profiles/<name>.yaml` source-of-truth; UI is a read+suggest layer for non-Git users (proposes edits, lets the operator commit through PR or via the UI directly).
- **Waiver-as-PR**: `compliance/waivers/<name>.yaml` source-of-truth; UI waiver creation opens a PR (or commits directly per per-org policy); required-reviewers config in `compliance/.compliancekit.yaml`.
- **Compliance posture in ArgoCD UI**: custom health check definition shipped in `deploy/argocd/` that surfaces compliancekit's scan status against an Application as healthy / degraded / unhealthy.
- **Drift triage queue**: `/drift` UI route — every open drift PR aggregated with status (open / mergeable / blocked); cross-link to git PR; per-drift severity badge.

**Out of scope at v2.18**

- Non-GitHub git providers' PR APIs. v2.18 ships GitHub + GitLab; Bitbucket + Gitea at v2.18.x if demand.

**Dependencies added**

- `github.com/google/go-github/v68` (already vendored, deepened).
- `github.com/xanzy/go-gitlab` for GitLab.

**API surface additions**: `gitops.Backend` interface in a new `pkg/compliancekit/gitops` subpackage.

---

### v2.19 — i18n 2.0

**Goal:** a genuinely-global compliance dashboard. 10+ languages, RTL layout, locale-aware everything, translator workflow, per-tenant locale, on-the-fly switch.

**Deliverables**

- **10-language translation coverage**: en (canonical) / es / fr / de / ja / zh-Hans / pt-BR / ko / it / ar. Every template, every email, every notification body, every CLI string, every framework name, every check title + description + remediation text.
- **RTL layout**: Arabic + Hebrew foundations; CSS logical properties throughout (`inline-start` / `inline-end` not `left` / `right`); UI rendering tested in both directions.
- **Locale-aware dates / numbers / currency / time-zones**: CLDR via `golang.org/x/text/message` + `display`; per-locale formatting for findings.csv exports; per-tenant time-zone respected in scheduled-report send times.
- **Translator workflow**: Weblate-compatible PO files + Crowdin-compatible JSON shipped in `internal/i18n/translations/`; CI gate blocks merge that adds untranslated key beyond a configurable threshold (default 5% per locale); translation-completeness badge in README.
- **Per-tenant + per-user locale + per-notification-channel override**: Slack DM honors recipient's locale not poster's; webhook payloads include `locale` field; email respects user pref.
- **On-the-fly language switch**: no reload; persists per-user; surfaces in topbar next to theme picker.
- **Community-contributed language packs**: extend the v1.13 plugin SDK so a `kind: i18n-pack` plugin can register a new locale; community-maintained packs for tier-2 languages (sv / nl / pl / tr / id / vi / fa / th / he / hu / ro / cs / sk / fi / da / no / uk / el).
- **Translation memory + auto-sync**: weekly job opens a PR with new keys added since last sync; per-locale stat updates; reviewer assigns translator.

**Out of scope at v2.19**

- Vendor-translated docs. Docs translation lives at v2.13.x if demand surfaces.
- Auto-translation. Translator workflow only; no LLM-generated translations in main (community plugins can choose to use LLM).

**Dependencies added**

- `golang.org/x/text` already vendored from v1.10.
- `github.com/nicksnyder/go-i18n/v2` already vendored from v1.10 — deepened.

**No API surface change.**

---

### v2.20 — Enterprise polish

**Goal:** Fortune-500 procurement-review ready. SSO MFA enforcement, audit immutability with WORM storage, retention policies, data residency, session intelligence, BYOK, contract-grade SLA documentation, paid support tier.

**Deliverables**

- **SSO MFA enforcement policy**: per-role + per-org + step-up auth on sensitive ops (waiver create over threshold, role assignment, settings export); WebAuthn / FIDO2 first-class; SMS deprecated with timeline.
- **Audit immutability (WORM)**: storage adapters — `internal/server/store/worm/` — S3 Object Lock + Azure Immutable Blob + GCS Bucket Lock; the v1.12 per-row hash-chain extended to a per-second Merkle root anchored to a public ledger optionally (Sigstore Rekor as default ledger; Ethereum L2 as opt-in).
- **Retention policies**: per-data-type TTL (findings 7yr / audit 10yr / sessions 90d / SSE replay ring 5min / inbox 1yr — every TTL customizable); GDPR delete-on-request workflow; right-to-be-forgotten audit log.
- **Data residency selector**: per-tenant region pin; cross-region replication off by default; `regions.yaml` documents data flow per region.
- **Session intelligence**: anomaly detection on geo / device / hour (per-user baseline established from history); risk-scored login with step-up MFA; impossible-travel detection.
- **IP allowlist + geo-fencing per-org**: extends v2.14 server-side middleware to a per-org configurable policy via the v1.12 admin UI.
- **Customer-managed encryption keys (BYOK)**: KMS adapters for AWS KMS / GCP KMS / Azure Key Vault / HashiCorp Vault Transit; envelope encryption for sensitive columns (tokens, secrets-in-rest, PII); per-tenant CMK rotation policy.
- **Contract-grade SLA**: documented in `docs/operations/SLA-template.md` — 99.9% uptime target, 24h RPO, 4h RTO for a properly-deployed HA daemon; status-page generator under `compliancekit serve status` (lightweight built-in status page or export to Statuspage/Cachet/Atlassian).
- **Paid support tier (documentation only — not a SaaS pivot)**: incident-response runbook template, 24/7 escalation contract template, professional-services-statement-of-work template; published so an org can buy support from a vendor (any vendor — compliancekit doesn't sell support, just provides the artifacts an integrator/consultancy can sell under).
- **Compliance certifications self-attestation**: docs + evidence-pack templates for SOC 2 Type II, ISO 27001, PCI DSS, HIPAA — the artifacts an operator hands to *their* auditor to demonstrate compliancekit-managed deployment posture; not compliancekit-the-vendor SOC 2.

**Out of scope at v2.20**

- compliancekit as a hosted SaaS. No plan; the binary is the product.
- Vendor-managed compliance certification (compliancekit-the-vendor pursuing SOC 2). If/when the project incorporates as a foundation or sponsor, separate effort.

**Dependencies added**

- Cloud KMS SDKs already vendored from v0.7/v0.8.
- `github.com/hashicorp/vault/api` from v2.14.

**No API surface change** (additive `internal/` packages only).

---

## Success metrics

- **v0.5 launch week:** 500+ stars, on HN front page for ≥4 hours.
- **30 days:** 1,000 stars, 10 external contributors, 3 GitHub Actions in public repos using it.
- **90 days:** 2,500 stars, mentioned in one major newsletter (`tldr.sec`, `KubeWeekly`, `Last Week in AWS`).
- **180 days:** at least one SaaS startup public-cases their SOC 2 prep using compliancekit.

Vanity metrics aren't the point. The honest goal: by month 6, someone googling **"open source DigitalOcean compliance"** lands on this repo as the obvious answer.
