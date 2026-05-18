# CLI reference

Every command, every flag, every exit code. The README has the friendly version; this is the lookup table.

## Synopsis

```
compliancekit <command> [subcommand] [flags]
```

## Global flags

Available on every subcommand:

| Flag | Default | Description |
|---|---|---|
| `--config <path>` | (lookup) | path to `compliancekit.yaml` |
| `--env <name>` | — | load `compliancekit.<name>.yaml` if present |
| `--out-dir <path>` | `./out` | output directory |
| `--output <fmt>` | `json` | output format(s), comma-separated |
| `--log-level <level>` | `info` | trace, debug, info, warn, error |
| `--log-format <fmt>` | `text` | text or json |
| `--no-color` | false | disable ANSI colors |
| `--quiet`, `-q` | false | suppress non-error output |
| `--verbose`, `-v` | false | verbose; sets `--log-level=debug` |
| `--help`, `-h` | — | show help for the command |

## Commands at a glance

| Command | First version | Purpose |
|---|---|---|
| `scan` | v0.1 | run a scan across enabled providers |
| `report` | v0.3 | convert findings to a different format |
| `evidence` | v0.4 | generate the audit-ready evidence pack |
| `checks list` / `show` | v0.1 | query the check catalogue |
| `diff` | v0.6 ✅ | compare two findings sets (drift gate) |
| `baseline` | v0.6 ✅ | capture current state as accepted baseline |
| `doctor` | v0.1 | smoke test config, secrets, connectivity |
| `version` | v0.1 | print version + commit + build date |
| `remediate` | v0.15 | generate remediation snippets |
| `ingest` | v0.13 | import Trivy / Checkov / OCSF / OSCAL / SCAP |
| `serve` | v1.3 | continuous monitoring daemon |
| `tui` | v1.7 | k9s-style terminal UI client (local findings.json or daemon) |
| `plugins` | v1.13 | manage plugin packages (SDK + signing); marketplace federation at v2.9 |
| `warehouse` | v1.17 | export findings to Parquet / BigQuery / Snowflake / Redshift / DuckDB |
| `trust-center` | v2.2 | generate public security page |

---

### `compliancekit scan`

Run a scan across all enabled providers.

```
compliancekit scan [provider] [flags]
```

If `provider` is omitted, scans everything enabled in the config.

Flags:

| Flag | Description |
|---|---|
| `--checks <ids>` | comma-separated check IDs to run; default: all |
| `--skip-checks <ids>` | check IDs to skip |
| `--frameworks <names>` | only checks mapped to these frameworks |
| `--severity <level>` | only run checks at this severity or higher |
| `--services <names>` | comma-separated services (e.g. `droplets,spaces`) |
| `--regions <names>` | comma-separated DO regions to scope |
| `--tags <list>` | only scan resources matching these tags |
| `--exclude-tags <list>` | exclude matching resources |
| `--fail-on <level>` | exit non-zero if any finding at this level (default: `high`) |
| `--inventory <path>` | path to `inventory.yaml` (linux provider) |
| `--include-raw` | evidence pack includes unredacted raw responses |
| `--no-evidence` | skip evidence pack generation |
| `--state-dir <path>` | override state directory |
| `--baseline` | treat current findings as accepted baseline (use `compliancekit baseline` for the workflow) |
| `--profile <name>` | named subset of checks declared in `compliancekit.yaml` under `profiles:` |
| `--dry-run` | enumerate what would run; don't execute checks |

Examples:

```
# Scan DO with default config
DO_API_TOKEN=... compliancekit scan digitalocean

# Scan Linux fleet via inventory
compliancekit scan linux --inventory=inventory.yaml

# CI gate: fail only on new critical findings
compliancekit scan --output=json,sarif --fail-on=critical

# Filter to SSH checks, JSON-only
compliancekit scan linux --services=sshd --output=json
```

Exit codes: see [Exit codes](#exit-codes) below.

---

### `compliancekit render`

Re-render an existing `findings.json` against any registered reporter format. Useful for refreshing an HTML/Markdown report after upgrading compliancekit, iterating on the v1.2 HTML template without re-scanning, or producing a fresh SARIF/OCSF artifact from a saved scan. Defaults to HTML.

```
compliancekit render [flags]
```

Flags:

| Flag | Description | Default |
|---|---|---|
| `--in <path>` | input `findings.json` (or `-` for stdin) | `findings.json` |
| `--format <fmt>` | reporter format: `html`, `json`, `markdown`, `sarif`, `ocsf` | `html` |
| `--out <path>` | output destination | stdout |
| `--baseline <path>` | baseline.json file OR directory of historical baselines (HTML only — drives the drift card + score/actionable-count sparklines + per-finding "new" badges) | (empty) |

Examples:

```
compliancekit scan digitalocean --out-dir=./out
compliancekit render --in=./out/findings.json --out=./report.html

# Render markdown to stdout (great for pasting into a PR comment)
compliancekit render --in=./out/findings.json --format=markdown

# Trend visualisation: drift card + sparklines vs a saved baseline
compliancekit render --in=./out/findings.json --baseline=./.compliancekit/baseline.json --out=./trend.html

# Up to 7-point trend from a directory of historical baselines
compliancekit render --in=./out/findings.json --baseline=./.compliancekit/history/ --out=./trend.html
```

---

### `compliancekit evidence`

Generate an audit-ready evidence pack from a `findings.json`. See ARCHITECTURE.md §10 for the output layout.

```
compliancekit evidence --in findings.json --out <dir> [flags]
```

Reads either the wrapped scan envelope (the default `scan` output) or a raw findings array, so a `jq`-trimmed subset is acceptable input. Writes a tamper-evident folder with per-framework, per-control directories, an auditor-readable `summary.html`, a Drata/Vanta-importable `control-mapping.csv`, and `MANIFEST.sha256` covering every file.

Flags:

| Flag | Default | Description |
|---|---|---|
| `--in <path>` | `findings.json` | scan findings to package |
| `--out <path>` | — (required) | output directory; must be empty or absent |
| `--period <label>` | current quarter | audit period embedded in the pack (e.g. `2026-Q2`) |
| `--include-raw` | `false` | skip redaction of sensitive tokens (AWS keys, GitHub PATs, Slack tokens, bearer headers, emails) in messages |
| `--config <path>` | — | v0.12+. Path to `compliancekit.yaml`; loads the `tailoring:` block so the pack carries operator-declared scope-outs |
| `--env <name>` | — | v0.12+. Load `compliancekit.<env>.yaml` overlay alongside `--config` |

Frameworks shipped at v1.0: SOC 2 (TSC), ISO/IEC 27001:2022 Annex A, CIS Controls v8, CIS Linux Server Benchmark v8 (added v0.20), NSA/CISA Kubernetes Hardening Guide v1.2 (added v0.21), NIST SP 800-53 r5, HIPAA Security Rule, PCI DSS v4.0, MITRE ATT&CK Enterprise. **668 controls total across 9 catalogs.** Frameworks are picked up automatically from `internal/frameworks/<id>.yaml`; new ones can be added without code changes.

When `--config` is passed, the pack additionally writes a `tailoring.json` to the root and adds `framework_name`, `control_family`, `control_tags`, `tailored`, and `tailoring_justification` columns to `control-mapping.csv` so auditors see every operator-declared scope-out with its written reason.

Example:

```
compliancekit scan --output json > findings.json
compliancekit evidence --in findings.json --out evidence/2026-Q2/
# verify tamper-evidence:
cd evidence/2026-Q2/ && sha256sum -c MANIFEST.sha256
```

---

### `compliancekit checks`

Query the check catalogue.

```
compliancekit checks list [flags]
compliancekit checks show <check-id>
```

`list` flags:

| Flag | Description |
|---|---|
| `--framework <name>` | filter by framework |
| `--provider <name>` | filter by provider |
| `--severity <level>` | filter by severity |
| `--format <fmt>` | `table` (default), `json`, `csv` |

Examples:

```
compliancekit checks list
compliancekit checks list --framework=soc2 --severity=high
compliancekit checks show do-spaces-public-acl
```

---

### `compliancekit baseline`

Capture a scan's findings as the accepted baseline. The next scan's
`diff` against this file classifies findings as new / existing /
resolved.

```
compliancekit baseline [flags]
```

Flags:

| Flag | Default | Description |
|---|---|---|
| `--in <path>` | `findings.json` | scan findings to capture |
| `--out <path>` | `.compliancekit/baseline.json` | baseline file to write |

Baselines are gitignored by default. Commit one deliberately if you
want PR-level drift gating. Schema is `compliancekit.baseline.v1`;
a future change bumps the schema rather than silently invalidating
older files.

Example:

```
compliancekit scan --output json --out-dir out/
compliancekit baseline --in out/findings.json
# commit .compliancekit/baseline.json
```

---

### `compliancekit diff`

Classify a current scan's findings against a previously captured
baseline. The drift gate for CI.

```
compliancekit diff <baseline.json> <findings.json> [flags]
```

Flags:

| Flag | Default | Description |
|---|---|---|
| `--fail-on` | `never` | exit-code gate; see below |

Severity-aware exit codes:

| `--fail-on` value | Meaning |
|---|---|
| `never` | always exit 0 (just print the diff) |
| `<sev>` | exit 2 if **any** current finding is actionable at or above `<sev>` (matches `scan --fail-on`) |
| `new-<sev>` | exit 2 if any **NEW** actionable finding is at or above `<sev>` (drift-gate: PR introduced a regression) |

Severities: `critical`, `high`, `medium`, `low`, `info`.

Output:

```
+ 2 new   (1 high, 1 medium)
- 1 resolved  (1 high)
= 23 existing
Hardening score: 76 -> 73 (-3)
```

Example CI workflow:

```yaml
- run: compliancekit scan --output json --out-dir out/
- run: compliancekit diff .compliancekit/baseline.json out/findings.json --fail-on=new-high
```

---

### `compliancekit doctor`

Smoke test: validates config, resolves env vars, checks connectivity to provider APIs and inventory hosts. Does **not** run any checks.

```
compliancekit doctor [flags]
```

Flags:

| Flag | Description |
|---|---|
| `--check-config` | only validate config schema; skip network probes |

Example output:

```
$ compliancekit doctor
✓ config: ./compliancekit.yaml loaded
✓ providers.digitalocean: DO_API_TOKEN resolved (token length: 71)
✓ providers.digitalocean: API reachable (api.digitalocean.com → 200 OK in 312ms)
✓ providers.linux: 12 hosts in inventory
✓ providers.linux: SSH agent has 1 key loaded
⚠ providers.linux: db-03 unreachable (i/o timeout) — will skip on scan
✓ frameworks: soc2, cis-v8 loaded; 47 checks mapped
```

---

### `compliancekit version`

Print version, commit, and build date.

```
$ compliancekit version
compliancekit v0.1.0 (commit abc1234, built 2026-05-13T14:22:00Z)
```

Flags:

| Flag | Description |
|---|---|
| `--short` | print version only |
| `--json` | machine-readable output |

---

### `compliancekit remediate` (v0.15+)

Generate remediation snippets for a finding.

```
compliancekit remediate [flags]
```

Flags:

| Flag | Description |
|---|---|
| `--in <path>` | input findings file |
| `--finding <id>` | specific finding ID |
| `--as <tool>` | output language: `bash`, `terraform`, `ansible`, `aws`, `gcloud`, `doctl`, `hcloud` |
| `--out <path>` | write to file (default: stdout) |
| `--apply` | (v2.x, opt-in) actually execute the remediation; requires `--yes-i-mean-it` |

---

### `compliancekit ingest` (v0.13+)

Import findings from external scanners and normalize to compliancekit format.

```
compliancekit ingest <source> [flags]
```

Supported sources: `trivy`, `checkov`, `kics`, `terrascan`, `grype`, `scap`, `oscal`.

Flags:

| Flag | Description |
|---|---|
| `--in <path>` | source file or directory |
| `--out <path>` | normalized findings.json |
| `--map <framework>` | re-map ingested check IDs to our framework controls |

---

### `compliancekit serve` (v1.3+)

Run the continuous monitoring daemon.

```
compliancekit serve [flags]
```

Flags:

| Flag | Description |
|---|---|
| `--listen <addr>` | bind address (default `0.0.0.0:8080`) |
| `--state-dir <path>` | state directory for the daemon |
| `--schedule <cron>` | scan interval (default: every 6h) |

The daemon exposes:

- `GET /healthz`, `GET /readyz`
- `GET /api/v1/findings`
- `GET /api/v1/scans`
- `POST /api/v1/scans` (trigger an on-demand scan)
- `GET /` — server-rendered HTML dashboard

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success; no findings at or above `--fail-on` severity |
| 1 | generic error (bad config, network failure, etc.) |
| 2 | findings at or above `--fail-on` severity present |
| 3 | partial failure (some hosts/services unreachable) |
| 4 | config validation failure |
| 5 | authentication failure |
| 127 | command not found / unknown subcommand |

Codes 2 and 3 are *expected* signals for CI: "the scan ran successfully, but here are findings to act on." Tools wrapping compliancekit should distinguish them from code 1 (something went wrong with the tool itself).

## Flag conventions

- Boolean flags: `--foo` enables, `--no-foo` disables. Both forms accepted where it matters.
- List flags: comma-separated, no spaces. Example: `--checks=a,b,c`.
- Paths: `~` is expanded; relative paths resolve against the working directory.
- Durations: Go duration syntax (`10s`, `5m`, `1h`).
- Severity levels: `info | low | medium | high | critical`. Comparisons are inclusive (`--fail-on=high` includes critical).

## Environment variable overrides

Every flag is overridable via env var. The mapping is `COMPLIANCEKIT_<UPPER_FLAG_NAME>`. Example: `--out-dir` ↔ `COMPLIANCEKIT_OUT_DIR`. See CONFIGURATION.md for full env conventions.

## Shell completion

```
compliancekit completion bash > /etc/bash_completion.d/compliancekit
compliancekit completion zsh  > "${fpath[1]}/_compliancekit"
compliancekit completion fish > ~/.config/fish/completions/compliancekit.fish
compliancekit completion powershell | Out-String | Invoke-Expression
```

Generated via the Cobra default; each shell's `completion --help` prints
the install path appropriate for that shell.

## Color palette + glyph reference (v1.1+)

Every subcommand routes its styled output through a single Styler
(`internal/ui/style.go`) so the visual language stays consistent.
Three switches disable color, in this precedence order — first
negative wins:

1. `--no-color` global flag (forces plain even on a TTY)
2. `NO_COLOR` environment variable (any value disables, per
   [no-color.org](https://no-color.org))
3. `CLICOLOR=0` (legacy BSD / git convention)
4. Non-TTY stdout (pipes, redirects, CI runners)

### Severity palette

| Severity   | Color (TTY)            | Chip      | Glyph |
| ---------- | ---------------------- | --------- | ----- |
| `critical` | red bold               | `[CRITICAL]` | `✗` (fail-rendered) |
| `high`     | orange bold            | `[HIGH]`     |       |
| `medium`   | yellow                 | `[MEDIUM]`   |       |
| `low`      | blue                   | `[LOW]`      |       |
| `info`     | grey                   | `[INFO]`     | `·`   |
| `unknown`  | muted grey             | `[UNKNOWN]`  |       |

The `bold` modifier kicks in at `high` so the eye lands on
high + critical first.

### Status palette

| Status   | Color (TTY) | Glyph (TTY) | ASCII fallback |
| -------- | ----------- | ----------- | -------------- |
| `pass`   | green dim   | `✓`         | `ok`           |
| `fail`   | red         | `✗`         | `X`            |
| `skip`   | grey        | `–`         | `-`            |
| `error`  | orange      | `⚠`         | `!`            |

### Diff palette

| Kind       | Color (TTY)             | Glyph |
| ---------- | ----------------------- | ----- |
| `added`    | bold green              | `+`   |
| `removed`  | dim grey strikethrough  | `-`   |
| `existing` | muted grey              | `=`   |

### Frame characters (table renderer)

| Mode  | Corners | Edges | Junctions |
| ----- | ------- | ----- | --------- |
| TTY   | `┌ ┐ └ ┘` | `─ │` | `┬ ┴ ├ ┤ ┼` |
| Plain | `+`      | `- |`  | `+`       |

Frame characters render in the muted color so the eye lands on
the row content, not the table chrome.

### Width stability

ASCII fallbacks for status / diff glyphs are intentionally width-
matched to their unicode counterparts so column layouts stay
stable across modes. A table that lines up in TTY mode lines up
in plain mode without re-padding.
