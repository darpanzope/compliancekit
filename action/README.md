# compliancekit GitHub Action

[![release](https://img.shields.io/github/v/release/darpanzope/compliancekit)](https://github.com/darpanzope/compliancekit/releases)

Run [`compliancekit`](https://github.com/darpanzope/compliancekit) in CI:
scan DigitalOcean accounts and Linux fleets against SOC 2, ISO 27001, and
CIS Controls v8; fail the build on findings above a severity threshold;
optionally generate an audit-ready evidence pack as a build artifact.

```yaml
- uses: darpanzope/compliancekit-action@v1
  with:
    providers: digitalocean,linux
    output: sarif,markdown,json
    fail-on: high
  env:
    DO_API_TOKEN: ${{ secrets.DO_API_TOKEN }}
```

## Where the source lives

The `darpanzope/compliancekit-action@v1` reference resolves to a separate
public repository whose contents are copied verbatim from this directory
at every compliancekit release. The canonical source is here, in the main
binary's repo, so the action and the binary version together.

To change the action, edit `action/action.yaml` here, ship it with the
next binary release, and the publish script copies the updated file to
the action repo and moves the floating `v1` tag.

## Inputs

| Input             | Default                 | Description |
|-------------------|-------------------------|-------------|
| `version`         | `latest`                | compliancekit version to install (without leading 'v'). |
| `providers`       | (config)                | Comma-separated subset of enabled providers to scan. |
| `config-file`     | —                       | Path to `compliancekit.yaml` in the workspace. |
| `inventory`       | —                       | Path to a Linux inventory file (only used when scanning linux). |
| `frameworks`      | (all)                   | Comma-separated framework filter (`soc2`, `iso27001`, `cis-v8`). |
| `output`          | `sarif,markdown,json`   | Report formats to emit. |
| `out-dir`         | `./out`                 | Where to write reports. |
| `fail-on`         | `high`                  | Severity threshold for non-zero exit. Set to `never` to disable. |
| `evidence`        | `false`                 | Also generate an evidence pack under `<out-dir>/evidence/`. |
| `evidence-period` | (current quarter)       | Audit period label for the evidence pack. |
| `upload-sarif`    | `true`                  | Upload the SARIF output to GitHub Code Scanning. |

## Outputs

| Output         | Description |
|----------------|-------------|
| `reports-dir`  | Absolute path to the directory the scan wrote into. |
| `evidence-dir` | Absolute path to the evidence pack (empty when `evidence: false`). |

## Permissions

The composite action itself runs in the calling workflow's permission
context. The recommended job-level scope:

```yaml
permissions:
  contents: read           # checkout
  security-events: write   # upload-sarif (only if output contains sarif)
  pull-requests: write     # if you also want PR comments from a later step
```

If you set `upload-sarif: false` you can drop `security-events: write`.

## Examples

### Scan DigitalOcean only, fail on high

```yaml
name: compliancekit
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: darpanzope/compliancekit-action@v1
        with:
          providers: digitalocean
          fail-on: high
        env:
          DO_API_TOKEN: ${{ secrets.DO_API_TOKEN }}
```

### Quarterly evidence pack, upload as build artifact

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
          evidence-period: ${{ github.run_id }}-$(date +%Y-Q%q)
          fail-on: never
        env:
          DO_API_TOKEN: ${{ secrets.DO_API_TOKEN }}
      - uses: actions/upload-artifact@v4
        with:
          name: evidence-pack
          path: ${{ steps.scan.outputs.evidence-dir }}
```

### Comment markdown summary on the PR

```yaml
- uses: darpanzope/compliancekit-action@v1
  id: scan
  with:
    providers: linux
    output: markdown,json
    fail-on: medium
- uses: marocchino/sticky-pull-request-comment@v2
  with:
    path: ${{ steps.scan.outputs.reports-dir }}/findings.markdown
```

## License

[MIT](https://github.com/darpanzope/compliancekit/blob/main/LICENSE), same as
compliancekit itself.
