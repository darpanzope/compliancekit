# Development

How to build, test, and iterate on compliancekit locally. For contributors; users want the README and CLI.md.

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Go | 1.22+ | the only hard requirement |
| make | any | thin wrapper over `go` commands |
| golangci-lint | 1.55+ | installed by `make setup` if missing |
| Docker | optional | only needed for `make test-integration` (SSH harness) |
| asciinema | optional | recording demos for release notes |

macOS via Homebrew:

```
brew install go make golangci-lint
```

Linux: install Go from go.dev; `make` and `golangci-lint` via your package manager.

## First-time setup

```
git clone git@github.com:darpanzope/compliancekit.git
cd compliancekit
make setup        # installs goimports, golangci-lint via 'go install' if missing
make build        # produces bin/compliancekit
./bin/compliancekit version
```

If `make setup` complains about missing system tools (make, docker), install them via your package manager — we don't auto-install OS-level dependencies.

## Daily loop

| Command | What it does |
|---|---|
| `make build` | `go build` → `bin/compliancekit` |
| `make run ARGS="scan digitalocean"` | `go run` with arguments |
| `make test` | unit tests with race detector |
| `make test-integration` | integration tests; brings up docker SSH harness |
| `make lint` | `golangci-lint run` |
| `make fmt` | `gofmt` + `goimports` on all `.go` files |
| `make tidy` | `go mod tidy` |
| `make clean` | `rm bin/` and test artifacts |
| `make check` | lint + test + build (the pre-push gate) |

**`make check` is the contract.** If it passes locally, CI passes.

## Project layout

See ARCHITECTURE.md §5. Short version:

```
cmd/compliancekit/     binary entry point (main package, thin)
internal/              private packages — CLI, engine, collectors, evaluators, reporters, ...
pkg/                   public API — empty until v1.0
web/report/            HTML/CSS for the embedded report
test/                  integration test fixtures + docker harness
```

## Build flags

The Makefile injects build metadata via `ldflags`:

```
-X main.version=v0.1.0-dev
-X main.commit=$(git rev-parse --short HEAD)
-X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
```

For release builds (handled by goreleaser from v0.5):

```
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w ..." ./cmd/compliancekit
```

## Testing

Three layers:

### Unit tests

`*_test.go` next to source. Run with `make test`. Mandatory for every check. Use `testify` for assertions.

### Provider fixtures

Recorded real provider responses, replayed forever:

```
RECORD=1 DO_API_TOKEN=<read-token> go test ./internal/collectors/digitalocean/...
```

Recorded fixtures live in `internal/collectors/<provider>/testdata/`. Commit them; they make tests deterministic and offline.

The recorder redacts tokens, account UUIDs, and emails automatically. **Always manually review** the recorded file before committing — automated redaction is best-effort.

### Integration tests (v0.2+)

Linux checks against real Ubuntu/Debian containers via `test/compose.yaml`. Run with `make test-integration`. Optional locally; required in CI.

```
docker compose -f test/compose.yaml up -d
make test-integration
docker compose -f test/compose.yaml down
```

## Linting

`golangci-lint` with config at `.golangci.yaml`. Enabled linters include: `errcheck`, `gosimple`, `govet`, `ineffassign`, `staticcheck`, `unused`, `gosec`, `misspell`, `gofmt`, `goimports`, `revive`.

To suppress a finding, use a line-level directive with justification:

```go
// nolint:gosec // reading from controlled test fixture
```

A bare `nolint` without a reason is itself a lint failure.

## Continuous integration

`.github/workflows/ci.yaml` runs on every push and PR:

1. Checkout + Go setup with caching
2. `make lint`
3. `make test` (with race detector)
4. `make test-integration` (Docker-based)
5. `make build` — also validates cross-compile to linux/amd64 and darwin/arm64

Required to pass before merge. Additionally:

- `codeql.yaml` — GitHub CodeQL security scan
- `release.yaml` — runs on tag push; invokes goreleaser (from v0.5)

## Recording new fixtures

When adding a check that hits a new DO API endpoint:

```
export DO_API_TOKEN=<read-only-token>
RECORD=1 go test ./internal/collectors/digitalocean/... -run TestNewCheck
git add internal/collectors/digitalocean/testdata/
```

Steps:

1. Export a **read-only** token. The recorder won't enforce this, but a write-scope token has no business being used for fixtures.
2. Run the test with `RECORD=1`. The HTTP layer captures every request/response pair.
3. Open the new file under `testdata/`. Verify no tokens, account UUIDs, IPs, or emails leaked through redaction.
4. Commit.

## Working on a new check

See CHECKS.md for the full workflow. Short version:

1. Add YAML metadata under `internal/checks/<provider>/`.
2. Implement the scanner func under `internal/collectors/<provider>/`.
3. Add unit test with fixture.
4. Add framework mappings.
5. `make check` should pass.

## Releasing (v0.5+)

```
git tag v0.5.0
git push origin v0.5.0
```

GitHub Actions invokes `goreleaser`; outputs cross-compiled binaries, Homebrew formula update, Docker image (`ghcr.io/darpanzope/compliancekit`), cosign signatures, SBOM.

Tag format: `v<major>.<minor>.<patch>` strictly. Pre-releases use `-rc.N` suffix.

## Debugging

Useful flags during development:

```
compliancekit scan --log-level=debug --log-format=text
compliancekit scan --dry-run          # enumerate without executing
compliancekit doctor                  # validate config + connectivity
```

To attach a debugger:

```
dlv debug ./cmd/compliancekit -- scan digitalocean
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `make setup` fails on golangci-lint | install manually: `brew install golangci-lint` or `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest` |
| `go: go.sum entry missing` | `make tidy` |
| flaky SSH integration test | docker daemon not running; `colima start` on macOS |
| spell-check noise in IDE | ignore — most flagged words are technical terms (godo, OCSF, OSCAL, Rego, etc.) |
| `make test` is slow | `make test SHORT=1` skips integration-flavored unit tests |
