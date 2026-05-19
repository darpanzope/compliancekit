# Contributing to compliancekit

Thank you for considering a contribution. compliancekit is open source under
[the LICENSE file at the repo root](LICENSE) and lives or dies by the quality
of the checks it ships, so changes that add or refine checks are especially
welcome.

This document is the contributor's view. End-user docs live in
[README.md](README.md), the architecture is in [ARCHITECTURE.md](ARCHITECTURE.md),
and the design decisions are in [DECISIONS.md](DECISIONS.md). Read those first
if you're trying to understand *why* something is the way it is.

## Before you start

For anything larger than a typo:

- Open an issue describing what you want to change. A two-line "is this in
  scope?" comment is enough.
- Wait for a maintainer to ack before opening a sizeable PR. Drive-by
  refactors and "modernizations" of working code are likely to be closed.
- Check the [ROADMAP.md](ROADMAP.md) -- the next two or three milestones are
  fixed, and changes that pull a v1.5+ feature forward usually need a
  conversation first.

## Development setup

[DEVELOPMENT.md](DEVELOPMENT.md) has the full workflow. The short version:

```
git clone git@github.com:darpanzope/compliancekit.git
cd compliancekit
make setup        # installs goimports, golangci-lint, lefthook, hooks
make build        # produces bin/compliancekit
make test
make check        # lint + test, the gate you must clear before pushing
```

### UI development (v1.4 Phase 0+)

Touching `internal/server/ui/templates/` or `internal/server/ui/src/input.css`?
You'll need the Tailwind standalone CLI — no Node, no npm:

```
make ui-setup     # one-time: downloads pinned tailwindcss binary into .cache/
make ui           # recompiles internal/server/assets/{app.css,*.js}
git add internal/server/assets/
```

`make check` includes `make ui-check`, which fails if the committed
`internal/server/assets/` is stale vs. the sources. Bumping a vendored
JS library (htmx / Alpine / Preline) means: drop the new file under
`internal/server/ui/vendor/` with the version suffix in the filename,
bump the matching `*_VERSION` variable in the Makefile, run `make ui`,
commit both. See [ADR-015](DECISIONS.md#adr-015--serve-ui-is-htmx--alpine--tailwind--preline--vanilla-svg-embedded-at-build-time)
for the UI stack rationale.

lefthook installs three Git hooks that mirror CI:

- `pre-commit`: `go fmt`, `goimports`, `go mod tidy`, `go vet`, `golangci-lint run` on staged Go files only
- `commit-msg`: validates Conventional Commits 1.0
- `pre-push`: `golangci-lint run ./...`, `go test -race ./...`, full build

Hooks are mandatory: pushing without them green is how regressions reach main.

## The shape of a good check PR

Most contributions are new checks. The bar:

1. **One new check per file** under `internal/checks/<provider>/<service>.go`,
   matching the convention in the existing files. The check metadata
   (`compliancekit.Check{...}` — note `pkg/compliancekit` is the v1.0+
   public import; `internal/core` was deleted at v1.0) and the evaluator
   function live next to each other.
2. **Framework mappings are mandatory.** Every check must reference at least
   one control in each of `soc2`, `iso27001`, and `cis-v8` (the three
   frameworks bundled at v0.4). If your check legitimately covers nothing in
   one of them, say so in the PR description so a reviewer can confirm.
3. **A unit test against a fixture.** No live API calls. Network-dependent
   tests belong in `make test-integration` and need an explicit go-build tag
   (`//go:build integration`).
4. **The remediation field is a copy-pastable command.** "Tighten the
   firewall" is not remediation. `doctl compute firewall update <id> ...` is.
5. **Verify your check renders end-to-end** with
   `go run ./cmd/compliancekit checks show <your-check-id>` -- this is the
   surface auditors will see.

Anything that touches the engine, registry, reporter contracts, or the
evidence pack format needs an ADR (append to [DECISIONS.md](DECISIONS.md))
before code review.

## Commit conventions

We follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
`lefthook commit-msg` enforces the syntax; the linter does not enforce the
content.

Allowed types: `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `build`,
`ci`, `chore`, `revert`.

Scope is the package name without the `internal/` prefix: `checks/linux`,
`collectors/digitalocean`, `evidence`, `cli`, `engine`, `report`.
Multi-scope commits are allowed: `feat(checks/linux,collectors/linux): ...`.

Body conventions:

- The body should explain *why*, not *what*. The diff already shows what.
- Reference the originating issue with `Refs #123` or `Closes #123`.
- Wrap at 72 columns. The pre-push hook does not enforce this but reviewers
  will ask.

Do **not** add `Co-Authored-By: Claude` trailers or
`🤖 Generated with Claude Code` footers. Even when the bulk of a PR was
machine-generated, the contributor signs for the work.

## Pull request flow

1. Fork, branch off `main`. Branch names: `feat/`, `fix/`, `docs/`,
   `refactor/`, matching the commit type.
2. One feature per PR. A 20-file PR that mixes a new check, a refactor, and
   a docs cleanup will be asked to split.
3. Keep commits in the PR meaningful. Squashing 12 "wip" commits into one
   well-written commit is part of the work.
4. CI must be green before request for review. `ci` and `govulncheck` are
   the two required workflows.
5. Re-request review after every push that addresses feedback. Don't make
   reviewers go hunting.

## What gets accepted vs. what doesn't

**Yes:**
- New checks for the providers we already ship (DigitalOcean, Linux), as
  long as they map cleanly to a framework control.
- Bug fixes to existing checks with a regression test.
- Documentation fixes and additions.
- Performance improvements with `go test -bench` numbers.
- Framework mappings for existing checks against frameworks already shipped.
- Translations of error messages and CLI strings -- but only after v0.5
  when the wording stabilizes.

**No, or not yet:**
- New providers before the version that's slated to add them (see
  [ROADMAP.md](ROADMAP.md)). Shipped: AWS at v0.7, GCP at v0.8,
  DigitalOcean depth pass at v0.9 (74 checks, every DO surface
  except DOKS), Hetzner at v0.10 (15 checks). Next: K8s +
  EKS/GKE/DOKS at v0.11. Tail clouds (Cloudflare, GitHub, Google
  Workspace, Vercel, Linode, Vultr) at v2.6 (re-slotted from v1.11 per ADR-016 — v1.x reserved for server / UI / UX / backend / CLI polish). Pulling any planned
  milestone forward needs a conversation -- the sequence is locked
  in [DECISIONS.md ADR-007](DECISIONS.md).
- New output formats. Five reporters at v0.4 is enough; a new format
  needs an ADR.
- Adding new lint rules to `.golangci.yaml`. Suppressing existing rules
  needs an in-line reason and a maintainer sign-off.
- Reformatting / rewriting working code for stylistic reasons.

## Security

If you find a vulnerability **do not open a public issue**. See
[SECURITY.md](SECURITY.md) for the disclosure process.

## License

By contributing you agree your changes are released under the same license
as the project. See LICENSE.
