# Security Policy

compliancekit is a security tool. Vulnerabilities in it directly weaken the
posture of every organisation that runs it, so we take reports seriously
and respond quickly.

## Supported versions

| Version  | Status         | Security fixes |
|----------|----------------|----------------|
| `0.5.x`  | active         | yes            |
| `0.4.x`  | last minor     | yes (60 days)  |
| `< 0.4`  | unsupported    | no             |

Once compliancekit reaches `1.0` we will commit to maintaining the previous
major for 12 months in addition to the active one.

## What counts as a vulnerability

The non-exhaustive list:

- Code execution in the compliancekit binary triggered by attacker-controlled
  input (a malformed `findings.json`, a malicious `inventory.yaml`, a
  poisoned godo response).
- Path traversal or directory escape from the evidence pack writer.
- Disclosure of secrets in scan output, logs, or evidence packs that the
  redactor should have masked.
- Bypasses of the framework / severity gating in CI -- e.g. a finding that
  should produce exit code 2 but does not.
- SSH transport flaws that downgrade host-key verification or accept
  unauthenticated connections.
- Supply-chain issues: a release with a tampered binary, a broken cosign
  signature, an SBOM that omits a real dependency.

Bug-bounty-style findings outside the scope above (general DoS via large
inputs, slow loris on the future `serve` mode at v1.1, etc.) are valid bug
reports but go to the public issue tracker, not the disclosure channel
below.

## How to report

Use **GitHub Private Vulnerability Reporting** at:

> https://github.com/darpanzope/compliancekit/security/advisories/new

Or, if you cannot use GitHub: email **darpanzope@gmail.com** with the
subject prefix `[compliancekit-security]`. We do not run a separate
security mailbox at this time.

Please include:

1. The compliancekit version (`compliancekit version`).
2. A minimal reproducer -- a script, a sample input file, exact CLI flags.
3. Your assessment of impact and a CVSSv3.1 score if you have one
   (we will compute one ourselves either way).
4. Whether you intend to publish, and on what timeline.

Do **not** open a public issue, do **not** include the reproducer in a
public PR, and do **not** post on the project's Discussions tab before
coordinated disclosure.

## Our response process

| When                      | What                                                                |
|---------------------------|---------------------------------------------------------------------|
| within 3 working days     | acknowledge receipt, assign a tracking ID                           |
| within 7 working days     | confirm or dispute the vulnerability                                |
| within 14 working days    | propose a fix and a disclosure timeline                             |
| at coordinated disclosure | publish a security advisory, ship a patch release, credit reporter |

The default disclosure window is **45 days** from confirmation. We will
ask for an extension on findings that need an upstream fix (a Go stdlib
issue, a `godo` change) and proactively cut it short when the bug is
already being exploited in the wild.

## Credit

We credit every researcher who reports a confirmed vulnerability in the
release notes and in the relevant security advisory. If you would prefer
to remain anonymous, say so in your initial report.

## Out of scope

- The Homebrew tap, GitHub Action, and Docker image at `ghcr.io/darpanzope/
  compliancekit` are first-party but are released by the same goreleaser
  pipeline as the binaries; report issues against them here.
- Misconfigurations in *your* compliancekit deployment (an unprotected
  evidence pack served from a public S3 bucket, say) are operational
  issues, not vulnerabilities -- unless the misconfiguration is the
  documented default.

## Hardening defaults we already ship

- The evidence pack redacts AWS access keys, GitHub PATs, Slack tokens,
  bearer headers, and email addresses by default; `--include-raw` is the
  documented opt-out.
- `MANIFEST.sha256` covers every file in the pack; tampering after the
  fact is detectable with `sha256sum -c MANIFEST.sha256`.
- Releases are cosign-signed (keyless via GitHub OIDC) and ship with a
  Syft-generated SBOM.
- The binary is `CGO_ENABLED=0`-built and statically linked, eliminating
  an entire class of dynamic-linker attacks.
- `govulncheck` runs on every CI build against the call graph; vulnerable
  stdlib paths block merge.
