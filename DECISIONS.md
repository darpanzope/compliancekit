# Decisions

A running ledger of load-bearing decisions. Each entry has a question, a chosen answer, the reasoning, and the alternatives we rejected. New decisions append; we never silently rewrite history.

Format: ADR-lite. If something here is wrong, fix it here first, then change the code.

---

## ADR-001 — Resource graph designed in at v0.1
**Date:** 2026-05-13
**Status:** Accepted

### Question
Do we ship v0.1 as the natural "Provider fetches → checks emit Findings" shape and refactor at v0.6, or do we split `Collector` (fetch) from `Evaluator` (check) from day one?

### Decision
Split at v0.1. A typed `Resource` graph sits between `Collector` and `Evaluator`. Even with one provider and ten checks, the seam exists.

### Reasoning
- The natural v0.1 shape works for 10 checks. By v0.6 we will want: check-level fact reuse (two checks reading the same droplet shouldn't trigger two API calls), cross-resource queries ("every droplet must belong to a firewall with rule X"), and a place for Rego policies to read from.
- All three of those are trivial against a graph and painful against per-check fetches.
- Cost of doing this at v0.1: ~50 lines of extra code and one extra interface. Cost of retrofitting at v0.6: a multi-day refactor that touches every check.
- Pay the small cost now.

### Rejected alternatives
- **Ship the simple shape, refactor at v0.6.** Tempting but historically these refactors get deferred indefinitely. The check catalogue grows, the refactor grows, the refactor never happens.
- **Skip the graph, use Steampipe as our collector.** Considered — Steampipe already wraps DigitalOcean. Rejected because it adds a Postgres dependency, breaks the single-binary promise, and ties our scan model to someone else's release cadence.

### Consequences
- v0.1 ships with `Collector` and `Evaluator` interfaces. `Provider` is retired as a concept; what was "the DO provider" is now "the DO collector plus a set of DO checks."
- Rego adoption at v0.13 is a new `Evaluator` impl, not a check-signature change.

---

## ADR-002 — Policy DSL is Rego, landing at v0.13
**Date:** 2026-05-13
**Status:** Accepted

### Question
Stay Go-only forever, or add a policy DSL? If a DSL, which — Rego (OPA), CEL, Cloud Custodian's YAML, or our own?

### Decision
Add Rego at v0.13. Until then, Go-only checks. The `Evaluator` interface is shaped so a `RegoEvaluator` slots in without touching existing checks.

### Reasoning
- Rego is the industry standard: Trivy, KICS, Terrascan, Gatekeeper, Conftest all use it. Security teams already know it.
- Go-only at v0.1 keeps the surface small. We can hand-write 50 checks in Go before the boilerplate hurts; that buys us through v0.5.
- Rego lowers the contributor bar — a community PR for a new check becomes 10 lines of Rego, not 100 lines of Go + tests + fixtures.
- CEL is more ergonomic but less established in the compliance space.
- A homegrown DSL is a forever-tax we don't want to pay.

### Rejected alternatives
- **Rego from v0.1.** Adds the OPA dependency and a parallel codepath before we have proof anyone will write a check. Defer.
- **CEL.** Better syntax, smaller adoption. If Rego turns out to be a bad fit at v0.13, CEL is the fallback.
- **Cloud Custodian–style YAML policy.** Couples policy to action; we want them separable.
- **Stay Go-only forever.** Caps contributor velocity. Hard no.

### Consequences
- v0.1 `Check` and `Evaluator` interfaces must not assume Go-native logic. A check is metadata + a reference to *something that produces findings* — initially a Go function, eventually a Rego policy.
- v0.13 is a real release, not a refactor — by then we'll have ~100 Go checks, and converting the simpler 30-40 to Rego validates the model.

---

## ADR-003 — OCSF output lands at v0.3, not v0.10
**Date:** 2026-05-13
**Status:** Accepted

### Question
When do we ship JSON-OCSF (Open Cybersecurity Schema Framework)? Original roadmap had it implicit in v0.10's "framework expansion."

### Decision
Ship JSON-OCSF as a first-class output format at v0.3, alongside SARIF.

### Reasoning
- OCSF is the emerging standard for cybersecurity event interchange — backed by AWS, Splunk, IBM, Cloudflare. Prowler already emits it.
- Retrofitting OCSF means revisiting every reporter's data shape; doing it once, early, while the shape is malleable, is cheap.
- "SARIF + OCSF + JSON + HTML + Markdown" is the right output portfolio. Anything less leaves a downstream SIEM user stuck.

### Rejected alternatives
- **Defer to v0.10.** Cheap now, expensive later. Rejected.
- **Skip OCSF, OCSF will lose to something else.** Possible but unlikely given the backers. Bet on it.

### Consequences
- v0.3 reporter layer has OCSF mapping baked into Finding → output translation.
- Future Finding fields (MITRE ATT&CK techniques, confidence scores) must remain OCSF-mappable.

---

## ADR-004 — GRC layer is in scope, at v1.4
**Date:** 2026-05-13
**Status:** Accepted

### Question
Are we a pure technical scanner, or do we also ship lightweight GRC features (risk register, vendor register, CAIQ/SIG response templates, training tracking)? This is the largest scope question.

### Decision
GRC is in scope, at v1.4 — after scanning maturity is established. Lightweight, CSV/YAML-driven, no HRIS ambitions.

### Reasoning
- Drata, Vanta, and Secureframe's actual moat isn't scanning — it's the GRC workflows. If we want to be a credible alternative to the $20k-100k/yr SaaS for small teams, we have to address this.
- Earning technical credibility first protects us from being miscategorized as "yet another GRC tool." Scanner-first, GRC-second.
- The GRC layer in OSS form is unambitious in scope: CSV-driven risk register, vendor register, policy templates, questionnaire response markdown. No personnel HRIS, no training LMS — we cite tools that already do those.
- This is the feature set that turns "interesting tool" into "we cancelled our Drata subscription."

### Rejected alternatives
- **Stay strictly a scanner forever.** Caps our addressable problem. Half the SOC 2 prep work is non-technical.
- **Ship GRC at v0.5 alongside launch.** Premature — would dilute the launch narrative.

### Consequences
- v1.4 introduces a `register/` directory convention (risks.yaml, vendors.yaml, etc.) and a markdown library for policies and questionnaire responses.
- Trust Center (v1.3) and Auditor Portal (v1.5) are designed knowing the GRC layer lands at v1.4.

---

## ADR-005 — `serve` mode is optional forever
**Date:** 2026-05-13
**Status:** Accepted

### Question
Is `compliancekit serve` (continuous monitoring daemon) a future requirement, or is the CLI always sufficient?

### Decision
`serve` is optional, forever. The CLI is the source of truth — every feature ships to CLI first, then daemon. Daemon mode is a deployment convenience, not a feature gate.

### Reasoning
- The audience is OSS-flavored DevOps teams. "Run a daemon" is a configuration burden for many of them. A cron job calling the binary should always be a valid deployment.
- Daemon-mandatory tools (Wazuh, Trivy Operator) are great for their audience but ours skews lighter.
- Day-1 internal interfaces are still designed daemon-aware: no package-level globals, every long-lived path takes `context.Context`. This makes v1.1's `serve` a feature add, not a rewrite.

### Rejected alternatives
- **Daemon-mandatory at v1.x.** Cuts the audience.
- **CLI-only forever.** Closes off the auditor-portal and continuous-drift-alert use cases that matter for v1.x.

### Consequences
- v0.1 code must use `context.Context` end-to-end. No init-time singletons.
- v1.1's `serve` ships as `compliancekit serve [--port=...]`. Same binary. Same checks. Same output formats. Just a different entry point.

---

## ADR-006 — Auto-remediation is opt-in at v2.x
**Date:** 2026-05-13
**Status:** Accepted

### Question
Is auto-remediation (the tool actually fixes findings, not just reports them) ever in scope? ARCHITECTURE.md previously said "explicit non-goal for v0.x."

### Decision
Opt-in at v2.x. Permanently behind `--apply-fix` or `--yes-i-mean-it`. Dry-run by default. Full audit log. Resource-level allowlists required.

### Reasoning
- Cloud Custodian proves the model: declarative scan + opt-in act. Useful for some teams, terrifying for others.
- The single feature that turns a SaaS subscription into a one-time install is the one where the tool can *close* findings, not just identify them.
- Permanently splitting the project into "audit-only" (default, safe) and "act-on-it" (advanced) keeps the safety invariant intact: someone who just installs the binary cannot accidentally mutate their infrastructure.
- v0.12 ships remediation *generators* (Bash/Terraform/Ansible/doctl snippets the human applies). The leap from "generated snippet" to "applied snippet" is small in code, large in trust — hence the v2.x gate.

### Rejected alternatives
- **Never.** Caps the project's long-term value ceiling.
- **At v0.x or v1.x.** Premature — credibility comes from being right about findings first, then being trusted to act on them.

### Consequences
- v0.12 must produce machine-applicable remediation artifacts (not just human prose) so v2.x's `--apply-fix` reuses them.
- v2.x ships with `compliancekit remediate --dry-run` as the default; `--apply` requires both `--yes-i-mean-it` and explicit resource-level allowlist in config.

---

## Open questions (not yet decided)

- **Plugin host model:** subprocess gRPC (Terraform-provider pattern), WASM via wazero, or both? Decision at v2.0.
- **Storage backend default for `serve`:** SQLite or Postgres? Probably SQLite default, Postgres opt-in. Decide at v1.1.
- **CIS Certification pursuit:** worth the paperwork for credibility? Decide post-launch once audience traction is known.
- **Web UI framework for `serve`:** server-rendered HTML (htmx?) vs. a real SPA. Stay server-rendered as long as we can.
- **AWS provider depth:** Prowler-parity is out of scope. Where exactly do we stop? Defer to v1.7.
