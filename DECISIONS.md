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
- Rego adoption at v0.16 is a new `Evaluator` impl, not a check-signature change. (Originally slated for v0.13; moved to v0.16 per ADR-007 cloud-sequencing pivot.)

---

## ADR-002 — Policy DSL is Rego, landing at v0.16
**Date:** 2026-05-13
**Status:** Accepted

### Question
Stay Go-only forever, or add a policy DSL? If a DSL, which — Rego (OPA), CEL, Cloud Custodian's YAML, or our own?

### Decision
Add Rego at v0.16. Until then, Go-only checks. The `Evaluator` interface is shaped so a `RegoEvaluator` slots in without touching existing checks. (Originally planned for v0.13; rescheduled to v0.16 by ADR-007 to make room for AWS / GCP / DigitalOcean depth / Hetzner ahead of it.)

### Reasoning
- Rego is the industry standard: Trivy, KICS, Terrascan, Gatekeeper, Conftest all use it. Security teams already know it.
- Go-only at v0.1 keeps the surface small. We can hand-write 50 checks in Go before the boilerplate hurts; that buys us through v0.5.
- Rego lowers the contributor bar — a community PR for a new check becomes 10 lines of Rego, not 100 lines of Go + tests + fixtures.
- CEL is more ergonomic but less established in the compliance space.
- A homegrown DSL is a forever-tax we don't want to pay.

### Rejected alternatives
- **Rego from v0.1.** Adds the OPA dependency and a parallel codepath before we have proof anyone will write a check. Defer.
- **CEL.** Better syntax, smaller adoption. If Rego turns out to be a bad fit at v0.16, CEL is the fallback.
- **Cloud Custodian–style YAML policy.** Couples policy to action; we want them separable.
- **Stay Go-only forever.** Caps contributor velocity. Hard no.

### Consequences
- v0.1 `Check` and `Evaluator` interfaces must not assume Go-native logic. A check is metadata + a reference to *something that produces findings* — initially a Go function, eventually a Rego policy.
- v0.16 is a real release, not a refactor — by then we'll have ~150 Go checks across DO, AWS, GCP, Hetzner, and Linux, and converting the simpler 40-50 to Rego validates the model.

---

## ADR-003 — OCSF output lands at v0.3, not v0.13
**Date:** 2026-05-13
**Status:** Accepted

### Question
When do we ship JSON-OCSF (Open Cybersecurity Schema Framework)? Original roadmap had it implicit in v0.13's "ingest + emit" milestone (originally numbered v0.10 before the ADR-007 reorder).

### Decision
Ship JSON-OCSF as a first-class output format at v0.3, alongside SARIF.

### Reasoning
- OCSF is the emerging standard for cybersecurity event interchange — backed by AWS, Splunk, IBM, Cloudflare. Prowler already emits it.
- Retrofitting OCSF means revisiting every reporter's data shape; doing it once, early, while the shape is malleable, is cheap.
- "SARIF + OCSF + JSON + HTML + Markdown" is the right output portfolio. Anything less leaves a downstream SIEM user stuck.

### Rejected alternatives
- **Defer to v0.13.** Cheap now, expensive later. Rejected.
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
- v0.15 ships remediation *generators* (Bash/Terraform/Ansible/aws/gcloud/doctl/hcloud snippets the human applies). The leap from "generated snippet" to "applied snippet" is small in code, large in trust — hence the v2.x gate. (Originally slated for v0.12; rescheduled to v0.15 by ADR-007.)

### Rejected alternatives
- **Never.** Caps the project's long-term value ceiling.
- **At v0.x or v1.x.** Premature — credibility comes from being right about findings first, then being trusted to act on them.

### Consequences
- v0.15 must produce machine-applicable remediation artifacts (not just human prose) so v2.x's `--apply-fix` reuses them.
- v2.x ships with `compliancekit remediate --dry-run` as the default; `--apply` requires both `--yes-i-mean-it` and explicit resource-level allowlist in config.

---

## ADR-007 — Cloud sequencing: AWS, GCP, DigitalOcean depth before Hetzner
**Date:** 2026-05-14 (post-v0.5 launch)
**Status:** Accepted

### Question
The pre-launch roadmap had Hetzner at v0.7, Containers + K8s at v0.8, and AWS / GCP / Cloudflare / Vercel / Linode / Vultr collapsed into a single v1.7 "more clouds" milestone. Is that the right order after the v0.5 launch signal?

### Decision
Re-sequence v0.6 → v1.0 so the cloud arc lands as:

| Slot | Was | Now |
|---|---|---|
| v0.7 | Hetzner | **AWS** |
| v0.8 | Containers + K8s | **GCP** |
| v0.9 | Framework expansion | **DigitalOcean deepening** |
| v0.10 | IaC / OCSF / OSCAL ingest | **Hetzner** |
| v0.11 | Vuln / secret / SCA ingest | Containers + K8s + EKS / GKE / DOKS-deep |
| v0.12 | Remediation generators | Framework expansion (NIST / HIPAA / PCI / ATT&CK) |
| v0.13 | Rego DSL | IaC / OCSF / OSCAL ingest |
| v0.14 | Notifications | Vuln / secret / SCA ingest |
| v0.15 | Waivers | Remediation generators |
| v0.16 | (not previously numbered) | Rego policy DSL |
| v0.17 | (not previously numbered) | Notifications |
| v0.18 | (not previously numbered) | Waivers + skip annotations |

The old v1.7 "more clouds" entry collapses: AWS and GCP land at v0.7-v0.8 as first-class providers. The tail (Cloudflare, GitHub, Workspace, Vercel, Linode, Vultr) stays at v1.7 as a smaller "expand-the-tail" milestone. v1.0 (API stability) is unchanged.

### Reasoning
- The v0.5 HN launch was the first real audience-selection event. The single most common feedback theme — outpacing every other category combined — was *"would love to use this but we're on AWS."* Same indie-SaaS demographic that put compliancekit on the map, different provider.
- GCP fits the same pattern. The "we're portable, but on GCP at the moment" SaaS shops are the same readership. Pairing AWS (v0.7) and GCP (v0.8) in successive releases lets the cloud-common abstractions amortise — region/account attribution, SDK client pooling, OIDC auth shape — instead of getting two cold-start cloud collectors 18 months apart.
- DigitalOcean owes its audience a depth pass. Five DO checks was enough to launch; a real DO production fleet has Spaces, LBs, VPCs, managed DBs, App Platform, DOKS, Container Registry. v0.9 catches up so the audience that funded the launch is not left at the v0.5 surface for two years.
- Hetzner is still in scope. It moves to v0.10 — after the AWS / GCP / DO arc — because (a) it serves the same indie-cloud demographic that already gets value from v0.5 DO support, and (b) the cloud abstractions established at v0.7-v0.9 absorb the Hetzner-specific bits in much less time than going Hetzner-first would.
- K8s + EKS / GKE / DOKS-deep moves from v0.8 to v0.11 because EKS / GKE / DOKS each meaningfully need their owning cloud's collector. Shipping K8s before any of those clouds means shipping a kubeconfig-only scanner and then refactoring three times when each cloud lands. Landing K8s after all four clouds means one coherent K8s arc with cloud-specific glue per provider.

### Rejected alternatives
- **Stay the pre-launch course.** Rejected. The HN signal was too specific to ignore, and the cost of pivoting is one ADR plus a roadmap rewrite.
- **Pull only AWS forward, leave GCP and DO-deep where they were.** Rejected. The SDK amortisation argument requires GCP while the AWS abstractions are fresh in the code and in our heads. Splitting GCP out by 18 months loses the amortisation.
- **Front-load every cloud (AWS + GCP + Hetzner + DO-deep at v0.7 as one release).** Rejected. v0.7 already risks a two-weekend budget; a four-cloud v0.7 risks two months.
- **Pull K8s forward to v0.7.5 as a generic-K8s-only release.** Rejected. Cloud-specific K8s is the value; a generic kubeconfig scanner without IRSA / Workload Identity / DOKS-specific glue is a half-finished feature.

### Consequences
- The "v1.7 more clouds" milestone shrinks to just the tail (Cloudflare, GitHub, Workspace, Vercel, Linode, Vultr).
- The previously deferred *AWS provider depth* open question is now answered: depth at v0.7 is "the 30 highest-leverage checks that map cleanly to the three shipping frameworks." Full scope enumerated in ROADMAP.md v0.7.
- ADR-002 (Rego policy DSL) shifts from v0.13 to v0.16. The interface design and the rationale are unchanged; only the release slot moves. The `Evaluator` seam from v0.1 still pays off, just three minor versions later.
- ADR-003 (OCSF) is unaffected on the *emit* side (shipped at v0.3). The *ingest* side moves from the old v0.10 slot to v0.13 alongside the rest of the ingest work.
- ADR-006 (auto-remediation at v2.x) is unaffected directly, but v0.15 (remediation *generators*, the v2.x prerequisite) moves from v0.12 to v0.15.
- Downstream consumers who were waiting for AWS at v1.7 now see it at v0.7. Strict improvement.
- Downstream consumers who were waiting for Hetzner at v0.7 now wait until v0.10. The cost of the pivot.
- The README "Providers" table and the FAQ are rewritten in lockstep so the public marketing matches the engineering schedule.

---

## Open questions (not yet decided)

- **Plugin host model:** subprocess gRPC (Terraform-provider pattern), WASM via wazero, or both? Decision at v2.0.
- **Storage backend default for `serve`:** SQLite or Postgres? Probably SQLite default, Postgres opt-in. Decide at v1.1.
- **CIS Certification pursuit:** worth the paperwork for credibility? Decide post-launch once audience traction is known.
- **Web UI framework for `serve`:** server-rendered HTML (htmx?) vs. a real SPA. Stay server-rendered as long as we can.
