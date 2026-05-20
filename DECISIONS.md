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
**Status:** Resolved — implemented at v0.16 (2026-05-15). See [ADR-012](#adr-012--rego-is-embedded-via-opas-go-library-not-shelled-out) for the embedded-OPA implementation choice.

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
**Status:** Resolved — v0.13 closed the loop (2026-05-15)

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

### Resolution at v0.13
The original v0.3 framing was emit-only. v0.13 finished what the original
"OCSF is no longer just an output, it is a wire format" goal pointed at:

- OCSF emit was enriched (Phase 3) to populate `finding_info.{title,desc,types}`,
  `compliance.{standards,requirements}`, resource `region` + `cloud.account`,
  and a `unmapped.compliancekit_source` slot preserving the original Finding's
  Source struct.
- An OCSF ingest adapter (Phase 2) was added that reads AWS Security Hub,
  GCP SCC, and Defender for Cloud OCSF exports.
- A round-trip test proves `compliancekit native → OCSF emit → OCSF ingest`
  recovers every load-bearing Finding field including the diff engine's
  Fingerprint.

OCSF is now genuinely a wire format. ADR closed.

---

## ADR-004 — GRC layer is in scope, at v2.3
**Date:** 2026-05-13 (slot renumbered v1.4 → v1.6 on 2026-05-18 [v1.1 CLI + v1.2 HTML wedge], then v1.6 → v1.8 on 2026-05-18 [v1.3 serve + v1.4 studio + v1.5 explorer wedge], then v1.8 → v2.3 on 2026-05-18 [v1.6-v1.17 server/UI/UX polish reservation — see ADR-016])
**Status:** Accepted

### Question
Are we a pure technical scanner, or do we also ship lightweight GRC features (risk register, vendor register, CAIQ/SIG response templates, training tracking)? This is the largest scope question.

### Decision
GRC is in scope, at v2.3 — after scanning maturity is established **and** after the v1.x server / UI/UX / backend / CLI polish reservation (ADR-016) completes. Lightweight, CSV/YAML-driven, no HRIS ambitions.

### Reasoning
- Drata, Vanta, and Secureframe's actual moat isn't scanning — it's the GRC workflows. If we want to be a credible alternative to the $20k-100k/yr SaaS for small teams, we have to address this.
- Earning technical credibility first protects us from being miscategorized as "yet another GRC tool." Scanner-first, GRC-second.
- The GRC layer in OSS form is unambitious in scope: CSV-driven risk register, vendor register, policy templates, questionnaire response markdown. No personnel HRIS, no training LMS — we cite tools that already do those.
- This is the feature set that turns "interesting tool" into "we cancelled our Drata subscription."

### Rejected alternatives
- **Stay strictly a scanner forever.** Caps our addressable problem. Half the SOC 2 prep work is non-technical.
- **Ship GRC at v0.5 alongside launch.** Premature — would dilute the launch narrative.

### Consequences
- v2.3 introduces a `register/` directory convention (risks.yaml, vendors.yaml, etc.) and a markdown library for policies and questionnaire responses.
- Trust Center (v2.2) and Auditor Portal (v2.4) are designed knowing the GRC layer lands at v2.3.

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
- Day-1 internal interfaces are still designed daemon-aware: no package-level globals, every long-lived path takes `context.Context`. This makes v1.3's `serve` a feature add, not a rewrite.

### Rejected alternatives
- **Daemon-mandatory at v1.x.** Cuts the audience.
- **CLI-only forever.** Closes off the auditor-portal and continuous-drift-alert use cases that matter for v1.x.

### Consequences
- v0.1 code must use `context.Context` end-to-end. No init-time singletons.
- v1.3's `serve` ships as `compliancekit serve [--port=...]`. Same binary. Same checks. Same output formats. Just a different entry point.

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
The pre-launch roadmap had Hetzner at v0.7, Containers + K8s at v0.8, and AWS / GCP / Cloudflare / Vercel / Linode / Vultr collapsed into a single v1.7 "more clouds" milestone (the slot moved v1.7 → v1.11 on 2026-05-18 [CLI/HTML/serve/studio/explorer wedges], then v1.11 → v2.6 on 2026-05-18 [ADR-016 v1.x server/UI/UX reservation] — described historically here as v1.7 to preserve the pre-pivot terminology). Is that the right order after the v0.5 launch signal?

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

The old v1.7 "more clouds" entry collapses: AWS and GCP land at v0.7-v0.8 as first-class providers. The tail (Cloudflare, GitHub, Workspace, Vercel, Linode, Vultr) stays in the same slot — now numbered v2.6 (after ADR-016's v1.x reservation) — as a smaller "expand-the-tail" milestone. v1.0 (API stability) is unchanged.

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
- The "v1.7 more clouds" milestone (renumbered v1.9 on 2026-05-18 [CLI/HTML wedge], then v1.11 on 2026-05-18 [serve/studio/explorer wedge], then v2.6 on 2026-05-18 [ADR-016 v1.x server/UI/UX reservation]) shrinks to just the tail (Cloudflare, GitHub, Workspace, Vercel, Linode, Vultr).
- The previously deferred *AWS provider depth* open question is now answered: depth at v0.7 is "the 30 highest-leverage checks that map cleanly to the three shipping frameworks." Full scope enumerated in ROADMAP.md v0.7.
- ADR-002 (Rego policy DSL) shifts from v0.13 to v0.16. The interface design and the rationale are unchanged; only the release slot moves. The `Evaluator` seam from v0.1 still pays off, just three minor versions later.
- ADR-003 (OCSF) is unaffected on the *emit* side (shipped at v0.3). The *ingest* side moves from the old v0.10 slot to v0.13 alongside the rest of the ingest work.
- ADR-006 (auto-remediation at v2.x) is unaffected directly, but v0.15 (remediation *generators*, the v2.x prerequisite) moves from v0.12 to v0.15.
- Downstream consumers who were waiting for AWS at v1.7 now see it at v0.7. Strict improvement.
- Downstream consumers who were waiting for Hetzner at v0.7 now wait until v0.10. The cost of the pivot.
- The README "Providers" table and the FAQ are rewritten in lockstep so the public marketing matches the engineering schedule.

---

## ADR-008 — Hardening score is a single 0-100 number with fixed severity weights
**Date:** 2026-05-14 (v0.6 design)
**Status:** Accepted

### Question
The v0.6 milestone introduces a "hardening score." What's the formula? Is it configurable? How does it handle skips and errors?

### Decision
Ship a single 0-100 integer score with **fixed severity weights** at v0.6. Skips are excluded from both numerator and denominator; errors count against the score the same way fails do; pass is the only positive contributor.

Formula:
```
weights = { critical: 50, high: 20, medium: 8, low: 3, info: 1 }

evaluable_findings = [f for f in findings if f.status != skip]
total_weight       = sum(weights[f.severity] for f in evaluable_findings)
passing_weight     = sum(weights[f.severity] for f in evaluable_findings if f.status == pass)

if total_weight == 0: score = 100
else:                 score = round(100 * passing_weight / total_weight)
```

A parallel `coverage` metric reports the fraction of findings that were evaluable (i.e. not skipped) so the operator can tell a 100/100 from "everything skipped."

### Reasoning
- **Single number is the point.** v0.6's headline is "your score went from 78 to 73 since Friday." A multi-dimensional score (one per framework, plus a coverage, plus a per-severity bar) is more accurate but less actionable. We ship the simple number on the surface and keep the breakdown one CLI flag away (`--score-detail`).
- **Fixed weights at v0.6.** Configurability is tempting but breaks the cross-fleet comparison story. Two compliancekit users with different weight configs cannot meaningfully compare scores. Lock the weights now; revisit after community pressure if it comes.
- **The weight curve (50 / 20 / 8 / 3 / 1) is non-linear on purpose.** A single critical finding should obviously hurt more than the same number of low-severity findings. A linear curve (5/4/3/2/1) flattens the signal; the chosen curve is roughly log-ish and matches how operators triage.
- **Skips excluded** because they reflect "we couldn't evaluate" — neither a pass nor a fail. Counting them as passes inflates the score for misconfigured scans; counting them as fails punishes operators for things they didn't break. Excluding them keeps the number honest.
- **Errors count as fails** because an error is a failure of the scan, not a successful pass. The operator must investigate either way.

### Rejected alternatives
- **Configurable weights via `compliancekit.yaml`.** Rejected at v0.6. Breaks cross-fleet comparison. A future v0.X may reintroduce as `score.profile = strict|balanced|lenient` with the weights bound to the profile name, keeping comparisons honest.
- **Per-framework scores.** Rejected — multiplies the surface, dilutes the headline. The evidence pack already breaks findings down per framework; the score is the cross-framework rollup.
- **A 0.0-1.0 float or 0-1000 fine-grained score.** Rejected — the integer 0-100 fits the "I went from 78 to 73" use case and is what every dashboard reader expects.
- **Award credit for fail findings that have a waiver.** Rejected at v0.6. Waivers don't land until v0.18; designing the score around them now is premature.

### Consequences
- v0.6 ships `internal/score/` as a small, pure package. Inputs: `[]compliancekit.Finding`. Outputs: `{Score int, Coverage int, Total, Passing, Failing, Skipped int}`.
- The number is deterministic by construction — identical input produces identical output. Tests pin this with table-driven cases.
- The number is monotonic by construction — converting a fail to a pass cannot decrease the score; converting a pass to a fail cannot increase it.
- v0.7 (AWS) and v0.8 (GCP) inherit the same weights automatically because severity is provider-agnostic. No re-tuning per cloud.
- The HTML reporter and the evidence pack `summary.html` show the score as the most prominent metric. The CLI `scan` footer prints it on its own line.
- Baseline files (v0.6 phase 3) record the score so `diff` (v0.6 phase 4) can render the delta: "76 → 73 (-3)."

---

## ADR-009 — Vulnerability scanning is composed, not native
**Date:** 2026-05-15 (v0.13 wrap)
**Status:** Accepted

### Question
Should compliancekit grow a native CVE / vulnerability scanner — its own NVD / OSV / GHSA mirror, its own package-version resolver, its own container-image layer extractor — or should the project stay in the composition lane and ingest other tools' output?

### Decision
**Composition, not detection.** compliancekit ingests Trivy / Grype / Checkov / gitleaks / AWS Security Hub / GCP SCC / Defender for Cloud output through the v0.13 ingest pipeline. We do not maintain a native CVE database, package-version resolver, or container layer parser. The value compliancekit adds is joining external findings to cloud resources + framework controls, not enumerating the CVEs in the first place.

### Reasoning
- **Maintainer cost is the dominant constraint.** A real CVE detector requires daily ETL across NVD / GHSA / OSV / Red Hat / Debian / Ubuntu / Alpine, ecosystem-specific package version parsers (dpkg/rpm/apk/npm/pip/gem/cargo/Go-modules/Maven), and OCI image layer extraction. Trivy and Grype have paid teams behind them; an indie OSS project should not try to compete on detection quality.
- **The audience already runs Trivy.** Every customer profile we care about — SOC 2-ready SaaS, FedRAMP-curious shop, indie cloud-native team — has Trivy or an equivalent in CI already. Asking them to swap to a compliancekit-native scanner makes the value proposition harder, not easier.
- **Our actual differentiation is the join.** Trivy says "image X has CVE-Y." Only compliancekit can say "image X has CVE-Y, runs on droplet Z in SOC 2 CC7.1 scope, the operator's tailoring justification for CC7.1 carries over, and here's the evidence pack with the finding pinned to NIST SI-2 + ISO A.8.8 + PCI 6.3 alongside compliancekit's native posture findings on the same droplet." The join is the moat; detection is commodity.
- **Audit reality.** Auditors don't reward "one tool that finds CVEs." They reward evidence that the operator runs a vuln scanner and remediates against a policy. compliancekit's role is the policy + control attribution + evidence trail — not the scanner.
- **Scope discipline.** v0.12 + v0.13 already ship 298 native checks × 7 frameworks × 6 providers + 3 ingest formats + 2 OSCAL emits. Adding a native CVE database multiplies maintenance work by an order of magnitude. Better to deepen what only compliancekit can do.

### Rejected alternatives
- **Vendor Trivy's CVE database code into the binary.** Rejected. Trivy is open source so we *could* legally do this, but the maintenance burden lands on us — daily DB refresh, ecosystem-parser updates, layer-extraction bug fixes. That is the actual cost.
- **Add a `compliancekit vuln` subcommand backed by a thin native wrapper around `osv-scanner` / `trivy fs`.** Rejected at v0.13. It still requires us to ship a particular scanner inside our binary, growing the supply-chain surface for marginal user benefit beyond what ingest already provides.
- **Native CVE-database mirror at v0.14, replacing the ingest path.** Rejected. The original v0.14 ROADMAP framing was already "ingest, not detection"; reversing that here would invalidate the v0.13 work and double the v0.14 scope.

### Consequences
- v0.13's ingest pipeline (SARIF / OCSF) is the canonical path for vulnerability findings entering compliancekit. v0.14 will extend the same pipeline with explicit adapters for Trivy / Grype / Checkov / gitleaks plus the `compliancekit.Finding.Vulnerability` + `compliancekit.Finding.Secret` typed metadata blocks so reporters render CVE IDs natively.
- The evidence pack's `vulnerabilities.csv` index (v0.14 deliverable) joins ingested vuln findings to the cloud resource graph by image SHA, package PURL, and ARN — the join we DO offer, layered over external detection we do not.
- The ROADMAP design-principle note "Vulnerability scanning is composed, not native" (ROADMAP.md §"Success metrics") is now load-bearing and codified as this ADR. Reopening this decision requires another ADR explicitly reversing it.

---

## ADR-010 — Secret redaction is mandatory; raw values never leave the producing tool
**Date:** 2026-05-15 (v0.14 wrap)
**Status:** Accepted

### Question
v0.14 ingests output from secret scanners (gitleaks, Trivy's secret detector). Every raw match a scanner reports IS the leaked credential, by definition. Where does that raw value live inside compliancekit, and what guarantees do we offer the operator that it stays bounded?

### Decision
**The raw secret value never enters compliancekit's data plane.** Adapters consume the producing tool's report, derive a non-reversible fingerprint via `ingest.RedactSecret`, and write only the fingerprint into `compliancekit.Finding.Secret.Fingerprint`. The raw value is never stored in a Finding field, written to a log line, embedded in an evidence-pack artifact, or transmitted across an HTTP boundary.

`ingest.RedactSecret` is the single canonical helper:

- Empty input → empty output.
- 16+ chars → first 4 + `"..."` + last 4. Preserves anchor characters for visual correlation across runs.
- < 16 chars → `"sha256:"` + first 12 hex of SHA-256(raw). Short secrets that survive first4+last4 redaction would leak too much identifying material; the hash collapses them.

Every adapter package (`internal/ingest/{trivy,gitleaks,...}/redact.go`) defines a one-line wrapper around `ingest.RedactSecret`. No adapter is permitted to roll its own redaction.

### Reasoning
- **Bounding the blast radius is the only credible posture.** Once a secret enters our process memory we cannot prove it stays there; we can however prove it never enters the persistent data plane. The bound is "we read and forget" rather than "we read and protect."
- **One algorithm across every adapter** is non-negotiable for the property to hold. If Trivy uses first4+last4 but gitleaks uses a hash, an operator running both gets inconsistent fingerprints, can't dedup across tools, and may incorrectly conclude two findings represent different secrets when they're the same.
- **Why fingerprint at all?** Operators need a stable identifier to (a) suppress duplicates across runs, (b) confirm rotation worked ("the old fingerprint is gone"). A raw hash works for that but loses visual anchorability — operators triaging see "sha256:abc..." for every secret and can't recognize at-a-glance which credential is which. The first4+last4 pattern is the field convention (AWS Console, GitHub's UI, Stripe dashboard all show it).
- **Why 16 chars as the threshold?** Below 16, first4+last4 leaks 8 chars out of <16 — half or more of the credential. SHA-256 collapse is safer for short secrets even though it loses anchorability.
- **Why not encryption?** Encryption requires a key; a key requires key management; key management is the problem we're trying not to add to compliancekit. Redaction is one-way and stateless.

### Rejected alternatives
- **Encrypt with a per-scan key.** Rejected. Requires key storage; raises the question of how to share the key with the auditor who wants to verify the finding; defeats the point of "never persist the raw value."
- **Truncate to first 8 chars only (no trailing).** Rejected. Many credential formats (AWS access keys, JWTs) have static prefixes — `AKIA` for AWS, `eyJ` for JWT. First-8-only would render every AWS key as `AKIAIOSF`, losing dedup. Last-4 anchors against the variable suffix.
- **Allow operators to set their own redaction function via plugin.** Rejected at v0.14. Convenient for power users but makes the property impossible to verify centrally. Revisit if the v2.0 plugin system lands and warrants it.
- **Make redaction opt-in.** Rejected, hard. Defaults that leak credentials are a security footgun nobody wants.

### Consequences
- `internal/ingest/redact.go` ships `RedactSecret` as the public, ADR-anchored helper. Every adapter aliases it.
- A property test in each adapter test suite confirms that known fixture secrets (`AKIAIOSFODNN7EXAMPLE`, etc.) never appear as substrings of the produced Finding's Fingerprint. This is the regression-proof layer for the redaction policy.
- `compliancekit.Finding.Secret.Fingerprint` doc-comment carries a redaction notice so future reporter authors know not to "enrich" it.
- `compliancekit ingest --format=gitleaks-json` will reject a payload where `Match` field is missing only if it would also have to fabricate a fingerprint; otherwise it produces an empty Fingerprint rather than guessing.
- The OCSF emit's `unmapped.compliancekit_secret` slot carries the redacted Secret struct verbatim — no additional transformation.

---

## ADR-011 — Remediation strategies are per-format Go, hand-written, generate-only
**Date:** 2026-05-15 (v0.15 kickoff)
**Status:** Accepted

### Question
v0.15 turns every finding into a copy-pasteable fix in the operator's tool of choice (Terraform, kubectl, aws/gcloud/az/doctl/hcloud CLI, Helm overlay, Ansible, bash). Three architectural shapes are plausible:

1. **Templates.** Strategies are go:embed text templates, one per (CheckID, Format). Easiest to author; weakest at expressing branching logic ("if KMS not present, also generate a Key resource").
2. **One method on each check.** `compliancekit.Check` gains `Remediate(Finding) -> Snippet`. Locality is great; every check carries its remediation. But the method has to know every output format, which forces format-specific logic into the check files.
3. **Per-format Go strategy packages.** `internal/remediate/<format>/` each registers Strategy implementations against the CheckIDs it can fix. Verbose but every output format owns its own correctness boundary and tests.

We also need to decide whether remediation can ever auto-apply (and if so, when), how risky changes are signaled, and what happens to findings without a strategy.

### Decision
**Per-format Go strategy packages, hand-written, generate-only.** Concretely:

- `internal/remediate/` ships a `Strategy` interface, a `Registry`, and the `Format` / `RiskClass` / `Snippet` value types.
- Each output format gets a subpackage (`internal/remediate/{terraform,kubectl,helm,ansible,bash,awscli,gcloud,azcli,doctl,hcloud}`) that registers strategies in `init()` against the CheckIDs it can fix.
- A Strategy declares `RiskClass` (safe / review / manual). `safe` snippets are idempotent and have no behavior change; `review` snippets change visible behavior; `manual` snippets cannot be rendered and route the finding to the OSCAL POA&M emitter for out-of-band remediation tracking.
- Strategies emit Snippets with `Content` + optional `VerifyCmd` + optional `RollbackCmd` + `Notes`. The runbook surfaces all four. Operators get the fix, plus a way to confirm it landed, plus a way to undo it.
- Remediation is GENERATION only. ADR-006 already established that `--apply-fix` is the v2.x trust gate; ADR-011 codifies the internal invariant: the binary writes files and exits, it never calls any cloud API or `kubectl apply`.
- Findings whose CheckID has no registered strategy fall through to POA&M as manual-action items. We never silently drop a finding from the remediation flow.

### Reasoning
- **Hand-written Go beats templates** for the bigger strategies (Terraform fixes that depend on the existing resource graph, kubectl patches that vary by Pod spec shape). The 5% of simple strategies that would be cleaner as templates aren't enough volume to justify a second authoring path.
- **Per-format subpackages over per-check methods** because the Strategy interface lets one strategy declare multiple CheckIDs and multiple Formats — a single `aws-s3-public-access` strategy can emit both Terraform and aws-cli for every flavor of S3-public finding. Putting that strategy on the check struct forces it into the wrong file and prevents reuse across check IDs.
- **`RiskClass` gates auto-apply forever.** Even when v2.x lands `--apply-fix`, the only safe class to default-apply is `safe`. `review` will require explicit per-resource allowlists. `manual` is never apply-able. Encoding the risk on the strategy (not on the runtime flag) means a contributor can't accidentally promote a manual fix to auto-apply by passing the wrong flag.
- **`VerifyCmd` separately from `Content`.** An operator who applies a remediation needs to confirm the fix landed without re-reading the original finding. The verify command is the cheapest possible audit trail entry: "I ran the fix, then ran the verify, both succeeded, here are the timestamps."
- **No silent drops.** If a finding has no strategy, the POA&M emitter surfaces it. Auditors want a paper trail showing "here are the findings we can't auto-fix and the human action assigned to each." Dropping unmatched findings would be operator-friendly but auditor-hostile.

### Rejected alternatives
- **Generic template engine (gotemplate / yaml.v3 marshaling).** Rejected. Operators paste these into production; subtle whitespace or quoting errors in templates land as broken Terraform or kubectl. Hand-written Go with the shared `internal/remediate/render` helpers gives us a static type system over the generated code.
- **Single `Remediate` method on each check.** Rejected. Forces every check author to learn 10 output formats. Strategies can be added incrementally without touching check files; the unit of contribution is "I know AWS CLI for IAM and added strategies for the 12 IAM CheckIDs."
- **Auto-apply at v0.15 behind `--apply-fix`.** Rejected. ADR-006 explicitly defers this to v2.x, and the v0.15 strategy-level `RiskClass` is the necessary prerequisite — we won't ship apply before we ship a way to tag fixes as auto-safe.
- **CheckID wildcards as the primary lookup mechanism.** Rejected. Wildcards exist (`CheckIDs() == ["*"]`) but only as a last-resort fallback for the "manual review" generic strategy. The primary path is exact CheckID match because the per-finding rendering needs the specific check semantics, not a generic "go fix this" template.

### Consequences
- `internal/remediate/remediate.go` defines `Strategy`, `Snippet`, `Format`, `RiskClass`, errors. `internal/remediate/registry.go` provides `Default` + `Register`.
- Each format subpackage's `init()` registers its strategies. The CLI in `internal/cli/remediate.go` side-effect-imports each subpackage so `compliancekit remediate` resolves every format with zero configuration.
- `internal/remediate/poam/` consumes `unmatched` findings from `Registry.RenderAll` and emits OSCAL POA&M JSON into the evidence pack.
- `internal/remediate/tickets/` (Jira + Linear) reads the same unmatched + RiskClass=manual snippets and files tickets when the operator opts in via config.
- The contribution bar: a new CheckID should land with at least one Strategy alongside the check; CI gates this for v0.15-shipped checks (per issue #14 DoD).
- The evidence pack at v0.15 gains: `remediation/<format>/<resource-id>.<ext>`, `remediation.md` runbook, `remediate.sh` bulk-apply script, `poam.oscal.json` OSCAL POA&M file.

---

## ADR-012 — Rego is embedded via OPA's Go library, not shelled out
**Date:** 2026-05-15 (v0.16 kickoff)
**Status:** Accepted

### Question
v0.16 ships the Rego policy DSL promised since v0.1 ([ADR-002](#adr-002--policy-dsl-is-rego-landing-at-v016)). Three implementation shapes are plausible:

1. **Embed OPA as a Go library** (`github.com/open-policy-agent/opa/rego`). Policies compile + evaluate in-process; one binary.
2. **Shell out to `opa eval`.** Operator installs OPA separately; compliancekit invokes the CLI for every check.
3. **Compile policies to WASM at build time.** Policies ship as bytecode; runtime is a wazero interpreter, no Rego compiler at runtime.

Each has different trade-offs around binary size, performance, sandboxing, and the operator's onboarding story.

### Decision
**Embed OPA as a Go library** at v0.16. The Rego compiler + interpreter live inside the compliancekit binary; policies evaluate against an in-memory snapshot of the ResourceGraph; no separate OPA installation required.

Concrete shape:
- `internal/policy/policy.go` wraps `rego.New(...).Eval(ctx)` into the existing `compliancekit.CheckFunc` signature.
- `internal/policy/loader.go` walks `*.rego` files, extracts `metadata := {...}` constants into `compliancekit.Check` records, and registers each as a CheckFunc alongside the Go-evaluator checks.
- Custom built-ins (`compliancekit.has_tag`, `compliancekit.attr_str`, `compliancekit.attr_bool`, `compliancekit.cvss_band`) are registered on the `rego.New` builder so policy authors aren't forced to re-derive common idioms.

### Reasoning
- **Binary-size cost is acceptable.** OPA's Go dependency adds ~15 MB to the compliancekit binary (8 MB → 23 MB). That's the upper bound of what we're willing to spend for the contribution-bar reduction Rego unlocks. The v2.0 plugin marketplace can revisit if the size becomes painful.
- **Sandboxing is free with embed-as-library.** Rego is pure-functional with no I/O primitives; we don't need a separate sandbox. The data plane is the `ResourceGraph` snapshot we pass into `rego.Input(...)` — the policy cannot reach back into the live graph or make HTTP calls.
- **Byte-identical Findings without serialization round-trips.** A Rego policy that emits `{"resource_id": "x", "status": "fail"}` produces a `compliancekit.Finding` in the same process where Go-evaluator checks produce theirs. Parity testing (Phase 6) asserts byte-equality; shell-out would require JSON marshaling at every boundary and introduce subtle drift.
- **One distribution story.** "Install compliancekit; write Rego if you want." Shell-out would mean "install compliancekit; also install OPA; configure the path; debug version mismatches." Loses the appeal that lets the audience adopt the binary in the first place.

### Rejected alternatives
- **Shell out to `opa eval`.** Rejected. Adds a runtime dependency every operator has to discover and pin. Worse: every check execution pays a process-fork cost; a 300-check scan with 50 Rego checks would fork 50 times. Embedded eval is a function call.
- **WASM via wazero.** Rejected for v0.16. Compelling for v2.0 (plugin marketplace) because WASM gives us real sandboxing for untrusted third-party plugins. But Rego policies authored in this repo are not untrusted — they live in the same git tree as the Go code, get the same review. WASM's complexity (build-time compilation step, separate test harness) buys nothing at v0.16.
- **Defer custom built-ins to v0.17.** Considered but rejected. The ROADMAP note said "wait for community demand," but the four built-ins shipped (`has_tag`, `attr_str`, `attr_bool`, `cvss_band`) are unblockers — without them, every Rego policy reimplements the same `[t | t := input.resources[_].tags[_]; t == "x"]` boilerplate. Ship them as part of the v0.16 foundation; revisit additions case-by-case.

### Consequences
- `internal/policy/policy.go` + `internal/policy/loader.go` are the canonical entry points. Policies live in `internal/policies/<provider>/<id>.rego`; the same convention as the Go checks (`internal/checks/<provider>/...`).
- Every policy MUST declare `package compliancekit.<provider>.<service>` and expose `metadata := {...}` + `findings := [...]` rules. The loader rejects policies missing either.
- Custom built-ins are stable: removing or changing one is a breaking change for community-authored policies, governed by SemVer 2.0 once v1.0 freezes the API.
- The `compliancekit policy test / validate / fmt` subcommands give policy authors a local development workflow without round-tripping through `compliancekit scan`.
- Side-by-side parity: 15 existing Go checks ship as Rego twins at v0.16 (AWS / GCP / DigitalOcean / Kubernetes / Linux — 3 each). The Phase 6 parity test asserts both implementations produce byte-identical Finding slices against the same fixture graph; CI gates accidental drift.

---

## ADR-013 — Waivers vs baselines: distinct concerns, distinct mechanisms
**Date:** 2026-05-17 (v0.18 kickoff)
**Status:** Accepted

### Question
v0.6 shipped baselines: snapshots of the current findings set used as the starting point for `compliancekit diff`. v0.18 ships waivers: explicit operator acknowledgements that a specific (check, resource) pair is non-compliant by design. The two mechanisms overlap if you squint — both "make a finding stop alarming." Are they the same thing? If not, what is each for, and when does an operator use which?

### Decision
Waivers and baselines are **two different mechanisms for two different problems**, and v0.18 ships them as separate features with explicit handoff rules.

**Baselines** answer "what is our current state?" They are a snapshot tool. They have:
- No time bound (a baseline is the snapshot at the moment it was captured)
- No reason field (a baseline does not justify, it records)
- No approver field (no one signs off on a snapshot)
- One purpose: drive the `diff` engine to flag NEW findings since the snapshot

**Waivers** answer "what have we decided to accept?" They are a decision tool. They have:
- A required Expires date (a decision that lasts forever is not a decision, it is denial)
- A required Reason field (an undocumented acceptance is not auditable)
- A required Approver field (an unattributed acceptance is not accountable)
- One purpose: mute a specific (check, resource) pair WITHOUT hiding it from the auditor

Concretely: a waived finding flows through every reporter as `StatusSkip` with a `compliancekit.WaiverRef` block populated. The auditor sees the finding AND the reason AND the approver AND the expiry. Baselines, by contrast, drop pre-existing findings from `diff` output entirely — the auditor sees them only by re-comparing to the older baseline.

When to use which:
- "I am building a new fleet on a 10-year-old codebase; I want to know what's NEW from today forward" → **baseline**.
- "We acknowledge bucket X is public because CloudFront serves it; do not flag it again until 2026-12-31" → **waiver**.
- Both can coexist on the same scan; they are evaluated independently.

### Reasoning
- **Conflating the two would make one of them worse.** A baseline with a "reason" field becomes a half-built waiver system without expiry. A waiver without a reason becomes a partial baseline with hidden state. Two mechanisms with clear contracts beat one mechanism with overloaded semantics.
- **Audit trail matters more than terseness.** The CIS / SOC 2 / ISO model of "deviations are acceptable when documented + approved + time-bounded" maps 1:1 onto waivers. Baselines don't fit the model because they don't carry the metadata auditors require.
- **Visibility over silencing.** A waiver muting a finding into StatusSkip leaves the finding visible in evidence packs — the auditor sees the deviation and the reason. The alternative (drop the finding entirely) destroys the audit trail.
- **Expiry is non-negotiable.** Permanent waivers degrade into permanent ignore lists; the lapse is the forcing function that keeps the security team reviewing acceptances. Expired waivers stop muting and SURFACE as info-level findings of their own — the auditor sees the lapse, not silent re-coverage.
- **Reason length floor.** v0.18 enforces ≥16 non-whitespace characters in the reason field at load time. Catches "see ticket" / "OK" / "approved" without rejecting real explanations. Cheap defense against the audit-trail erosion every shipped exception-system experiences.

### Rejected alternatives
- **Unify waivers + baselines into one suppression mechanism.** Rejected. The two operations are semantically different (snapshot vs decision); operators need both. Forcing one shape onto the other compromises both.
- **Permanent waivers (no expiry).** Rejected. Becomes a hidden ignore list within 18 months of adoption; every operator who has shipped an ignore-list with no expiry process can attest. Expiry is the forcing function that keeps waivers fresh.
- **Allow waivers to mark findings as StatusPass (instead of StatusSkip).** Rejected. The auditor must see "this fails compliance but you decided it's OK", not "this passes compliance." StatusSkip + WaiverRef preserves both pieces of information.
- **Per-framework / per-tag broader waivers.** Considered for v0.18; deferred. The exact (CheckID, ResourceID) pair is the operator-facing unit of acceptance; broader scopes (e.g. "waive all NIST 800-53 SI-2 across the staging account") risk overreach. Add only when narrow waivers prove insufficient in practice.

### Consequences
- `internal/waivers/` ships the loader + matcher + expiry logic. `compliancekit.WaiverRef` joins `Vulnerability` + `Secret` as a typed metadata block on `compliancekit.Finding`.
- Two declaration paths: `waivers.yaml` central file + `// compliancekit:waive <check-id> <reason>` in-code annotations. Both lift into the same WaiverList with `WaiverRef.Source` recording the provenance.
- The evidence pack's `control-mapping.csv` gains 4 waiver columns at v0.18: `waiver_active`, `waiver_reason`, `waiver_approver`, `waiver_expires`. Additive — v0.4+ consumers reading by column name keep working.
- Expired waivers emit a new info-level CheckID `compliancekit-waiver-expired` per expiry, so an auditor sees the lapse as an explicit finding rather than as a silently-revived prior finding.
- `compliancekit waivers list / show / validate / check` subcommand mirrors the v0.13 `mapping` and v0.17 `notify --list` ergonomics: declarative state inspection without round-tripping `scan`.
- `compliancekit doctor` gains a waivers line: "N active, M expiring in 30 days, K expired" so operational health is visible.
- ADR is intentionally narrow: it codifies the boundary between waivers + baselines and the audit-trail-protecting rules (expiry required, reason floor, visibility). Future ADRs can introduce broader scopes or different precedence rules without revisiting these core invariants.

---

## ADR-014 — v1.0 API freeze: pkg/compliancekit is the SemVer surface
**Date:** 2026-05-18 (v1.0 release)
**Status:** Accepted

### Question
The v0.x line carried no stability promise: every release could rename a method, drop a field, or move a type without notice, and embedders relying on the Go API had to pin a commit and accept whatever follow-on churn each version brought. By v0.22 the load-bearing types (Finding, Resource, ResourceGraph, Check, Framework, Severity, Status, Reporter, Collector, Evaluator) had iterated four times — v0.1 → v0.6 → v0.12 → v0.18 — and the shapes had stabilized. What does v1.0 actually commit to, and how do we enforce it?

### Decision
v1.0 promotes the load-bearing types into a new top-level package, `pkg/compliancekit`, and commits to SemVer 2.0 on that package — and ONLY that package — for the entire v1.x line.

Concretely:

- **What's in:** Severity, Status, Resource, ResourceRef, EvidencePtr, ResourceGraph (including the Query DSL), Vulnerability, Package, Secret, WaiverRef, Source, Finding, Check, CheckFunc, Registry, Reporter, Collector, Evaluator, Framework, Control, Tactic, ResolvedControl, plus their constructors / helpers / consts. Every exported identifier is enumerated in `pkg/compliancekit/api.txt`.
- **What's out:** Everything under `internal/`. The check registry implementations, the engine, the collectors, the ingest adapters, the remediation strategies, the reporters' internals, the policy evaluator, the notify sinks, the waivers loader — all stay internal and may change in any release.
- **What's machine-enforced:** A `cmd/genapi` tool re-derives the public surface on every CI run and diffs it against the committed `api.txt`. Adding, renaming, or removing any exported identifier under `pkg/compliancekit` fails CI unless `api.txt` is regenerated in the same PR. The reviewer sees the contract diff before the merge button.
- **What's behaviourally enforced:** A `//go:build external`-gated test file under `package compliancekit_test` exercises the canonical embedding shape from the perspective of a downstream consumer. CI runs `go test -tags=external` so a refactor that accidentally narrows the contract (e.g. drops an unexported helper an embedder was reaching for via package-private access) fails to compile.
- **What the promise covers:** Security patches land on the last two minor versions of v1.x for at least two years from each minor's release date, per SECURITY.md. The Go module path stays `github.com/darpanzope/compliancekit` for all of v1.x; a hypothetical v2.0 lives under `/v2/` per Go module conventions.

### Reasoning
- **Stability is what embedders are buying.** Pre-v1.0 the value proposition was "the CLI works"; the API was incidental. Post-v1.0 it becomes "build on us without a pinning treadmill" — which is the only way a third-party tool can take a hard dependency.
- **The promotion bar is "survived four iterations."** Every graduating type was reshaped multiple times in the v0.x line and converged to its current form by v0.18. That's strong evidence the shape is right. Types that hadn't iterated that many times (the engine, the collectors, the registry implementations) stay internal — graduating them prematurely would force a v2.0 that nobody wants.
- **Machine-enforced contracts beat policy.** A maintainer cannot widen, narrow, or rename the public surface by accident if CI fails the build. The api.txt diff in the PR is the proof the contract change was intentional. This is the same shape Go's own standard library uses (cmd/api enforces the same gate on stdlib).
- **External-tagged tests catch what api.txt misses.** A reduction in the contract (e.g. an exported helper becoming unexported, a constructor signature changing in a backwards-incompatible way) shows up in api.txt — but a refactor that breaks the canonical *usage shape* without changing any identifier signatures wouldn't. The compile-time external test catches that class.
- **Two minors × two years is a real promise, not a marketing line.** It maps to "we'll backport one security fix every six months on average" — sustainable for an indie OSS project, generous enough for an embedder to plan upgrades.
- **internal/ stays open for change.** Locking the engine + collectors + reporters at v1.0 would have forced premature decisions about evolution we haven't earned. Keeping them internal preserves the freedom to ship the v0.22 deferred backlog (spec-pattern lifts, fake-API-server coverage, cookbook) under v1.0.x without a v2.0.

### Rejected alternatives
- **Promote everything: engine, collectors, reporters, ingest adapters.** Rejected. Most of those have iterated only once or twice and the shapes are demonstrably still moving (the collector interface gained a context.Context parameter in v0.7, the reporter interface gained the graph argument in v0.11). Locking now forces a v2.0 within 12 months. The audience asking for embedability wants the types, not the runtime — and the runtime is exposed through the CLI either way.
- **Promote nothing; keep pinning by commit hash.** Rejected. That signal — "we won't commit to a contract" — kills the "embed compliancekit in your own tool" use case at the door. The v1.0 release has to mean something concrete; "we've stopped renaming Finding" is concrete.
- **Sub-packages: pkg/compliancekit/finding, pkg/compliancekit/registry, etc.** Rejected. The types form one coherent surface (Finding references Resource references ResourceGraph references Check); splitting them into subpackages creates an artificial barrier embedders have to chase across multiple import lines. A flat pkg/ matches what consumers actually want.
- **One-year compat instead of two.** Rejected. One year doesn't survive a contract embedder's annual planning cycle ("we adopted v1.x in Q2, can we wait until the following Q3 to upgrade?"). Two years is the next sustainable floor; it also matches the rough rhythm at which one minor per quarter ships, so we'll always have two relevant supported minors.
- **API freeze includes the YAML schemas (frameworks/checks/waivers).** Rejected for v1.0; deferred. The Go API is one contract; the YAML schemas are another and have their own audience (operators writing custom catalogs, not Go embedders). They'll get their own ADR if/when an explicit schema freeze becomes worth it.
- **Auto-generate the embedding example from the test file.** Rejected. The contract test and the documentation example are different artifacts: the test asserts shape preservation, the example shows narrative usage. Keeping them separate lets each be the right shape for its audience.

### Consequences
- `pkg/compliancekit/` is the v1.0 public package. 13 source files, ~1200 LoC including doc comments. Every exported identifier is documented in godoc, machine-enumerated in api.txt, and behaviourally exercised under `-tags=external`.
- `internal/core/` is deleted at v1.0. Every internal caller imports `pkg/compliancekit` directly; the alias-shim period that bridged the migration is gone.
- `cmd/genapi/` ships as a maintainer tool. The `make api-check` target wraps `go run ./cmd/genapi -check`, runs in the pre-push hook and on CI, and fails when api.txt is stale.
- SECURITY.md gains a "Two-year compatibility commitment" section with the per-minor expiry dates expressed concretely (the v0.22.x sunset is 2026-11-18 — six months from v0.22.1 release).
- A maintainer adding a new check or provider — the v0.x workflow — still happens entirely under `internal/`. No new public types ship at v1.0; v1.0 is a contract release, not a feature release. The v0.22.x deferred backlog (spec-pattern lifts, fake API server coverage, deep cookbook, ADR index, CHANGELOG backfill, lint v2) stays valid and can land as v1.0.x or v1.3 (post-CLI/HTML polish) in parallel.
- The Go module path stays `github.com/darpanzope/compliancekit`. A hypothetical v2.0 (plugin marketplace, fundamentally new evaluator interface, etc.) lives at `/v2/` and is a separate import path so v1.x embedders are unaffected.

---

## ADR-015 — `serve` UI is htmx + Alpine + Tailwind + Preline + vanilla SVG, embedded at build time
**Date:** 2026-05-18
**Status:** Accepted

### Question
v1.3 landed `compliancekit serve`. v1.4 landed the studio (config-as-UI); v1.5 landed the explorer (resource map, findings filter, remediation studio). What does the UI ship in, given the project's "single binary, no SaaS, no Node runtime, no CDN" ethos?

### Decision
Server-rendered HTML driven by htmx + Alpine.js for client-side reactivity, styled with Tailwind CSS, using Preline UI for high-quality off-the-shelf components, with vanilla SVG drawers (continuing the v1.2 chart.js pattern) for charts + the resource map. The full asset bundle is compiled at `make ui` time and `go:embed`-ed into the binary. No Node runtime ships with compliancekit; no CDN is reached at runtime.

### Reasoning
- **Single-binary invariant preserved.** Tailwind (~30 KB CSS), htmx (~14 KB JS), Alpine (~8 KB JS), Preline components on top — total client-side bundle around 60 KB, all embedded. `curl -L https://.../compliancekit | sudo install` still gets the operator a working `serve` without any external dependency.
- **No bundler runtime in the repo.** Contributors run `make ui` to refresh the embedded assets (driven by Tailwind CLI + esbuild for Alpine plugin packaging). The repo carries the compiled outputs under `internal/server/assets/`; CI verifies they're fresh against source via a `make ui-check` gate, matching how api.txt + checks.md gate their generated content.
- **htmx is a Go-shop's frontend framework.** The interaction model (`hx-get`, `hx-post`, `hx-swap`) is a natural extension of how Go HTTP handlers think — return HTML fragments, browser swaps them in. Maintainers writing Go don't context-switch to a JS/TS mental model to add a UI feature. Linear, GitHub, and Hotwire-style Rails apps demonstrate this stack produces UIs indistinguishable from SPAs for the use cases compliancekit needs (filter panels, side-drawer drill-in, live progress streams via SSE).
- **Preline UI ships polished components.** Command palette, datatable, modal, popover, dropdown, drawer, accordion, stepper, alert toast, tabs — all themed via Tailwind utility classes, all keyboard-accessible by default. Avoids the "I designed a popover from scratch and it has six accessibility bugs" trap.
- **Vanilla SVG continues the v1.2 chart.js pattern.** The gauge / donut / hbar / sparkline drawers already live in `internal/report/assets/chart.js`. The v1.5 resource-map graph extends the same pattern — a `drawResourceMap(el)` registered in the same drawer dispatch, no graph library, palette pulled live from CSS variables so the theme toggle re-paints automatically.
- **Real-time updates use SSE, not WebSockets.** Server-Sent Events are unidirectional but enough for scan progress + audit-log tail + drift alerts. WebSockets add bidirectional complexity (auth handshake, reconnection, framing) for no payoff at v1.5's scope.
- **PDF export uses chromedp embedded.** Headless Chrome via chromedp is the cleanest path to "print this filter view to A4." The v1.2 print stylesheet already prepares the page for clean PDF conversion; chromedp just drives the print pipeline server-side. The chromedp dep adds ~3-4 MB to the binary; acceptable given the operator value.

### Rejected alternatives
- **Preact / Solid SPA with esbuild/vite.** Considered. The interactivity ceiling is marginally higher (Monaco editor inline, drag-to-reorder, complex graph state). Rejected because it forces contributors to maintain a `package.json` + node_modules + a JS build pipeline alongside the Go build, foreign to a Go-shop maintainer + reviewer. The htmx stack hits the same visual ceiling for compliancekit's specific use cases (filter chips, side-panel drill-in, live progress) at half the contributor cost.
- **Server-rendered Go templates with no JS framework.** Considered as the minimalist option. Rejected because compliancekit-as-Wiz-competitor needs side-panel drill-in (no page reload), live scan progress (SSE), fluid filter chips (no flicker), Cmd+K palette, and the resource map — all require at least Alpine-tier reactivity. A pure-templates approach hits a 7/10 visual ceiling at most; the user explicitly named "world-famous, production-grade" as the bar.
- **Next.js / Nuxt full SPA + Go backend over REST.** Rejected. Two-runtime deployment (Node + Go), CDN expectations, hydration complexity. Incompatible with the single-binary invariant compliancekit makes its biggest pitch around.
- **Pure WebComponents + Lit.** Considered briefly. Rejected because Lit pulls a build pipeline regardless + the component ecosystem is thinner than Preline-on-Tailwind for the components compliancekit needs day one.

### Consequences
- A new top-level directory `internal/server/` houses the v1.3 server: `server.go` (chi router, middleware), `auth/` (local + OIDC), `api/` (REST handlers), `store/` (SQLite + Postgres backends), `ui/` (handlers that render the htmx-driven HTML). Assets live under `internal/server/assets/` (templates, compiled CSS, JS, sprite, images).
- `make ui` (new top-level target) runs Tailwind CLI + esbuild against source under `internal/server/ui/src/` and writes compiled outputs under `internal/server/assets/`. `make ui-check` verifies cleanliness; CI gates on it, same shape as `api-check` / `gencheckdocs-check`.
- Tailwind config + Preline + Alpine + htmx vendored at known versions under `internal/server/ui/vendor/` so a clean clone can `make ui` without network. Updates land via `make ui-update` (vendoring helper) + reviewed PR.
- `compliancekit serve` adds a new binary section for the embedded assets. Estimated stripped-binary delta: ~4-5 MB (Tailwind output, htmx, Alpine, Preline JS bundle, chromedp Chrome-driver bindings — Chrome itself remains an OS-level dep that operators provide if they want PDF export).
- The v1.2 HTML report (`internal/report/assets/`) stays as-is — its single-file invariant is for the offline / emailable / committed-to-git artefact. `serve` mode renders the same template for `/scans/:id`, so a v1.2 polish improvement propagates to both surfaces for free.

---

## ADR-016 — v1.x is fully scoped to server / UI/UX / backend / CLI polish
**Date:** 2026-05-18
**Status:** Accepted

### Question
After v1.5 (Explorer + Remediation Studio) ships, the original v1.6-v1.13 lineup mixed cross-cutting platform expansion (multi-tenant, GRC, auditor portal, tail clouds, OSCAL, OS-coverage expansion, risk-score modelling) with what could have been a focused continuation of the v1.3-v1.5 server / UI / UX arc. Do we keep that mixed lineup, or do we reserve the entire remaining v1.x slot for server + frontend + UI/UX + backend + CLI polish, pushing everything else to v2.x?

### Decision
**v1.x (v1.6 through v1.19) is fully reserved for server, frontend, UI/UX, backend, and CLI polish.** No new providers, no new GRC capabilities, no new framework catalogs, no OS-coverage expansion, no risk-scoring model in v1.x — those are all explicitly deferred to v2.x.

The v1.x lineup that lands under this reservation:

| Slot | Theme |
|---|---|
| v1.6  | Live Operations (SSE / WebSocket / live dashboards) |
| v1.7  | TUI mode (`compliancekit tui`) |
| v1.8  | Collaboration & workflow (comments / assignees / two-way sync) + notification inbox 2.0 |
| v1.9  | Workflow automation / rules engine |
| v1.10 | Accessibility / i18n / keyboard excellence |
| v1.11 | Performance & scale |
| v1.12 | Admin & RBAC (SAML / SCIM / tamper-evident audit log) + settings UX excellence |
| v1.13 | Plugin SDK + marketplace prep |
| v1.14 | Reporting renaissance (dashboard builder / scheduled email; chart-interactivity hooks designed for v1.18) |
| v1.15 | Deploy & operate (Helm / operator / Terraform / distroless) |
| v1.16 | Mobile / PWA |
| v1.17 | Data warehouse bridges |
| v1.18 | **Design system & visual polish** (tokens, motion, skeletons, illustrations, chart interactivity, magic moments, brand kit) |
| v1.19 | **Onboarding 2.0 + global search + table excellence** (feature tours, changelog modal, demo seed, fuzzy Cmd-K, table 2.0) |

Demo mode (`compliancekit serve --demo`) ships at v1.4 (Studio) rather than v1.19 so first-impression evaluators see screenshot-grade seed data from day one. The v1.4 work also closes the v1.3.1 throwaway-seeddemo gap by shipping daemon-bootstrap CLI subcommands (`serve users create --admin`, `serve tokens issue --scope=...`). v1.19 polishes the seed-data fidelity for screenshot quality.

The v2.x lineup absorbs the displaced items: v2.1 multi-tenant, v2.2 Trust Center, v2.3 GRC layer (ADR-004 re-slotted), v2.4 auditor portal, v2.5 macOS/Windows/BSD hardening, v2.6 tail clouds, v2.7 OSCAL ecosystem + SCAP, v2.8 risk score + executive PDF + time-series. v2.9-v2.11 retain the pre-existing v2.0/v2.x rows (plugin marketplace, K8s operator, auto-remediation).

### Reasoning
- **The daemon's UX is the moat.** v1.3 shipped server foundation; v1.4 shipped the config builder; v1.5 shipped the findings explorer. The next leap in audience reach comes from a daemon experience that beats Wiz / Snyk / Drata at developer-experience even though it has 1% of their R&D budget. That's a polish-and-focus play, not a feature-breadth play.
- **Cross-cutting platform expansion is a v2.x prerequisite anyway.** Multi-tenant + auditor portal + GRC layer all assume an already-polished single-tenant daemon. Building them in v1.x before the v1.x polish lands means re-doing the polish work twice.
- **Tail clouds, OS expansion, OSCAL** are scope-expansion features, not depth features. compliancekit's audience is best served by *depth* in v1.x and *breadth* in v2.x, mirroring the pre-v1.0 cadence where we picked depth (DO deepening, K8s deepening, Linux deepening) over breadth.
- **Risk score + executive PDF** is partially folded into v1.14 reporting renaissance for the *report* shape (scheduled email, executive-summary auto-gen, watermarked exports). The *model* (a 0-100 risk score with separate weights from the hardening score) is a v2.8 modelling task that benefits from v1.14's reporting surfaces being in place.

### Rejected alternatives
- **Ship the original mixed v1.6-v1.13 lineup as-is.** Spreads attention too thin between platform expansion and depth polish. The risk: a v1.x where the daemon ships multi-tenant before its mobile UI works, ships tail clouds before its accessibility audit, ships an auditor portal before its admin-RBAC story.
- **Cut v1.x at v1.10 and call it v2.0.** Tempting (clean break), but the v1.x slot has runway for 14 more milestones of polish work and the audience signal (per the v1.3 demo: "POST /api/auth/login=404 because CLI didn't have a `users create` subcommand") is that there's depth to mine in the server + CLI experience before we should worry about a v2 surface break.
- **Slot a v1.x AI-assist milestone.** Reserved as a future possibility but not committed in v1.x. Any LLM-assist work has to honor the no-telemetry / no-phone-home invariant and the ADR-009 composed-not-native principle — implying local-LLM-only, which is a significant tooling dependency the audience doesn't yet need. Re-evaluate after v1.17.

### Consequences
- **ADR-004 re-slotted**: GRC layer moves v1.8 → v2.3. Trust Center moves v1.7 → v2.2. Auditor portal moves v1.9 → v2.4. All other references updated in the ROADMAP table.
- **The v1.x table is now 14 minor versions deep**, all server / UI / UX / backend / CLI. ROADMAP.md has full per-milestone expansions for v1.6-v1.19.
- **v1.18 (design system & visual polish) is the load-bearing magnificent-dashboard slot.** ADR-017 will codify the design-system contract — tokens, component library, motion language, illustration catalog — so v2.x builds on it without re-deriving.
- **v1.19 (onboarding 2.0 + global search + table 2.0)** closes the "first 10 minutes feel guided + daily search is instant + tables feel modern" gap. Feature tours, changelog modal, demo seed (layered on v1.4 `--demo`), fuzzy Cmd-K search across everything, table-2.0 (resize/reorder/pin/bulk-actions/inline-edit/saved column sets).
- **Three existing milestones scope-up** to absorb adjacent UX gaps without inflating the milestone count further: v1.8 adds notification inbox 2.0 (snooze / mark-all-read / per-event-type prefs / DND); v1.12 adds settings UX excellence (Cmd-K settings search / change diff / deep links / auto-save); v1.14 designs chart interactivity hooks so v1.18 visual polish can flesh them out without re-shaping SVG.
- **Demo mode is pulled forward** from where it would naturally fit (v1.19) into v1.4 Studio. First-impression evaluators get screenshot-grade seed data day one; v1.19 polishes seed fidelity later. Closes the v1.3.1 throwaway-seeddemo gap.
- **Stack-independent visual ceiling commitment**: ADR-015 fixes the daemon UI stack to htmx + Alpine + Tailwind + Preline + vanilla SVG. v1.18 + v1.19 commit that this stack choice is **not** a quality ceiling — whatever modern React + shadcn/ui dashboards (Linear / Vercel / Wiz) achieve "for free" via vendored component libraries, compliancekit invests equivalent effort to hit the same visual + interaction ceiling via carefully crafted htmx + Alpine partials. The concrete patterns codified into the v1.18/v1.19 expansions: per-domain color tokens (severity-/status-/resource-) extended across every provider compliancekit ships; gradient utility tokens; MetricCard component spec with variant + tooltip + trend + icon-in-rounded-bg; InfoTooltip-on-every-card-title pattern as the in-context discovery layer; named shadow scale (soft/elevated/floating/glass); 20–25 carefully crafted components modeled on shadcn's API shape (not breadth); filter-card convention; page-header convention; bulk-actions-in-page-header pattern. The htmx stack constrains *how* we implement, never *what quality* we ship.
- **v1.5 resource graph escape hatch**: vanilla SVG is the default per ADR-015 spirit. v1.5 shipped (2026-05-19) with the hierarchical-SVG resource map and stayed inside budget — no cytoscape.js needed. The cytoscape.js (~150KB, vanilla JS, no React) escape hatch remains documented for v1.5.x if pan/zoom/drag demand grows beyond a 1500+ LoC budget. Explicit escape hatch, not a yak-shave.
- **v2.x grows from 3 rows (plugin marketplace, K8s operator, auto-remediation) to 12 rows** (those three plus the eight displaced items plus a reserved v2.0 slot for the next API-surface refinement cycle).
- **Tracking issue cadence**: issues open just-in-time. The roadmap is the long-form planning artifact; issues are the work artifacts. Status: #25-#27 closed (v1.3-v1.5), v1.5.1 patch shipped 2026-05-19 without a tracking issue (patches don't get one per convention), #38 closed (v1.6, 2026-05-20), #39 closed (v1.7, 2026-05-20), #40-#42 open (v1.8-v1.10, batched 2026-05-20 per user request — deliberate deviation; v1.11+ stay in ROADMAP table form).
- **ADR-006 unchanged**: auto-remediation remains a v2.x trust gate. The v2.x slot moves from "v2.x" to v2.11 (concrete numbering).

---

## ADR-018 — Strict CSP with `'unsafe-eval'`: the cost-of-doing-business for Alpine 3
**Date:** 2026-05-19
**Status:** Accepted

### Question
v1.5.0's demo testing surfaced two latent CSP-blocked bugs in the daemon UI: the Cmd+K palette + the No-FOUC theme bootstrap silently failed because the templates' inline `<script>` blocks ran into `script-src 'self'`. Extracting the inline scripts to `/assets/app.js` fixed those two specific cases — but Alpine 3.13's expression evaluator uses `(async function(){}).constructor(...)` (the indirect AsyncFunction trick), which CSP gates the same way it gates `new Function`. Without `'unsafe-eval'` in `script-src`, every `x-data` / `x-show` / `@keydown` binding in every template silently no-ops too.

How do we keep ADR-015's "single binary, no Node runtime, htmx + Alpine stack" promise without shipping a UI that's silently broken under strict CSP?

### Decision
The daemon's CSP carries **`script-src 'self' 'unsafe-eval'`**. `'unsafe-inline'` stays OUT (no inline `<script>` tags ship — the No-FOUC bootstrap + cmdk factory live in `/assets/app.js`). Inline `<style>` attributes remain allowed via `style-src 'self' 'unsafe-inline'` for Tailwind's compiled utility classes.

### Reasoning
- **Alpine 3 needs eval-equivalent.** The default Alpine 3.x build evaluates string expressions via the indirect AsyncFunction constructor pattern. Every binding (`x-data="cmdk()"`, `x-show="visible"`, `@keydown.window.prevent.cmd.k="open()"`) goes through it. There is no way to use the default build without `'unsafe-eval'`.
- **The CSP-friendly Alpine build (`@alpinejs/csp`) requires every binding to be precompiled.** No string expressions; every reactive method registered via `Alpine.data()` factories; every event handler bound declaratively. Migrating the v1.3-v1.5 templates (50+ Alpine bindings across 20+ templates) to the CSP build is a milestone-scale rewrite, not a patch. Out of scope for the htmx + Alpine stack ADR-015 codifies.
- **`'unsafe-eval'` is the standard cost-of-doing-business for any runtime-expression UI framework** — Alpine, Vue inline templates, Knockout, AngularJS legacy. With `script-src 'self'` (no `'unsafe-inline'`) still in place, an attacker who finds a reflected-HTML injection cannot execute their own script — they'd need to also inject into a build-time Alpine template expression, which is server-controlled. The XSS attack surface is tighter than `'unsafe-inline' 'unsafe-eval'`, which other htmx-stack projects ship without controversy.
- **No inline `<script>` tags ship anywhere.** The two latent inline-block bugs from v1.5.0 (No-FOUC theme bootstrap + cmdk factory) were extracted to `internal/server/ui/src/app.js`, wired into `make ui`, and embedded via `go:embed`. Future templates must follow the same pattern (codified in `feedback-csp-alpine` memory). Inline scripts are a CSP-violation footgun + a v1.5.0-style silent-failure mode in one.

### Rejected alternatives
- **`script-src 'self' 'unsafe-inline'` (drop unsafe-eval, allow inline).** Rejected: weaker security posture (an XSS attacker can inject `<script>` tags inline + run them; with `unsafe-eval` they need to also inject into a template expression). Also a step backward — the v1.3 ship already established no-inline-script as the norm.
- **Switch to `@alpinejs/csp` build.** Rejected for v1.5.1: would require rewriting every `x-data` / `x-show` / `@event` in 20+ templates to declarative form + registering every reactive method via `Alpine.data()`. Milestone-scale work. v1.6 may revisit if a security audit / FedRAMP-style CSP-strict requirement makes `'unsafe-eval'` a non-starter.
- **Hash-based inline-script CSP (`script-src 'self' 'sha256-...'`).** Considered for the inline blocks alone: SHA-256-pin each inline script. Rejected: doesn't solve the Alpine-eval problem (every binding still needs `'unsafe-eval'`); adds build-time hash-emission tooling for no security gain; brittle (every template edit invalidates the hash).

### Consequences
- The daemon's CSP `Content-Security-Policy` response header carries `script-src 'self' 'unsafe-eval'`.
- `internal/server/server.go::securityHeaders` documents the choice + the F15 lesson it came from in its body comment.
- `feedback-csp-alpine` memory codifies "never add an inline `<script>` block to any template" as a hard rule.
- ADR-015's stack ceiling commitment is preserved; this ADR clarifies the CSP boundary the stack lives within.
- A v1.6+ "FedRAMP-strict mode" or hardening track may migrate to `@alpinejs/csp`; recorded as a future possibility, not a current commitment.

---

## Open questions (not yet decided)

- **Plugin host model:** subprocess gRPC (Terraform-provider pattern), WASM via wazero, or both? Decision at v2.0.
- **CIS Certification pursuit:** worth the paperwork for credibility? Decide post-launch once audience traction is known.
