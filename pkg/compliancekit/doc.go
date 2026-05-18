// Package compliancekit is the v1.0+ public API surface of
// compliancekit. Anything exported from this package is covered by
// SemVer 2.0 — breaking changes require a major-version bump and the
// last two minor versions receive security patches for at least two
// years after release.
//
// The contract was established at the v1.0 release by promoting the
// load-bearing types that survived four iterations (v0.1, v0.6, v0.12,
// v0.18) out of internal/ and into this package. The full surface is
// machine-checked: cmd/genapi enumerates every exported identifier and
// diffs against api.txt in this directory; the CI gate fails the build
// when an identifier is added, renamed, or removed without an explicit
// api.txt update so the maintainer cannot widen the contract by
// accident.
//
// # Embedding compliancekit
//
// The canonical embedding shape is "build a ResourceGraph, register
// checks, run an Evaluator, render Findings through a Reporter."
// Operators who only run the CLI never touch this package; tool authors
// who want to compose compliancekit into a larger product import it
// directly:
//
//	import "github.com/darpanzope/compliancekit/pkg/compliancekit"
//
// Subpackages and internal/ are NOT covered by the SemVer promise.
// Anything under internal/ may change in any release; consumers who
// reach across that boundary do so at their own risk.
//
// # What is NOT in pkg/compliancekit
//
//   - Vulnerability databases. compliancekit ingests Trivy / Grype
//     output; it does not reimplement a CVE store. See ADR-009.
//   - Auto-remediation execution. Remediation snippets are generated and
//     rendered through this package, but applying them is an opt-in
//     CLI-only action that requires per-run reaffirmation.
//   - The serve daemon. CLI parity is a hard invariant; daemon mode is
//     permanently optional and lives under internal/.
//   - Telemetry. There is none, and there will never be any.
//
// # Versioning
//
// The Go module path stays github.com/darpanzope/compliancekit for the
// entire v1.x line. A hypothetical v2.0 would live under /v2/ per Go
// module conventions and would only ship if a real contract break is
// unavoidable.
package compliancekit
