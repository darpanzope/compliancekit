// Package core defines the value types and interfaces shared across the
// compliancekit codebase: Severity, Status, Resource, ResourceGraph,
// Finding, Check, Collector, Evaluator, and the check registry.
//
// Every other internal package depends on core; core depends only on
// the standard library and on pkg/compliancekit (the v1.0 public API
// package) — for the v1.0 migration window, the load-bearing types
// graduate into pkg/compliancekit one at a time and core re-exports
// them as type aliases so the rest of the codebase keeps compiling
// without a flag-day import sweep. The aliases will be deleted once
// every internal/ package has been migrated to import directly from
// pkg/compliancekit (v1.0 Phase 10).
package core
