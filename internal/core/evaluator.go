package core

import "context"

// Evaluator runs a set of checks against a ResourceGraph and emits
// the produced Findings.
//
// At v0.1 the only implementation is the function-backed evaluator in
// internal/engine: it iterates the check registry and invokes each
// registered CheckFunc. At v0.13 a Rego-backed evaluator joins,
// sourcing CheckFuncs from compiled Rego policies. The interface was
// shaped on day 1 so adding the second implementation requires no
// change to existing checks (see DECISIONS.md ADR-002).
//
// Implementations must honor ctx.Done() -- a long-running evaluator
// gets canceled on user interrupt (Ctrl-C) and on engine-side timeouts.
type Evaluator interface {
	// Evaluate runs all configured checks against the graph and returns
	// every Finding produced. Findings of any Status are returned;
	// filtering by status, severity, or check ID is the caller's
	// responsibility.
	Evaluate(ctx context.Context, graph *ResourceGraph) ([]Finding, error)
}
