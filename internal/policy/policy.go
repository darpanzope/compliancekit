// Package policy implements the Rego-backed Check evaluator and the
// loader that turns `internal/policies/*.rego` files into entries in
// the core.Check registry. v0.16+.
//
// The seam was set up at v0.1 specifically for this milestone: the
// Evaluator interface (internal/core/evaluator.go) and the
// Scanner/Policy mutual-exclusion fields on core.Check were both
// shaped so a second evaluator could land without touching any
// existing Go check.
//
// Per ADR-002 (Policy DSL is Rego, landing at v0.16): community
// authors can contribute checks in <10 lines of Rego with no Go
// toolchain. Per ADR-012 (this milestone): OPA is embedded via
// github.com/open-policy-agent/opa/rego — not shelled out — because
// (a) Rego programs are pure-functional with no I/O so sandboxing
// is free, (b) embedding gives us byte-identical Findings without
// JSON serialization round-trips, (c) one binary stays the
// distribution story.
//
// What this package is NOT:
//   - It does not load remote bundles or fetch policies over HTTP.
//     That belongs to `serve` mode at v1.1 if the feature lands.
//   - It does not provide WASM compilation. That belongs to the v2.0
//     plugin marketplace alongside subprocess gRPC.
//   - It does not let Rego call out to compliancekit's cloud SDKs.
//     The data plane is the ResourceGraph, snapshotted before
//     evaluation; collectors do all I/O.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/darpanzope/compliancekit/internal/core"
)

// Module is a parsed Rego policy with its catalog metadata extracted.
// One .rego file produces one Module; modules with multiple rule
// blocks all share the file's `metadata := {...}` constant.
type Module struct {
	// SourcePath is the path the loader read the policy from. Used by
	// `compliancekit checks show <id>` to surface the source file and
	// by error messages to attribute compile failures.
	SourcePath string

	// PackageName is the Rego `package` identifier, e.g.
	// `compliancekit.aws.s3`. Used to scope rule references in the
	// query string.
	PackageName string

	// Body is the raw Rego source. Held verbatim so the loader can
	// re-render it for `checks show` and the parity-test fixture
	// snapshots.
	Body string

	// Check is the catalog metadata parsed out of the policy's
	// `metadata := {...}` constant. Always non-nil for a successfully
	// loaded Module; missing or malformed metadata makes the Module
	// fail to load.
	Check core.Check
}

// CheckFunc returns the evaluator function this module exposes,
// suitable for registration alongside Go-backed CheckFuncs. The
// returned function evaluates the policy against the graph passed
// in at call time; it does NOT hold a stale snapshot.
func (m *Module) CheckFunc() core.CheckFunc {
	return func(ctx context.Context, graph *core.ResourceGraph) ([]core.Finding, error) {
		return m.Evaluate(ctx, graph)
	}
}

// Evaluate runs the policy against graph and returns the resulting
// Findings. Rego query: `data.<package>.findings` — every shipped
// policy is required to expose a `findings` rule whose value is a
// list of objects with at least `resource_id`, `status`, and an
// optional `message`. The rule MAY return additional fields and
// they will be projected onto the Finding (severity, tags, …).
//
// The graph is passed in as the `input.resources` array — a JSON
// projection of the live ResourceGraph. Rego sees a stable, snapshot
// shape; it cannot reach into the live graph after eval starts.
func (m *Module) Evaluate(ctx context.Context, graph *core.ResourceGraph) ([]core.Finding, error) {
	if m == nil {
		return nil, errors.New("policy: nil module")
	}
	if graph == nil {
		return nil, errors.New("policy: nil graph")
	}

	input, err := graphToInput(graph)
	if err != nil {
		return nil, fmt.Errorf("policy %s: build input: %w", m.SourcePath, err)
	}

	query := fmt.Sprintf("data.%s.findings", m.PackageName)
	r := rego.New(
		rego.Query(query),
		rego.Module(m.SourcePath, m.Body),
		rego.Input(input),
	)
	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy %s: eval: %w", m.SourcePath, err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return nil, fmt.Errorf("policy %s: marshal result: %w", m.SourcePath, err)
	}

	var rawFindings []regoFinding
	if err := json.Unmarshal(raw, &rawFindings); err != nil {
		return nil, fmt.Errorf("policy %s: decode findings: %w (got %s)", m.SourcePath, err, string(raw))
	}

	out := make([]core.Finding, 0, len(rawFindings))
	for _, rf := range rawFindings {
		f, err := rf.toFinding(m.Check, graph)
		if err != nil {
			return nil, fmt.Errorf("policy %s: bad finding: %w", m.SourcePath, err)
		}
		out = append(out, f)
	}
	return out, nil
}

// regoFinding is the shape every shipped Rego policy emits.
// Required fields: resource_id + status. Optional fields override
// the Check-level defaults so a policy can flag one resource at a
// higher severity than the rule-level default if the data warrants
// (e.g. CVSS 9+ critical, 7+ high).
type regoFinding struct {
	ResourceID string   `json:"resource_id"`
	Status     string   `json:"status"`
	Severity   string   `json:"severity,omitempty"`
	Message    string   `json:"message,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

// toFinding lifts the Rego-emitted shape into a typed core.Finding,
// resolving the ResourceRef from the graph and inheriting Check
// metadata for severity/tags when the policy didn't override.
func (rf regoFinding) toFinding(check core.Check, graph *core.ResourceGraph) (core.Finding, error) {
	status, err := core.ParseStatus(rf.Status)
	if err != nil {
		return core.Finding{}, fmt.Errorf("status %q: %w", rf.Status, err)
	}
	severity := check.Severity
	if rf.Severity != "" {
		s, err := core.ParseSeverity(rf.Severity)
		if err != nil {
			return core.Finding{}, fmt.Errorf("severity %q: %w", rf.Severity, err)
		}
		severity = s
	}
	tags := append([]string(nil), check.Tags...)
	tags = append(tags, rf.Tags...)

	ref := core.ResourceRef{ID: rf.ResourceID}
	if res, ok := graph.ByID(rf.ResourceID); ok {
		ref = res.Ref()
	}

	return core.Finding{
		CheckID:  check.ID,
		Status:   status,
		Severity: severity,
		Resource: ref,
		Message:  rf.Message,
		Tags:     tags,
	}, nil
}

// graphToInput projects the live ResourceGraph into the shape Rego
// policies expect on input. We send the full Resource slice — each
// resource carries ID, Type, Name, Provider, Region, Attributes,
// Relations, and Tags. Rego policies query `input.resources[_]` and
// filter from there.
//
// JSON round-trip is intentional: it forces the snapshot semantics
// (Rego cannot mutate the live graph) and gives us a stable,
// well-defined data model for the policy author.
func graphToInput(graph *core.ResourceGraph) (map[string]any, error) {
	resources := graph.All()
	encoded, err := json.Marshal(resources)
	if err != nil {
		return nil, err
	}
	var decoded []any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, err
	}
	return map[string]any{"resources": decoded}, nil
}
