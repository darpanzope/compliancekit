// Package engine orchestrates a scan: it runs Collectors to populate
// the ResourceGraph, then drives the check Registry to produce
// Findings.
//
// The engine is the only piece that knows about both collection and
// evaluation; every other package operates on one side at a time.
package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Engine runs a scan end-to-end. It is constructed via New and invoked
// once per scan via Run.
//
// At v0.1 collection and evaluation are sequential. v0.6 will introduce
// bounded parallelism for both phases (max_parallel from config).
type Engine struct {
	collectors []compliancekit.Collector
	registry   *compliancekit.Registry
}

// New returns an Engine configured with the given collectors and check
// registry. Pass compliancekit.DefaultRegistry() for production scans; pass a
// fresh compliancekit.NewRegistry() for isolated tests.
func New(collectors []compliancekit.Collector, registry *compliancekit.Registry) *Engine {
	return &Engine{
		collectors: collectors,
		registry:   registry,
	}
}

// Result is the output of one scan.
//
// Findings is the full list (any status). The scan command applies
// min_report filtering before handing the list to reporters; reporters
// themselves render whatever is passed in.
//
// Graph is the populated resource graph used during evaluation.
// Reporters that need raw resource detail (the evidence pack reporter
// at v0.4) read from it.
type Result struct {
	Findings []compliancekit.Finding
	Graph    *compliancekit.ResourceGraph
}

// Run executes the scan.
//
// Collection phase: each collector is invoked once; emitted Resources
// are added to a fresh graph. A collector error aborts the scan --
// partial data would produce misleading findings.
//
// Evaluation phase: every check registered in the registry is invoked
// against the populated graph. A check error is converted to a
// StatusError Finding so the operator sees what failed without losing
// findings from checks that succeeded.
//
// All findings produced in one scan share a single Timestamp (engine
// end-of-scan time) for stable diff correlation across runs.
func (e *Engine) Run(ctx context.Context) (Result, error) {
	graph := compliancekit.NewResourceGraph()

	for _, c := range e.collectors {
		if err := ctx.Err(); err != nil {
			return Result{Graph: graph}, err
		}
		resources, err := c.Collect(ctx)
		if err != nil {
			return Result{Graph: graph}, fmt.Errorf("collector %s: %w", c.Name(), err)
		}
		for _, r := range resources {
			graph.Add(r)
		}
	}

	var findings []compliancekit.Finding
	timestamp := time.Now().UTC()

	for _, id := range e.registry.IDs() {
		if err := ctx.Err(); err != nil {
			return Result{Findings: findings, Graph: graph}, err
		}
		fn, ok := e.registry.Get(id)
		if !ok {
			continue // race-safe: a check de-registered between IDs() and Get()
		}
		produced, err := fn(ctx, graph)
		if err != nil {
			findings = append(findings, compliancekit.Finding{
				CheckID:   id,
				Status:    compliancekit.StatusError,
				Severity:  compliancekit.SeverityInfo,
				Message:   fmt.Sprintf("check failed: %v", err),
				Timestamp: timestamp,
			})
			continue
		}
		for i := range produced {
			if produced[i].Timestamp.IsZero() {
				produced[i].Timestamp = timestamp
			}
		}
		findings = append(findings, produced...)
	}

	return Result{Findings: findings, Graph: graph}, nil
}
