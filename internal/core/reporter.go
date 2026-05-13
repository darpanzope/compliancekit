package core

import (
	"context"
	"io"
)

// Reporter renders a set of Findings to a writer in a specific format.
//
// One Reporter exists per output format -- "json", "html", "sarif",
// "json-ocsf", "markdown", "evidence-pack" -- and lives in its own
// subpackage under internal/reporters/. The scan command builds the
// reporter set from config.Output.Format and runs each against the
// final findings list.
//
// Reporters are stateless: a single Reporter value may be reused
// across scans. They must not mutate their Findings or graph inputs.
type Reporter interface {
	// Format returns the lowercase identifier matching the config value
	// (e.g. "json", "html"). The scan command compares against this.
	Format() string

	// Render writes findings in this reporter's format. The graph is
	// passed so reporters that need raw resource detail (the evidence
	// pack reporter at v0.4, primarily) can access it without forcing
	// every check to denormalize attributes into Findings.
	//
	// Implementations must honor ctx.Done() -- a large evidence pack
	// can take meaningful wall time to write.
	Render(ctx context.Context, findings []Finding, graph *ResourceGraph, w io.Writer) error
}
