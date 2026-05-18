package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/darpanzope/compliancekit/internal/config"
	"github.com/darpanzope/compliancekit/internal/engine"
	"github.com/darpanzope/compliancekit/internal/ingest"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// mergeConfigIngest is the runScan-side wrapper around
// runIngestSources. It appends ingested findings to result.Findings,
// surfaces ingest warnings on stderr-ish (w), runs the v0.14
// image-SHA correlation pass to cross-reference ingested CVEs with
// running cloud resources, and reports a summary line. Extracted
// from runScan so the host function stays under gocyclo's 15-edge
// ceiling.
func mergeConfigIngest(ctx context.Context, w io.Writer, result *engine.Result, sources []config.IngestSource) error {
	if len(sources) == 0 {
		return nil
	}
	findings, warns, err := runIngestSources(ctx, sources, result.Graph)
	if err != nil {
		return fmt.Errorf("ingest: %w", err)
	}
	result.Findings = append(result.Findings, findings...)
	for _, ww := range warns {
		fmt.Fprintf(w, "ingest warning: %s\n", ww)
	}
	fmt.Fprintf(w, "merged %d ingested finding(s) from %d source(s)\n", len(findings), len(sources))

	// v0.14 Phase 5: image-SHA correlation. Ingested CVE findings
	// pinned to a container image get cloned onto every cloud
	// resource in the live graph referencing the same SHA, so an
	// auditor pivoting through "what's wrong with this Deployment"
	// sees the upstream image's CVEs too.
	expanded, added := ingest.CorrelateImageSHA(result.Findings, result.Graph)
	result.Findings = expanded
	if added > 0 {
		fmt.Fprintf(w, "correlated %d additional finding(s) via image-SHA join\n", added)
	}
	return nil
}

// runIngestSources executes every ingest source declared in
// cfg.Ingest after the native scan completes. Findings are accumulated
// and merged into the engine result; phantom resources are added to
// the live graph so reporters that look up resources by ID
// (control-mapping.csv, evidence pack) find them.
//
// Warnings are accumulated rather than aborting on the first one —
// an ingest source missing a mapping for one rule should not stop
// the rest of the pipeline.
func runIngestSources(
	ctx context.Context,
	sources []config.IngestSource,
	graph *compliancekit.ResourceGraph,
) ([]compliancekit.Finding, []string, error) {
	var (
		merged   []compliancekit.Finding
		warnings []string
	)

	for i, src := range sources {
		if src.Format == "" {
			return nil, nil, fmt.Errorf("ingest[%d]: format is required", i)
		}
		if src.File == "" {
			return nil, nil, fmt.Errorf("ingest[%d]: file is required", i)
		}

		adapter, ok := ingest.Default.Lookup(src.Format)
		if !ok {
			return nil, nil, fmt.Errorf("ingest[%d]: unknown format %q", i, src.Format)
		}

		f, err := os.Open(src.File) //nolint:gosec // operator-supplied path
		if err != nil {
			return nil, nil, fmt.Errorf("ingest[%d] open %s: %w", i, src.File, err)
		}

		mapping, err := loadIngestMapping(src.Mapping)
		if err != nil {
			_ = f.Close()
			return nil, nil, fmt.Errorf("ingest[%d] mapping: %w", i, err)
		}

		opts := ingest.Options{
			Provenance: ingest.Provenance{
				Tool:        src.Tool,
				ToolVersion: src.ToolVersion,
				Format:      src.Format,
				File:        src.File,
				IngestedAt:  time.Now().UTC(),
			},
			Mapping:        mapping,
			Graph:          graph,
			FailOnUnmapped: src.FailOnUnmapped,
		}

		result, err := adapter.Ingest(ctx, f, opts)
		_ = f.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("ingest[%d] %s: %w", i, src.Format, err)
		}

		merged = append(merged, result.Findings...)
		for _, w := range result.Warnings {
			warnings = append(warnings, fmt.Sprintf("[%s] %s", src.Format, w))
		}

		// Add phantom resources to the live graph. The graph is
		// shared with the evidence-pack writer, so ingested findings
		// that reference a phantom resource will resolve cleanly when
		// downstream code calls Graph.ByID.
		if graph != nil {
			for _, r := range result.Resources {
				resourceCopy := r // capture loop variable; Add takes value
				graph.Add(resourceCopy)
			}
		}
	}
	return merged, warnings, nil
}

// loadIngestMapping reads a custom mapping table from disk, or
// returns nil when src.Mapping is empty (adapters fall through to
// the built-in table via Provenance.Tool).
func loadIngestMapping(path string) (*ingest.MappingTable, error) {
	if path == "" {
		return nil, nil //nolint:nilnil // empty path → no mapping is a valid state, not an error
	}
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, err
	}
	var tab ingest.MappingTable
	if err := yaml.Unmarshal(b, &tab); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if tab.Tool == "" {
		return nil, fmt.Errorf("%s: missing 'tool' field", path)
	}
	return &tab, nil
}
