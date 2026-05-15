package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/ingest"

	// Side-effect imports register each format adapter with
	// ingest.Default. Adding a new format here is all it takes to
	// make --format=<name> light up across the CLI.
	_ "github.com/darpanzope/compliancekit/internal/ingest/sarif"
)

// newIngestCmd builds `compliancekit ingest`, which reads an external
// security tool's output and projects it onto compliancekit's
// (resource, finding, framework) model.
//
// Two modes:
//
//   - `ingest --list` enumerates the registered adapters.
//   - `ingest --format=<fmt> --in=<file>` runs the named adapter
//     against the file and writes findings JSON to stdout (or --out).
//
// Integrated ingest (config-driven, runs alongside `scan`) lives in
// the scan command; this subcommand is the standalone path for
// piping or one-shot CI integration.
func newIngestCmd() *cobra.Command {
	var opts ingestOptions
	cmd := &cobra.Command{
		Use:   "ingest",
		Short: "Read external tool output and project it onto compliancekit findings",
		Long: `Read a security tool's output file (SARIF, OCSF, OSCAL Assessment
Results, …) and convert each entry into a compliancekit Finding,
projecting subjects onto the resource graph and attributing rules
to framework controls via the per-tool mapping table.

Examples:

  # See available adapters
  compliancekit ingest --list

  # Read Trivy SARIF, write merged findings to stdout
  trivy fs --format=sarif --output trivy.sarif .
  compliancekit ingest --format=sarif --in=trivy.sarif

  # Read AWS Security Hub OCSF export, write to findings.json
  compliancekit ingest --format=ocsf --in=security-hub.json \
      --tool=aws-security-hub --tool-version=2026-04 \
      --out=findings.json

Output is the same envelope shape as findings.json from a native
scan, so downstream tooling (evidence pack, diff, baseline) treats
ingested findings identically to engine-produced ones.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runIngest(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().BoolVar(&opts.list, "list", false, "list registered adapters and exit")
	cmd.Flags().StringVar(&opts.format, "format", "", "wire format: sarif | ocsf | oscal-ar | oscal-catalog")
	cmd.Flags().StringVar(&opts.in, "in", "", "path to the external tool's output file (- for stdin)")
	cmd.Flags().StringVar(&opts.out, "out", "", "path to write findings JSON (default: stdout)")
	cmd.Flags().StringVar(&opts.tool, "tool", "", "tool identifier for provenance (e.g. trivy, checkov)")
	cmd.Flags().StringVar(&opts.toolVersion, "tool-version", "", "version of the producing tool")
	cmd.Flags().StringVar(&opts.mapping, "mapping", "", "path to a mapping table yaml (overrides built-in)")
	cmd.Flags().BoolVar(&opts.failOnUnmapped, "fail-on-unmapped", false, "error when any external rule lacks a mapping entry")
	cmd.Flags().StringVar(&opts.defaultSeverity, "default-severity", "medium", "severity for findings whose source severity can't be parsed")

	return cmd
}

type ingestOptions struct {
	list            bool
	format          string
	in              string
	out             string
	tool            string
	toolVersion     string
	mapping         string
	failOnUnmapped  bool
	defaultSeverity string
}

func runIngest(ctx context.Context, w io.Writer, opts ingestOptions) error {
	if opts.list {
		return renderIngestList(w)
	}

	if opts.format == "" {
		return fmt.Errorf("--format is required (try --list to see available formats)")
	}
	if opts.in == "" {
		return fmt.Errorf("--in is required (path to the external tool's output, or '-' for stdin)")
	}

	adapter, ok := ingest.Default.Lookup(opts.format)
	if !ok {
		return fmt.Errorf("unknown --format %q; available: %s",
			opts.format, strings.Join(ingest.Default.Formats(), ", "))
	}

	r, closeFn, err := openIngestInput(opts.in)
	if err != nil {
		return err
	}
	defer closeFn()

	defaultSev, err := core.ParseSeverity(opts.defaultSeverity)
	if err != nil {
		return fmt.Errorf("--default-severity: %w", err)
	}

	mapTab, err := loadMappingTable(opts.mapping)
	if err != nil {
		return fmt.Errorf("--mapping %s: %w", opts.mapping, err)
	}

	ingestOpts := ingest.Options{
		Provenance: ingest.Provenance{
			Tool:        opts.tool,
			ToolVersion: opts.toolVersion,
			Format:      opts.format,
			File:        opts.in,
			IngestedAt:  time.Now().UTC(),
		},
		Mapping:         mapTab,
		DefaultSeverity: defaultSev,
		FailOnUnmapped:  opts.failOnUnmapped,
	}

	result, err := adapter.Ingest(ctx, r, ingestOpts)
	if err != nil {
		return fmt.Errorf("ingest %s: %w", opts.format, err)
	}

	return writeIngestResult(w, opts.out, result)
}

// openIngestInput resolves "-" to stdin (no close needed) or opens
// the named path. Returns a close function that's safe to call in
// a defer regardless of which branch ran.
func openIngestInput(path string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}
	f, err := os.Open(path) //nolint:gosec // operator-supplied path; ingest reads files the operator named
	if err != nil {
		return nil, func() {}, fmt.Errorf("open %s: %w", path, err)
	}
	return f, func() { _ = f.Close() }, nil
}

// loadMappingTable reads a mapping table yaml from path. Empty path
// returns nil (adapters tolerate that — built-in tables ship per
// tool in a later phase).
func loadMappingTable(path string) (*ingest.MappingTable, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, err
	}
	var tab ingest.MappingTable
	if err := yaml.Unmarshal(b, &tab); err != nil {
		return nil, fmt.Errorf("yaml decode: %w", err)
	}
	if tab.Tool == "" {
		return nil, fmt.Errorf("mapping table is missing required 'tool' field")
	}
	return &tab, nil
}

// writeIngestResult serializes findings + warnings to JSON in the
// same envelope shape as findings.json so downstream evidence pack
// and diff tooling consume ingested + native findings uniformly.
func writeIngestResult(w io.Writer, outPath string, r ingest.Result) error {
	envelope := struct {
		Schema    string         `json:"schema"`
		Source    string         `json:"source"`
		Timestamp time.Time      `json:"timestamp"`
		Summary   ingestSummary  `json:"summary"`
		Findings  []core.Finding `json:"findings"`
		Warnings  []string       `json:"warnings,omitempty"`
	}{
		Schema:    "compliancekit.ingest.v1",
		Source:    "compliancekit ingest",
		Timestamp: time.Now().UTC(),
		Summary: ingestSummary{
			FindingCount:  len(r.Findings),
			ResourceCount: len(r.Resources),
			WarningCount:  len(r.Warnings),
		},
		Findings: r.Findings,
		Warnings: r.Warnings,
	}

	out, err := openIngestOutput(outPath)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(out.w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(envelope); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", outPath, err)
	}

	// User-visible breadcrumb on stderr only when --out was set so
	// pipe consumers on stdout never see noise.
	if outPath != "" && outPath != "-" {
		fmt.Fprintf(w, "wrote %s (%d findings, %d resources, %d warnings)\n",
			outPath, len(r.Findings), len(r.Resources), len(r.Warnings))
	}
	return nil
}

type ingestSummary struct {
	FindingCount  int `json:"finding_count"`
	ResourceCount int `json:"resource_count"`
	WarningCount  int `json:"warning_count"`
}

// outputSink lets writeIngestResult resolve stdout-vs-file once and
// hand back a Closer that's a no-op for stdout. The struct exists so
// callers can defer close uniformly.
type outputSink struct {
	w     io.Writer
	close func() error
}

func (s outputSink) Close() error {
	if s.close == nil {
		return nil
	}
	return s.close()
}

func openIngestOutput(path string) (outputSink, error) {
	if path == "" || path == "-" {
		return outputSink{w: os.Stdout}, nil
	}
	f, err := os.Create(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return outputSink{}, fmt.Errorf("create %s: %w", path, err)
	}
	return outputSink{w: f, close: f.Close}, nil
}

func renderIngestList(w io.Writer) error {
	formats := ingest.Default.Formats()
	if len(formats) == 0 {
		fmt.Fprintln(w, "No ingest adapters registered.")
		fmt.Fprintln(w, "(v0.13 ships SARIF in Phase 1, OCSF in Phase 2, OSCAL in Phases 4-5.)")
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "FORMAT\tDESCRIPTION")
	for _, f := range formats {
		adapter, _ := ingest.Default.Lookup(f)
		fmt.Fprintf(tw, "%s\t%s\n", adapter.Format(), adapter.Description())
	}
	return tw.Flush()
}
