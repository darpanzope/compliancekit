package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/open-policy-agent/opa/v1/format"
	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/policy"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// newPolicyCmd builds `compliancekit policy` and its three
// subcommands: test, validate, fmt. v0.16+.
//
// The Rego authoring workflow without compliancekit policy
// looks like: edit .rego → run `compliancekit scan --config=...`
// → grep findings for whether the rule fired. That's slow.
// With this subcommand: edit .rego → `compliancekit policy test
// fixture.json policy.rego` → instant pass/fail.
//
// Subcommands:
//
//	test    <fixture.json> <policy.rego>   evaluate against synthetic input
//	validate <dir>                          compile every policy + check metadata
//	fmt     <policy.rego> [...more.rego]   in-place reformat via opa fmt
//
// Per ADR-006 + ADR-011 these are read-only / generate-only; the
// CLI never applies anything to live infrastructure.
func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Author + test + format Rego policies",
		Long: `Workflow tooling for compliancekit's Rego policy DSL (v0.16+).

  compliancekit policy test FIXTURE.json POLICY.rego
      Run POLICY.rego against the synthetic resource graph in
      FIXTURE.json and print the resulting findings.

  compliancekit policy validate DIR
      Compile every .rego under DIR, confirm metadata is well-formed
      and that the catalog ID does not collide with a Go check.

  compliancekit policy fmt POLICY.rego [...more.rego]
      Reformat each policy in place via opa fmt. Idempotent.`,
	}
	cmd.AddCommand(newPolicyTestCmd())
	cmd.AddCommand(newPolicyValidateCmd())
	cmd.AddCommand(newPolicyFmtCmd())
	return cmd
}

// ----------------------------------------------------------------------
// policy test
// ----------------------------------------------------------------------

func newPolicyTestCmd() *cobra.Command {
	var outFormat string
	cmd := &cobra.Command{
		Use:   "test FIXTURE.json POLICY.rego",
		Short: "Evaluate POLICY.rego against a synthetic resource graph",
		Long: `Evaluate the Rego policy at POLICY.rego against a synthetic
resource graph loaded from FIXTURE.json. The fixture is a JSON
array of compliancekit.Resource objects:

  [
    {
      "id": "aws.s3.bucket.demo",
      "type": "aws.s3.bucket",
      "name": "demo",
      "provider": "aws",
      "region": "us-east-1",
      "attributes": {"public": true, "encryption": "AES256"},
      "tags": ["prod"]
    }
  ]

The policy is loaded, compiled, and evaluated against that graph;
the resulting findings are written to stdout as JSON.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyTest(cmd.Context(), cmd.OutOrStdout(), args[0], args[1], outFormat)
		},
	}
	cmd.Flags().StringVar(&outFormat, "format", "json", "output format: json | table")
	return cmd
}

func runPolicyTest(ctx context.Context, stdout io.Writer, fixturePath, policyPath, outFormat string) error {
	graph, err := loadFixtureGraph(fixturePath)
	if err != nil {
		return fmt.Errorf("load fixture: %w", err)
	}
	m, err := policy.LoadFile(ctx, policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	findings, err := m.Evaluate(ctx, graph)
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}
	switch outFormat {
	case "json", "":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(findings)
	case "table":
		return renderFindingsTable(stdout, findings)
	}
	return fmt.Errorf("unknown --format=%q (want json | table)", outFormat)
}

func renderFindingsTable(w io.Writer, findings []compliancekit.Finding) error {
	fmt.Fprintf(w, "%d finding(s)\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(w, "  [%s] %s on %s — %s\n", f.Severity, f.Status, f.Resource.ID, f.Message)
	}
	return nil
}

// loadFixtureGraph reads a JSON file containing an array of
// compliancekit.Resource and projects it into a ResourceGraph.
func loadFixtureGraph(path string) (*compliancekit.ResourceGraph, error) {
	// #nosec G304 — operator-supplied fixture path; this is the CLI's
	// documented input.
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var resources []compliancekit.Resource
	if err := json.Unmarshal(body, &resources); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	g := compliancekit.NewResourceGraph()
	for _, r := range resources {
		g.Add(r)
	}
	return g, nil
}

// ----------------------------------------------------------------------
// policy validate
// ----------------------------------------------------------------------

func newPolicyValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate DIR",
		Short: "Compile + metadata-check every .rego in DIR",
		Long: `Walk DIR for .rego files, compile each, verify the metadata
object is well-formed, and confirm the catalog ID does not collide
with a Go check. Reports a summary and exits non-zero on any error.

Useful as a CI gate (` + "`compliancekit policy validate ./policies`" + `) to
catch malformed policies before they ship.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyValidate(cmd.Context(), cmd.OutOrStdout(), args[0])
		},
	}
	return cmd
}

func runPolicyValidate(ctx context.Context, stdout io.Writer, dir string) error {
	modules, errs := policy.LoadDir(ctx, dir)
	fmt.Fprintf(stdout, "Loaded %d policy module(s) from %s\n", len(modules), dir)
	for _, m := range modules {
		fmt.Fprintf(stdout, "  ✓ %s — %s [severity=%s]\n", m.Check.ID, m.SourcePath, m.Check.Severity)
	}
	if len(errs) == 0 {
		return nil
	}
	fmt.Fprintf(stdout, "\n%d error(s):\n", len(errs))
	for i, e := range errs {
		fmt.Fprintf(stdout, "  %d) %v\n", i+1, e)
	}
	return fmt.Errorf("policy validate failed with %d error(s)", len(errs))
}

// ----------------------------------------------------------------------
// policy fmt
// ----------------------------------------------------------------------

func newPolicyFmtCmd() *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "fmt POLICY.rego [...more.rego]",
		Short: "Reformat Rego policies in place via opa fmt",
		Long: `Reformat each policy in place using OPA's canonical formatter.
Idempotent — running fmt on an already-formatted file is a no-op.

With --check, do not modify files; instead exit non-zero if any
file would be reformatted. Useful as a CI lint gate.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyFmt(cmd.OutOrStdout(), args, check)
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "exit non-zero if any file would change; do not rewrite")
	return cmd
}

func runPolicyFmt(stdout io.Writer, paths []string, checkOnly bool) error {
	changed := 0
	for _, p := range paths {
		// #nosec G304 — operator-supplied policy path.
		orig, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}
		formatted, err := format.Source(p, orig)
		if err != nil {
			return fmt.Errorf("format %s: %w", p, err)
		}
		if bytes.Equal(formatted, orig) {
			continue
		}
		changed++
		if checkOnly {
			fmt.Fprintf(stdout, "would reformat: %s\n", p)
			continue
		}
		// #nosec G306 — preserve original mode; policies are operator-readable.
		if err := os.WriteFile(p, formatted, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", p, err)
		}
		fmt.Fprintf(stdout, "reformatted: %s\n", p)
	}
	if checkOnly && changed > 0 {
		return fmt.Errorf("%d file(s) need reformatting", changed)
	}
	if !checkOnly {
		fmt.Fprintf(stdout, "%d file(s) reformatted, %d already clean\n", changed, len(paths)-changed)
	}
	return nil
}
