package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/frameworks"
	"github.com/darpanzope/compliancekit/internal/policy"
	"github.com/darpanzope/compliancekit/internal/ui"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// padRightLabel right-pads a label string with spaces. Mirrors the
// internal/ui padding helper but lives here so the cli package
// doesn't need to import a single helper through ui — the ui
// package's padRight is unexported by design (a single source of
// truth for table renderers).
func padRightLabel(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// newChecksCmd builds the `compliancekit checks` parent command.
// Subcommands: `list` (catalog query) and `show` (per-check detail).
//
// The check catalog is the read-only set of all compliancekit checks
// available in this binary: per-provider files in internal/checks/
// register themselves via init() so the catalog is whatever was
// compiled in.
func newChecksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "checks",
		Short: "Query the registered check catalog",
		Long: `Read-only queries over the check catalog compiled into this binary.

  checks list           list every registered check (filterable)
  checks show <id>      show full metadata for one check
  checks new <id>       scaffold a new plugin directory (v1.13)`,
	}
	cmd.AddCommand(newChecksListCmd())
	cmd.AddCommand(newChecksShowCmd())
	cmd.AddCommand(newChecksNewCmd())
	return cmd
}

// ----------------------------------------------------------------------
// checks list
// ----------------------------------------------------------------------

type checksListOptions struct {
	framework string
	provider  string
	severity  string
	format    string
}

func newChecksListCmd() *cobra.Command {
	var opts checksListOptions
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List registered checks with optional filtering",
		Long: `List the check catalog. Filters are AND-ed.

  --framework=soc2   include only checks mapped to the soc2 framework
  --provider=linux   include only checks from the linux provider
  --severity=high    include only checks at this level OR HIGHER

  --format=table     human-readable column table (default)
  --format=json      JSON array of full Check metadata
  --format=csv       header + one row per check`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runChecksList(cmd.OutOrStdout(), stylerFor(cmd), opts)
		},
	}
	cmd.Flags().StringVar(&opts.framework, "framework", "", "filter by framework ID (soc2, cis-v8)")
	cmd.Flags().StringVar(&opts.provider, "provider", "", "filter by provider (digitalocean, linux)")
	cmd.Flags().StringVar(&opts.severity, "severity", "", "filter by severity (info|low|medium|high|critical) and higher")
	cmd.Flags().StringVar(&opts.format, "format", "table", "output format: table | json | csv")
	return cmd
}

func runChecksList(w io.Writer, st *ui.Styler, opts checksListOptions) error {
	checks := compliancekit.RegisteredChecks()

	if opts.framework != "" {
		checks = filterChecksByFramework(checks, opts.framework)
	}
	if opts.provider != "" {
		checks = filterChecksByProvider(checks, opts.provider)
	}
	if opts.severity != "" {
		threshold, err := compliancekit.ParseSeverity(opts.severity)
		if err != nil {
			return fmt.Errorf("--severity: %w", err)
		}
		checks = filterChecksBySeverity(checks, threshold)
	}

	switch opts.format {
	case "", "table":
		return renderChecksTable(w, st, checks)
	case "json":
		return renderChecksJSON(w, checks)
	case "csv":
		return renderChecksCSV(w, checks)
	default:
		return fmt.Errorf("unknown --format %q (want: table, json, csv)", opts.format)
	}
}

func filterChecksByFramework(checks []compliancekit.Check, framework string) []compliancekit.Check {
	out := make([]compliancekit.Check, 0, len(checks))
	for _, c := range checks {
		if _, ok := c.Frameworks[framework]; ok {
			out = append(out, c)
		}
	}
	return out
}

func filterChecksByProvider(checks []compliancekit.Check, provider string) []compliancekit.Check {
	// v1.15.1 phase 5 — `k8s` is the documented short form (CLI
	// help, ROADMAP, `scan k8s`); checks are tagged `kubernetes`
	// internally. Audit caught --provider=k8s returning 0 checks.
	if provider == "k8s" {
		provider = "kubernetes"
	}
	out := make([]compliancekit.Check, 0, len(checks))
	for _, c := range checks {
		if c.Provider == provider {
			out = append(out, c)
		}
	}
	return out
}

// filterChecksBySeverity keeps checks at the given severity or higher.
// Severity is ordered ascending in core (Info < Low < ... < Critical),
// so "at or above" is a single >= comparison.
func filterChecksBySeverity(checks []compliancekit.Check, threshold compliancekit.Severity) []compliancekit.Check {
	out := make([]compliancekit.Check, 0, len(checks))
	for _, c := range checks {
		if c.Severity >= threshold {
			out = append(out, c)
		}
	}
	return out
}

func renderChecksTable(w io.Writer, st *ui.Styler, checks []compliancekit.Check) error {
	tbl := ui.NewTable("ID", "SEVERITY", "PROVIDER", "SOURCE", "TITLE")
	tbl.MaxWidth(4, 60) // truncate long titles so long-checkout terminals don't wrap

	regoCount := 0
	for _, c := range checks {
		src := "go"
		if c.Policy != "" {
			src = "rego"
			regoCount++
		}
		tbl.AddRow(c.ID, st.InSeverity(strings.ToUpper(c.Severity.String()), c.Severity), c.Provider, src, c.Title)
	}
	if _, err := io.WriteString(w, tbl.Render(st)); err != nil {
		return err
	}
	if regoCount > 0 {
		fmt.Fprintf(w, "\n%s check(s) — %d Go, %d Rego\n", st.Accent(fmt.Sprintf("%d", len(checks))), len(checks)-regoCount, regoCount)
	} else {
		fmt.Fprintf(w, "\n%s check(s)\n", st.Accent(fmt.Sprintf("%d", len(checks))))
	}
	return nil
}

func renderChecksJSON(w io.Writer, checks []compliancekit.Check) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(checks)
}

func renderChecksCSV(w io.Writer, checks []compliancekit.Check) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"id", "severity", "provider", "service", "title", "frameworks"}); err != nil {
		return err
	}
	for _, c := range checks {
		// Flatten the framework map to "soc2:CC6.1,CC6.6 | cis-v8:3.3"
		// so the CSV stays single-row-per-check.
		fwParts := make([]string, 0, len(c.Frameworks))
		for fw, controls := range c.Frameworks {
			fwParts = append(fwParts, fw+":"+strings.Join(controls, ","))
		}
		err := cw.Write([]string{
			c.ID, c.Severity.String(), c.Provider, c.Service, c.Title,
			strings.Join(fwParts, " | "),
		})
		if err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// ----------------------------------------------------------------------
// checks show
// ----------------------------------------------------------------------

func newChecksShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <check-id>",
		Short: "Show full metadata for one check",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runChecksShow(cmd.OutOrStdout(), stylerFor(cmd), args[0])
		},
	}
	return cmd
}

func runChecksShow(w io.Writer, st *ui.Styler, id string) error {
	check, ok := compliancekit.LookupCheck(id)
	if !ok {
		return fmt.Errorf("check %q not registered", id)
	}

	label := func(name string) string { return st.Muted(padRightLabel(name, 12)) }
	fmt.Fprintf(w, "%s%s\n", label("ID:"), st.Accent(check.ID))
	fmt.Fprintf(w, "%s%s\n", label("Title:"), check.Title)
	fmt.Fprintf(w, "%s%s\n", label("Severity:"), st.SeverityChip(check.Severity))
	fmt.Fprintf(w, "%s%s\n", label("Provider:"), check.Provider)
	if check.Service != "" {
		fmt.Fprintf(w, "%s%s\n", label("Service:"), check.Service)
	}
	if check.ResourceType != "" {
		fmt.Fprintf(w, "%s%s\n", label("Resource:"), check.ResourceType)
	}

	section := func(name string) { fmt.Fprintln(w, "\n"+st.Bold(name)) }

	if check.Description != "" {
		section("Description:")
		fmt.Fprintln(w, indentBlock(check.Description))
	}
	if check.Rationale != "" {
		section("Rationale:")
		fmt.Fprintln(w, indentBlock(check.Rationale))
	}
	if check.Remediation != "" {
		section("Remediation:")
		fmt.Fprintln(w, indentBlock(check.Remediation))
	}

	resolved := frameworks.ResolveCheckControls(check.Frameworks)
	if len(resolved) > 0 {
		section("Framework mappings:")
		fwTbl := ui.NewTable("FRAMEWORK", "CONTROL", "NAME")
		for _, rc := range resolved {
			fwTbl.AddRow(rc.Framework.ID, rc.Control.ID, rc.Control.Name)
		}
		fmt.Fprint(w, fwTbl.Render(st))
	}

	if len(check.Tags) > 0 {
		fmt.Fprintf(w, "\n%s%s\n", st.Bold("Tags: "), strings.Join(check.Tags, ", "))
	}
	if len(check.References) > 0 {
		section("References:")
		for _, r := range check.References {
			fmt.Fprintf(w, "  %s %s\n", st.Muted(st.Glyph("arrow")), r)
		}
	}

	// Rego-backed checks: surface the source file path and body so
	// operators can audit what's actually running without digging
	// through the repo. Go-backed checks have no equivalent surface
	// — their CheckFunc lives in compiled binary — so the section
	// is conditional on Check.Policy being set.
	if check.Policy != "" {
		fmt.Fprintf(w, "\n%s%s\n", st.Bold("Source: "), st.Muted("Rego ("+check.Policy+")"))
		if m := policy.Lookup(check.ID); m != nil && m.Body != "" {
			section("Policy body:")
			fmt.Fprintln(w, indentBlock(m.Body))
		}
	} else {
		fmt.Fprintf(w, "\n%s%s\n", st.Bold("Source: "), st.Muted("Go (internal/checks/...)"))
	}

	return nil
}

// indentBlock prefixes every line of s with two spaces. Used for the
// description / remediation blocks in `checks show` so multi-line
// strings render as a visually-grouped block under their heading.
//
// Hard-coded indent rather than a parameter -- every caller wants the
// same two-space form, and a parameter would just hide that.
func indentBlock(s string) string {
	const prefix = "  "
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, ln := range lines {
		lines[i] = prefix + ln
	}
	return strings.Join(lines, "\n")
}
