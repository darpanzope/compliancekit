package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/frameworks"
)

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
  checks show <id>      show full metadata for one check`,
	}
	cmd.AddCommand(newChecksListCmd())
	cmd.AddCommand(newChecksShowCmd())
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
			return runChecksList(cmd.OutOrStdout(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.framework, "framework", "", "filter by framework ID (soc2, cis-v8)")
	cmd.Flags().StringVar(&opts.provider, "provider", "", "filter by provider (digitalocean, linux)")
	cmd.Flags().StringVar(&opts.severity, "severity", "", "filter by severity (info|low|medium|high|critical) and higher")
	cmd.Flags().StringVar(&opts.format, "format", "table", "output format: table | json | csv")
	return cmd
}

func runChecksList(w io.Writer, opts checksListOptions) error {
	checks := core.RegisteredChecks()

	if opts.framework != "" {
		checks = filterChecksByFramework(checks, opts.framework)
	}
	if opts.provider != "" {
		checks = filterChecksByProvider(checks, opts.provider)
	}
	if opts.severity != "" {
		threshold, err := core.ParseSeverity(opts.severity)
		if err != nil {
			return fmt.Errorf("--severity: %w", err)
		}
		checks = filterChecksBySeverity(checks, threshold)
	}

	switch opts.format {
	case "", "table":
		return renderChecksTable(w, checks)
	case "json":
		return renderChecksJSON(w, checks)
	case "csv":
		return renderChecksCSV(w, checks)
	default:
		return fmt.Errorf("unknown --format %q (want: table, json, csv)", opts.format)
	}
}

func filterChecksByFramework(checks []core.Check, framework string) []core.Check {
	out := make([]core.Check, 0, len(checks))
	for _, c := range checks {
		if _, ok := c.Frameworks[framework]; ok {
			out = append(out, c)
		}
	}
	return out
}

func filterChecksByProvider(checks []core.Check, provider string) []core.Check {
	out := make([]core.Check, 0, len(checks))
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
func filterChecksBySeverity(checks []core.Check, threshold core.Severity) []core.Check {
	out := make([]core.Check, 0, len(checks))
	for _, c := range checks {
		if c.Severity >= threshold {
			out = append(out, c)
		}
	}
	return out
}

func renderChecksTable(w io.Writer, checks []core.Check) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tPROVIDER\tTITLE")
	for _, c := range checks {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.ID, c.Severity, c.Provider, c.Title)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\n%d check(s)\n", len(checks))
	return nil
}

func renderChecksJSON(w io.Writer, checks []core.Check) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(checks)
}

func renderChecksCSV(w io.Writer, checks []core.Check) error {
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
			return runChecksShow(cmd.OutOrStdout(), args[0])
		},
	}
	return cmd
}

func runChecksShow(w io.Writer, id string) error {
	check, ok := core.LookupCheck(id)
	if !ok {
		return fmt.Errorf("check %q not registered", id)
	}

	fmt.Fprintf(w, "ID:          %s\n", check.ID)
	fmt.Fprintf(w, "Title:       %s\n", check.Title)
	fmt.Fprintf(w, "Severity:    %s\n", check.Severity)
	fmt.Fprintf(w, "Provider:    %s\n", check.Provider)
	if check.Service != "" {
		fmt.Fprintf(w, "Service:     %s\n", check.Service)
	}
	if check.ResourceType != "" {
		fmt.Fprintf(w, "Resource:    %s\n", check.ResourceType)
	}

	if check.Description != "" {
		fmt.Fprintln(w, "\nDescription:")
		fmt.Fprintln(w, indentBlock(check.Description))
	}
	if check.Rationale != "" {
		fmt.Fprintln(w, "\nRationale:")
		fmt.Fprintln(w, indentBlock(check.Rationale))
	}
	if check.Remediation != "" {
		fmt.Fprintln(w, "\nRemediation:")
		fmt.Fprintln(w, indentBlock(check.Remediation))
	}

	resolved := frameworks.ResolveCheckControls(check.Frameworks)
	if len(resolved) > 0 {
		fmt.Fprintln(w, "\nFramework mappings:")
		for _, rc := range resolved {
			fmt.Fprintf(w, "  %-12s %-12s %s\n", rc.Framework.ID, rc.Control.ID, rc.Control.Name)
		}
	}

	if len(check.Tags) > 0 {
		fmt.Fprintf(w, "\nTags: %s\n", strings.Join(check.Tags, ", "))
	}
	if len(check.References) > 0 {
		fmt.Fprintln(w, "\nReferences:")
		for _, r := range check.References {
			fmt.Fprintf(w, "  %s\n", r)
		}
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
