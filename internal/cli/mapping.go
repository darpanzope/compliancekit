package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/darpanzope/compliancekit/internal/frameworks"
	"github.com/darpanzope/compliancekit/internal/ingest"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// newMappingCmd builds `compliancekit mapping`, a parent for managing
// the per-tool framework-mapping tables that translate ingested rule
// IDs (Trivy AVD, Checkov CKV_*, AWS Security Hub FSBP, …) into
// compliancekit framework controls. v0.13+.
//
// Subcommands:
//
//	list                       list every tool with a built-in mapping
//	show <tool>                dump the mapping table as YAML
//	validate <file>            structural + cross-registry validation
//	diff <tool> <override>     show added / changed / removed rules
//	                           between a built-in table and a custom
//	                           override file (operator's tailored map)
func newMappingCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mapping",
		Short: "Inspect and validate framework mapping tables",
		Long: `Manage the per-tool mapping tables compliancekit uses to
attribute ingested findings (SARIF / OCSF) to framework controls.

Mapping tables are yaml files. The binary ships one per supported
tool / product (Trivy, Checkov, KICS, Terrascan, AWS Security Hub,
GCP SCC, Defender for Cloud). Operators override via --mapping=...
on 'compliancekit ingest', or via the ingest: block in
compliancekit.yaml.

  mapping list                  list bundled tables
  mapping show <tool>           print a bundled table as yaml
  mapping validate <file>       validate a custom table
  mapping diff <tool> <file>    diff a custom override vs the built-in`,
	}
	cmd.AddCommand(newMappingListCmd())
	cmd.AddCommand(newMappingShowCmd())
	cmd.AddCommand(newMappingValidateCmd())
	cmd.AddCommand(newMappingDiffCmd())
	return cmd
}

// ---------------------- list ----------------------

func newMappingListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every tool with a built-in mapping table",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMappingList(cmd.OutOrStdout())
		},
	}
}

func runMappingList(w io.Writer) error {
	tables := ingest.AllBuiltinMappings()
	if len(tables) == 0 {
		fmt.Fprintln(w, "No built-in mapping tables registered.")
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TOOL\tRULES\tVERSION\tDESCRIPTION")
	keys := make([]string, 0, len(tables))
	for k := range tables {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t := tables[k]
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", t.Tool, len(t.Rules), t.Version, t.Description)
	}
	return tw.Flush()
}

// ---------------------- show ----------------------

func newMappingShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <tool>",
		Short: "Print a built-in mapping table as yaml",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMappingShow(cmd.OutOrStdout(), args[0])
		},
	}
}

func runMappingShow(w io.Writer, toolID string) error {
	tab, ok := ingest.LookupBuiltinMapping(toolID)
	if !ok {
		available := strings.Join(sortedKeys(ingest.AllBuiltinMappings()), ", ")
		return fmt.Errorf("no built-in mapping for tool %q; available: %s", toolID, available)
	}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	defer func() { _ = enc.Close() }()
	return enc.Encode(tab)
}

// ---------------------- validate ----------------------

func newMappingValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <file>",
		Short: "Validate a custom mapping table against the framework registry",
		Long: `Read a mapping yaml from <file> and check:

  - tool field present
  - every rule maps to at least one (framework, control) pair
  - every framework id is known (embedded or runtime-registered)
  - every control id exists within its named framework
  - severity values (if set) parse via compliancekit.ParseSeverity

Reports problems one per line; exits non-zero if any are found.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMappingValidate(cmd.OutOrStdout(), args[0])
		},
	}
}

func runMappingValidate(w io.Writer, path string) error {
	tab, err := loadMappingTableFromFile(path)
	if err != nil {
		return err
	}

	problems := validateMappingTable(tab)
	if len(problems) == 0 {
		fmt.Fprintf(w, "✓ %s: valid (%d rules)\n", path, len(tab.Rules))
		return nil
	}
	for _, p := range problems {
		fmt.Fprintln(w, p)
	}
	return fmt.Errorf("%d problem(s) in %s", len(problems), path)
}

func validateMappingTable(tab *ingest.MappingTable) []string {
	var problems []string
	if tab.Tool == "" {
		problems = append(problems, "missing required 'tool' field")
	}
	for ruleID, rule := range tab.Rules {
		if len(rule.Controls) == 0 {
			problems = append(problems, fmt.Sprintf("rule %q: zero controls (must map to at least one)", ruleID))
		}
		for _, c := range rule.Controls {
			fw, ok := frameworks.Get(c.Framework)
			if !ok {
				problems = append(problems, fmt.Sprintf("rule %q: unknown framework %q", ruleID, c.Framework))
				continue
			}
			if _, ok := fw.Controls[c.Control]; !ok {
				problems = append(problems, fmt.Sprintf("rule %q: framework %q has no control %q", ruleID, c.Framework, c.Control))
			}
		}
		if rule.Severity != "" {
			if _, err := compliancekit.ParseSeverity(rule.Severity); err != nil {
				problems = append(problems, fmt.Sprintf("rule %q: bad severity %q (%v)", ruleID, rule.Severity, err))
			}
		}
	}
	return problems
}

// ---------------------- diff ----------------------

func newMappingDiffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff <tool> <override-file>",
		Short: "Diff a custom override file against the built-in mapping for <tool>",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMappingDiff(cmd.OutOrStdout(), args[0], args[1])
		},
	}
}

func runMappingDiff(w io.Writer, toolID, overridePath string) error {
	builtIn, ok := ingest.LookupBuiltinMapping(toolID)
	if !ok {
		return fmt.Errorf("no built-in mapping for tool %q", toolID)
	}
	custom, err := loadMappingTableFromFile(overridePath)
	if err != nil {
		return err
	}

	var added, removed, changed []string
	for ruleID := range custom.Rules {
		if _, ok := builtIn.Rules[ruleID]; !ok {
			added = append(added, ruleID)
		} else {
			a := builtIn.Rules[ruleID]
			b := custom.Rules[ruleID]
			if !sameRule(a, b) {
				changed = append(changed, ruleID)
			}
		}
	}
	for ruleID := range builtIn.Rules {
		if _, ok := custom.Rules[ruleID]; !ok {
			removed = append(removed, ruleID)
		}
	}
	sort.Strings(added)
	sort.Strings(changed)
	sort.Strings(removed)

	fmt.Fprintf(w, "diff %s (built-in) vs %s\n\n", toolID, overridePath)
	fmt.Fprintf(w, "added (%d):    %s\n", len(added), strings.Join(added, ", "))
	fmt.Fprintf(w, "changed (%d):  %s\n", len(changed), strings.Join(changed, ", "))
	fmt.Fprintf(w, "removed (%d):  %s\n", len(removed), strings.Join(removed, ", "))
	return nil
}

func sameRule(a, b ingest.MappingRule) bool {
	if a.Severity != b.Severity {
		return false
	}
	if len(a.Controls) != len(b.Controls) || len(a.Tags) != len(b.Tags) {
		return false
	}
	for i := range a.Controls {
		if a.Controls[i] != b.Controls[i] {
			return false
		}
	}
	for i := range a.Tags {
		if a.Tags[i] != b.Tags[i] {
			return false
		}
	}
	return true
}

// ---------------------- helpers ----------------------

func loadMappingTableFromFile(path string) (*ingest.MappingTable, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var tab ingest.MappingTable
	if err := yaml.Unmarshal(b, &tab); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return &tab, nil
}

func sortedKeys(m map[string]*ingest.MappingTable) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
