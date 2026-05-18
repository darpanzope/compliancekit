package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/remediate/poam"
	"github.com/darpanzope/compliancekit/internal/remediate/runbook"
	"github.com/darpanzope/compliancekit/internal/remediate/tickets"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"

	// Side-effect imports register each format adapter with
	// remediate.Default. Adding a new format subpackage here is all
	// it takes to make --format=<name> work + the strategies in that
	// package become available everywhere the registry is queried.
	_ "github.com/darpanzope/compliancekit/internal/remediate/ansible"
	_ "github.com/darpanzope/compliancekit/internal/remediate/awscli"
	_ "github.com/darpanzope/compliancekit/internal/remediate/azcli"
	_ "github.com/darpanzope/compliancekit/internal/remediate/bash"
	_ "github.com/darpanzope/compliancekit/internal/remediate/doctl"
	_ "github.com/darpanzope/compliancekit/internal/remediate/gcloud"
	_ "github.com/darpanzope/compliancekit/internal/remediate/hcloud"
	_ "github.com/darpanzope/compliancekit/internal/remediate/helm"
	_ "github.com/darpanzope/compliancekit/internal/remediate/kubectl"
	_ "github.com/darpanzope/compliancekit/internal/remediate/terraform"
)

// newRemediateCmd builds `compliancekit remediate`, which reads a
// findings JSON file (output of `scan` or `ingest`) and writes the
// remediation artifacts into an output directory:
//
//   - remediation.md       — operator runbook
//   - remediate.sh         — RiskSafe bulk-apply script
//   - remediate-<format>/  — per-format snippet files
//   - poam.oscal.json      — OSCAL POA&M for manual items
//
// Per ADR-006 / ADR-011 the command is GENERATION ONLY — it never
// calls cloud APIs or kubectl. Operators apply the artifacts; ticket
// integration files Jira/Linear issues when credentials are present
// via env vars (JIRA_HOST/JIRA_EMAIL/JIRA_TOKEN/JIRA_PROJECT or
// LINEAR_API_KEY/LINEAR_TEAM_ID).
func newRemediateCmd() *cobra.Command {
	var opts remediateOptions
	cmd := &cobra.Command{
		Use:   "remediate",
		Short: "Generate fix-it artifacts (Terraform, kubectl, CLI, Helm, Ansible, bash) from findings",
		Long: `Read a compliancekit findings JSON file and emit:

  - remediation.md       — operator runbook grouping snippets by risk class.
  - remediate.sh         — bash script bundling the safe-class fixes.
  - remediate-<format>/  — per-resource snippet files (one directory per format).
  - poam.oscal.json      — OSCAL v1.1.2 POA&M for manual / unmatched findings.

Examples:

  # See registered strategies and the CheckIDs they handle
  compliancekit remediate --list

  # Generate every format the strategies support for the findings
  compliancekit scan --config=compliancekit.yaml --out=findings.json
  compliancekit remediate --in=findings.json --out=./remediation

  # Limit to a single format
  compliancekit remediate --in=findings.json --out=./remediation --format=terraform

  # Also file Jira tickets for manual items (env-driven; safe to leave unset)
  export JIRA_HOST=acme.atlassian.net JIRA_EMAIL=bot@acme.com \
         JIRA_TOKEN=$(pass jira/api-token) JIRA_PROJECT=SEC
  compliancekit remediate --in=findings.json --out=./remediation --tickets

Per ADR-006 + ADR-011: this command is GENERATION ONLY. Operators
apply the artifacts; --apply-fix is a v2.x trust gate, intentionally
deferred. Risk classes (safe / review / manual) flow from each
strategy and gate the bulk-apply script and POA&M routing.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRemediate(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().BoolVar(&opts.list, "list", false, "list registered strategies and the CheckIDs they handle")
	cmd.Flags().StringVar(&opts.in, "in", "", "path to findings JSON (output of `scan` or `ingest`; - for stdin)")
	cmd.Flags().StringVar(&opts.out, "out", "./remediation", "output directory for generated artifacts")
	cmd.Flags().StringVar(&opts.format, "format", "", "restrict to a single output format (default: all available)")
	cmd.Flags().StringVar(&opts.project, "project", "", "project identifier stamped into runbook + POA&M (default: compliancekit)")
	cmd.Flags().StringVar(&opts.period, "period", "", "assessment period for POA&M (default: derived from current quarter)")
	cmd.Flags().BoolVar(&opts.tickets, "tickets", false, "file Jira/Linear tickets for manual items (credentials via env vars)")

	return cmd
}

type remediateOptions struct {
	list    bool
	in      string
	out     string
	format  string
	project string
	period  string
	tickets bool
}

func runRemediate(ctx context.Context, stdout io.Writer, opts remediateOptions) error {
	if opts.list {
		return runRemediateList(stdout)
	}
	if opts.in == "" {
		return fmt.Errorf("remediate: --in is required (path to findings JSON or '-' for stdin)")
	}

	findings, err := loadRemediateFindings(opts.in)
	if err != nil {
		return fmt.Errorf("load findings: %w", err)
	}

	// Restrict formats if --format was passed.
	var formats []remediate.Format
	if opts.format != "" {
		f, err := remediate.ParseFormat(opts.format)
		if err != nil {
			return fmt.Errorf("--format: %w", err)
		}
		formats = []remediate.Format{f}
	}

	snippets, unmatched := remediate.Default.RenderAll(findings)
	if len(formats) > 0 {
		snippets = filterSnippetsByFormat(snippets, formats)
	}

	if err := os.MkdirAll(opts.out, 0o750); err != nil {
		return fmt.Errorf("mkdir %s: %w", opts.out, err)
	}

	// Phase 11 — runbook + bulk script + per-format dirs.
	rbookRes, err := runbook.Write(opts.out, snippets, unmatched, runbook.Options{
		GeneratedAt:    time.Now().UTC(),
		Project:        opts.project,
		IncludeFormats: formats,
	})
	if err != nil {
		return fmt.Errorf("runbook: %w", err)
	}

	// Phase 10 — POA&M.
	manualSnippets := filterRiskManual(snippets)
	poamPath, err := poam.Write(opts.out, manualSnippets, unmatched, poam.Options{
		GeneratedAt: time.Now().UTC(),
		Project:     opts.project,
		Period:      opts.period,
	})
	if err != nil {
		return fmt.Errorf("poam: %w", err)
	}

	// Phase 12 — ticket integration (optional).
	var refs []tickets.Ref
	if opts.tickets {
		providers := ticketProvidersFromEnv()
		var errs []error
		refs, errs = tickets.FileManualFindings(ctx, manualSnippets, providers)
		for _, e := range errs {
			fmt.Fprintf(stdout, "ticket-create error: %v\n", e)
		}
	}

	// Summary.
	fmt.Fprintf(stdout, "Remediation generated under %s:\n", opts.out)
	fmt.Fprintf(stdout, "  Runbook:        %s\n", rbookRes.RunbookPath)
	fmt.Fprintf(stdout, "  Bulk script:    %s\n", rbookRes.BulkScriptPath)
	fmt.Fprintf(stdout, "  POA&M:          %s\n", poamPath)
	for fmtName, dir := range rbookRes.FormatDirs {
		fmt.Fprintf(stdout, "  Snippets (%s): %s\n", fmtName, dir)
	}
	fmt.Fprintf(stdout, "Stats: %d snippets · %d manual · %d unmatched · %d tickets filed\n",
		len(snippets), len(manualSnippets), len(unmatched), len(refs))
	return nil
}

func runRemediateList(stdout io.Writer) error {
	stratList := remediate.Default.RegisteredStrategies()
	if len(stratList) == 0 {
		fmt.Fprintln(stdout, "No remediation strategies registered.")
		return nil
	}
	fmt.Fprintf(stdout, "%-50s %-12s %s\n", "Strategy", "Formats", "CheckIDs")
	fmt.Fprintf(stdout, "%s\n", strings.Repeat("-", 100))
	for _, s := range stratList {
		formats := make([]string, len(s.Formats()))
		for i, f := range s.Formats() {
			formats[i] = string(f)
		}
		fmt.Fprintf(stdout, "%-50s %-12s %s\n",
			s.Name(),
			strings.Join(formats, ","),
			strings.Join(s.CheckIDs(), ","),
		)
	}
	fmt.Fprintf(stdout, "\nTotal: %d strategies covering %d CheckIDs.\n",
		len(stratList), len(remediate.Default.RegisteredCheckIDs()))
	return nil
}

// loadRemediateFindings reads findings JSON from path. "-" means
// stdin. For paths, delegates to the shared loadFindings helper in
// evidence.go which already handles both envelope + bare-array
// shapes; we only own the stdin case here.
func loadRemediateFindings(path string) ([]compliancekit.Finding, error) {
	if path != "-" {
		return loadFindings(path)
	}
	body, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}
	var env struct {
		Findings []compliancekit.Finding `json:"findings"`
	}
	if err := json.Unmarshal(body, &env); err == nil && env.Findings != nil {
		return env.Findings, nil
	}
	var arr []compliancekit.Finding
	if err := json.Unmarshal(body, &arr); err == nil {
		return arr, nil
	}
	return nil, fmt.Errorf("unrecognized findings JSON shape on stdin")
}

// filterRiskManual picks snippets whose strategy declared the change
// as manual. These flow to POA&M + ticket creation.
func filterRiskManual(snippets []remediate.Snippet) []remediate.Snippet {
	out := make([]remediate.Snippet, 0, len(snippets))
	for _, s := range snippets {
		if s.Risk == remediate.RiskManual {
			out = append(out, s)
		}
	}
	return out
}

func filterSnippetsByFormat(snippets []remediate.Snippet, formats []remediate.Format) []remediate.Snippet {
	allowed := map[remediate.Format]bool{}
	for _, f := range formats {
		allowed[f] = true
	}
	out := make([]remediate.Snippet, 0, len(snippets))
	for _, s := range snippets {
		if allowed[s.Format] {
			out = append(out, s)
		}
	}
	return out
}

// ticketProvidersFromEnv reads the env vars for Jira and Linear and
// returns the providers as configured. Missing creds → provider is
// returned but reports Configured() = false → caller skips it.
func ticketProvidersFromEnv() []tickets.Provider {
	jira := tickets.NewJira(tickets.JiraConfig{
		Host:       os.Getenv("JIRA_HOST"),
		Email:      os.Getenv("JIRA_EMAIL"),
		Token:      os.Getenv("JIRA_TOKEN"),
		ProjectKey: os.Getenv("JIRA_PROJECT"),
		IssueType:  os.Getenv("JIRA_ISSUE_TYPE"),
	})
	linear := tickets.NewLinear(tickets.LinearConfig{
		APIKey: os.Getenv("LINEAR_API_KEY"),
		TeamID: os.Getenv("LINEAR_TEAM_ID"),
	})
	providers := []tickets.Provider{jira, linear}
	sort.SliceStable(providers, func(i, j int) bool { return providers[i].Name() < providers[j].Name() })
	return providers
}
