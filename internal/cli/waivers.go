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

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/waivers"
)

// newWaiversCmd builds `compliancekit waivers` with four subcommands:
//
//	list      — print a table of every active + expired waiver
//	show      — print full detail for one (check_id, resource_id) pair
//	validate  — load + run schema validation; non-zero exit on any error
//	check     — exit non-zero if any finding in --in= is NOT muted by
//	            a matching waiver (CI gate for "every fail-on=high
//	            finding must have a documented acceptance")
//
// Per ADR-013, this surface mirrors the v0.17 `notify --list` +
// v0.13 `mapping` ergonomics: declarative state inspection without
// having to round-trip `scan`.
func newWaiversCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "waivers",
		Short: "Inspect + validate + audit waivers (v0.18+)",
		Long: `Operational commands for compliancekit's waivers feature.

  compliancekit waivers list      [--file=waivers.yaml]
  compliancekit waivers show      <check-id> <resource-id> [--file=waivers.yaml]
  compliancekit waivers validate  [--file=waivers.yaml]
  compliancekit waivers check     --in=findings.json [--file=waivers.yaml]

Default --file is "waivers.yaml" in the current directory; pass --file=PATH
to scan a different location. Missing file is treated as zero waivers
(not an error) so the commands are safe to wire into CI unconditionally.`,
	}
	cmd.AddCommand(newWaiversListCmd())
	cmd.AddCommand(newWaiversShowCmd())
	cmd.AddCommand(newWaiversValidateCmd())
	cmd.AddCommand(newWaiversCheckCmd())
	return cmd
}

// --- list -------------------------------------------------------------

func newWaiversListCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Tabulate every active + expired waiver",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWaiversList(cmd.OutOrStdout(), file)
		},
	}
	cmd.Flags().StringVar(&file, "file", "waivers.yaml", "path to waivers.yaml")
	return cmd
}

func runWaiversList(stdout io.Writer, path string) error {
	now := time.Now().UTC()
	list, errs := waivers.LoadFile(path, now)
	for _, e := range errs {
		fmt.Fprintf(stdout, "warning: %v\n", e)
	}
	active, expired, expiring := list.Counts(now)
	fmt.Fprintf(stdout, "%s: %d active, %d expired, %d expiring within 30d\n\n",
		path, active, expired, expiring)
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tCHECK\tRESOURCE\tEXPIRES\tAPPROVER\tSOURCE")
	for _, w := range list.Active {
		days := w.ToRef().DaysUntilExpiry(now)
		status := "active"
		if days <= 30 {
			status = "expiring"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s (%dd)\t%s\t%s\n",
			status, w.CheckID, w.ResourceID,
			w.Expires.Format("2006-01-02"), days, w.Approver, w.Source)
	}
	for _, w := range list.Expired {
		days := -w.ToRef().DaysUntilExpiry(now)
		fmt.Fprintf(tw, "expired\t%s\t%s\t%s (-%dd)\t%s\t%s\n",
			w.CheckID, w.ResourceID,
			w.Expires.Format("2006-01-02"), days, w.Approver, w.Source)
	}
	return tw.Flush()
}

// --- show -------------------------------------------------------------

func newWaiversShowCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "show <check-id> <resource-id>",
		Short: "Print full detail for a specific (check, resource) waiver",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWaiversShow(cmd.OutOrStdout(), file, args[0], args[1])
		},
	}
	cmd.Flags().StringVar(&file, "file", "waivers.yaml", "path to waivers.yaml")
	return cmd
}

func runWaiversShow(stdout io.Writer, path, checkID, resourceID string) error {
	now := time.Now().UTC()
	list, errs := waivers.LoadFile(path, now)
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(stdout, "warning: %v\n", e)
		}
	}
	if w := list.Match(checkID, resourceID); w != nil {
		printWaiver(stdout, *w, "active", w.ToRef().DaysUntilExpiry(now))
		return nil
	}
	// Fall back to scanning Expired for the same pair so operators
	// can debug "why isn't my waiver muting any more".
	for _, w := range list.Expired {
		if w.CheckID == checkID && w.ResourceID == resourceID {
			printWaiver(stdout, w, "expired", w.ToRef().DaysUntilExpiry(now))
			return nil
		}
	}
	return fmt.Errorf("no waiver for (%s, %s) in %s", checkID, resourceID, path)
}

func printWaiver(w io.Writer, wv waivers.Waiver, status string, days int) {
	fmt.Fprintf(w, "Status:      %s\n", status)
	fmt.Fprintf(w, "CheckID:     %s\n", wv.CheckID)
	fmt.Fprintf(w, "ResourceID:  %s\n", wv.ResourceID)
	fmt.Fprintf(w, "Approver:    %s\n", wv.Approver)
	fmt.Fprintf(w, "Expires:     %s (%+dd from now)\n", wv.Expires.Format("2006-01-02"), days)
	fmt.Fprintf(w, "Source:      %s — %s\n", wv.Source, wv.SourcePath)
	fmt.Fprintln(w, "Reason:")
	for _, ln := range strings.Split(wv.Reason, "\n") {
		fmt.Fprintf(w, "  %s\n", ln)
	}
}

// --- validate ---------------------------------------------------------

func newWaiversValidateCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Load waivers.yaml + report any schema or duplicate errors (non-zero exit on any error)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWaiversValidate(cmd.OutOrStdout(), file)
		},
	}
	cmd.Flags().StringVar(&file, "file", "waivers.yaml", "path to waivers.yaml")
	return cmd
}

func runWaiversValidate(stdout io.Writer, path string) error {
	now := time.Now().UTC()
	list, errs := waivers.LoadFile(path, now)
	fmt.Fprintf(stdout, "Validating %s …\n", path)
	if len(errs) == 0 {
		fmt.Fprintf(stdout, "  ✓ loaded cleanly: %d active, %d expired\n",
			len(list.Active), len(list.Expired))
		return nil
	}
	for i, e := range errs {
		fmt.Fprintf(stdout, "  %d) %v\n", i+1, e)
	}
	return fmt.Errorf("validate failed with %d error(s)", len(errs))
}

// --- check ------------------------------------------------------------

func newWaiversCheckCmd() *cobra.Command {
	var file, in string
	cmd := &cobra.Command{
		Use:   "check --in=findings.json",
		Short: "Exit non-zero if any actionable finding lacks a matching waiver (CI gate)",
		Long: `Read findings JSON (output of scan or ingest) and report every
actionable finding that does NOT match an active waiver. Non-zero exit
on any unmuted finding — useful as a CI gate that says "every fail-on=
high finding must have a documented acceptance".`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWaiversCheck(cmd.Context(), cmd.OutOrStdout(), file, in)
		},
	}
	cmd.Flags().StringVar(&file, "file", "waivers.yaml", "path to waivers.yaml")
	cmd.Flags().StringVar(&in, "in", "", "findings JSON (required; - for stdin)")
	return cmd
}

func runWaiversCheck(_ context.Context, stdout io.Writer, file, in string) error {
	if in == "" {
		return fmt.Errorf("waivers check: --in is required")
	}
	now := time.Now().UTC()
	list, errs := waivers.LoadFile(file, now)
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(stdout, "warning: %v\n", e)
		}
	}
	findings, err := loadCheckFindings(in)
	if err != nil {
		return err
	}
	uncovered := 0
	for _, f := range findings {
		if !f.Status.IsActionable() {
			continue
		}
		if list.Match(f.CheckID, f.Resource.ID) == nil {
			uncovered++
			fmt.Fprintf(stdout, "uncovered: %s on %s (%s)\n",
				f.CheckID, f.Resource.ID, f.Severity)
		}
	}
	if uncovered > 0 {
		return fmt.Errorf("%d actionable finding(s) without a matching waiver", uncovered)
	}
	fmt.Fprintf(stdout, "all %d actionable finding(s) covered by an active waiver.\n",
		countActionable(findings))
	return nil
}

// loadCheckFindings reads findings JSON from path / stdin. Reuses
// the canonical loadFindings helper from evidence.go for the path
// case; only owns the stdin branch.
func loadCheckFindings(path string) ([]core.Finding, error) {
	if path != "-" {
		return loadFindings(path)
	}
	body, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}
	var env struct {
		Findings []core.Finding `json:"findings"`
	}
	if err := json.Unmarshal(body, &env); err == nil && env.Findings != nil {
		return env.Findings, nil
	}
	var arr []core.Finding
	if err := json.Unmarshal(body, &arr); err == nil {
		return arr, nil
	}
	return nil, fmt.Errorf("unrecognized findings JSON shape on stdin")
}

func countActionable(findings []core.Finding) int {
	n := 0
	for _, f := range findings {
		if f.Status.IsActionable() {
			n++
		}
	}
	return n
}
