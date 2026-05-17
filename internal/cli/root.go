// Package cli contains the cobra command tree for the compliancekit binary.
// Each subcommand lives in its own file (version.go, doctor.go, scan.go, ...).
package cli

import (
	"context"

	"github.com/spf13/cobra"
)

// BuildInfo carries values injected via -ldflags at build time.
// It's passed in from main rather than read from package-level vars so the
// CLI package stays testable in isolation.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// Execute builds the cobra command tree and runs whichever subcommand the
// user invoked. It is the single entry point from main.
func Execute(ctx context.Context, info BuildInfo) error {
	root := newRootCmd(info)
	return root.ExecuteContext(ctx)
}

func newRootCmd(info BuildInfo) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compliancekit",
		Short: "Open-source compliance scanner for cloud and Linux infrastructure",
		Long: `compliancekit scans your cloud accounts and Linux fleet against
SOC 2, ISO 27001, and CIS benchmarks, then generates audit-ready evidence packs.

Run 'compliancekit doctor' first to validate your config and connectivity.`,
		SilenceUsage:  true, // don't dump help on every error
		SilenceErrors: true, // main handles error printing
	}

	cmd.AddCommand(newVersionCmd(info))
	cmd.AddCommand(newDoctorCmd())
	cmd.AddCommand(newScanCmd())
	cmd.AddCommand(newChecksCmd())
	cmd.AddCommand(newEvidenceCmd())
	cmd.AddCommand(newBaselineCmd())
	cmd.AddCommand(newDiffCmd())
	cmd.AddCommand(newIngestCmd())
	cmd.AddCommand(newMappingCmd())
	cmd.AddCommand(newRemediateCmd())
	cmd.AddCommand(newPolicyCmd())

	return cmd
}
