package cli

import (
	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/ui"
)

// noColorFlag is the persistent name of the --no-color flag attached
// to the root command. Subcommands look it up by this constant when
// constructing their Styler so the flag is the single switch operators
// remember.
const noColorFlag = "no-color"

// stylerFor returns a styled output sink for cmd. The styler honors
// the --no-color persistent flag, NO_COLOR, CLICOLOR=0, and TTY-ness
// of the command's stdout (in that precedence order; see [ui.IsColorEnabled]).
//
// Subcommands call this once at the top of their RunE and pass the
// returned Styler down to any rendering helpers. The Styler is cheap
// to construct (no I/O) so per-call construction is fine.
func stylerFor(cmd *cobra.Command) *ui.Styler {
	return ui.NewStyler(cmd.OutOrStdout(), noColorIsSet(cmd))
}

// noColorIsSet reads the --no-color flag from the root command's
// persistent flag set. Returns false (color enabled) when the flag
// wasn't registered — defensive against subcommand tests that
// construct a bare cobra.Command in isolation.
func noColorIsSet(cmd *cobra.Command) bool {
	v, err := cmd.Flags().GetBool(noColorFlag)
	if err != nil {
		return false
	}
	return v
}
