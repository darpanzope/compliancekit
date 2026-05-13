package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func newVersionCmd(info BuildInfo) *cobra.Command {
	var (
		short  bool
		asJSON bool
	)

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, and build date",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVersion(cmd.OutOrStdout(), info, short, asJSON)
		},
	}

	cmd.Flags().BoolVar(&short, "short", false, "print version only")
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")

	return cmd
}

func runVersion(w io.Writer, info BuildInfo, short, asJSON bool) error {
	switch {
	case short:
		_, err := fmt.Fprintln(w, info.Version)
		return err
	case asJSON:
		return json.NewEncoder(w).Encode(info)
	default:
		_, err := fmt.Fprintf(w, "compliancekit %s (commit %s, built %s)\n",
			info.Version, info.Commit, info.Date)
		return err
	}
}
