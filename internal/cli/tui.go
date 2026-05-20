package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/tui"
)

// newTUICmd builds `compliancekit tui`, the v1.7 Bubble Tea
// terminal client. Two source modes:
//
//	compliancekit tui --findings=path.json
//	  open a static findings.json (offline)
//
//	compliancekit tui --server=http://localhost:8080 --api-token=ck_…
//	  connect to a running daemon (live updates from /api/v1/events
//	  arrive starting at phase 3; phase 0 ships static load).
//
// CK_API_TOKEN env var is honored as a fallback for --api-token so
// CI / scripted invocations don't have to splash secrets on the
// command line.
func newTUICmd() *cobra.Command {
	var (
		findingsPath string
		serverURL    string
		apiToken     string
	)
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "k9s-style terminal client (v1.7+)",
		Long: `tui opens an interactive Bubble Tea terminal client over compliancekit
findings. Two source modes:

  --findings=PATH                 open a static findings.json (offline)
  --server=URL --api-token=TOKEN  connect to a running daemon (or set
                                  $CK_API_TOKEN for the token)

Default keybindings (phase 0):
  q / Esc / Ctrl-C   quit
  j / down           next finding
  k / up             previous finding
  g                  jump to top
  G                  jump to bottom

Phases 1-9 layer multi-pane / vim-keys / live tail / in-place
actions / resource-graph / diff-vs-baseline / help overlay.`,
		Example: `  compliancekit tui --findings=out/findings.json
  compliancekit tui --server=http://localhost:8080 --api-token=ck_…`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if apiToken == "" {
				apiToken = os.Getenv("CK_API_TOKEN")
			}
			var src tui.Source
			var err error
			switch {
			case findingsPath != "":
				src, err = tui.NewFileSource(findingsPath)
			case serverURL != "":
				src, err = tui.NewDaemonSource(serverURL, apiToken)
			default:
				return fmt.Errorf("pass either --findings=PATH or --server=URL --api-token=TOKEN")
			}
			if err != nil {
				return err
			}
			return tui.Run(cmd.Context(), src)
		},
	}
	cmd.Flags().StringVar(&findingsPath, "findings", "", "path to a local findings.json (file mode)")
	cmd.Flags().StringVar(&serverURL, "server", "", "base URL of a running compliancekit daemon (daemon mode)")
	cmd.Flags().StringVar(&apiToken, "api-token", "", "Bearer token for the daemon (defaults to $CK_API_TOKEN)")
	return cmd
}
