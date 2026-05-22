package cli

// v1.12 phase 10 — `compliancekit serve audit verify` subcommand.
//
// Walks the audit_log hash chain and reports any rows whose prev_hash
// or row_hash doesn't match the recomputed value. Exits 0 on a clean
// chain; exits 1 with the broken row IDs on tamper detection.
//
// Legacy rows (pre-v1.12, NULL row_hash) are counted but not
// validated. Operators who care about full-history integrity
// archive + truncate the audit_log before upgrade so the next row
// becomes the chain genesis.

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/ui"
)

func newServeAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit-log operations (verify the v1.12 hash chain)",
	}
	cmd.AddCommand(newServeAuditVerifyCmd())
	return cmd
}

func newServeAuditVerifyCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the audit_log SHA-256 hash chain (v1.12 phase 10)",
		Long: `Walks audit_log oldest-first and recomputes each row's hash.

Every chained row's prev_hash should equal the previous row's
row_hash, and its row_hash should equal SHA-256(prev_hash ||
canonical-json(row)). A mismatch means the row (or one before it)
was tampered.

Exit 0 = chain intact. Exit 1 = broken rows reported. Legacy rows
(NULL row_hash, pre-v1.12) are counted but not validated.`,
		Example: `  compliancekit serve audit verify --db=./.compliancekit/serve.db
  compliancekit serve audit verify --db=postgres://localhost/ck`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			st, err := openStore(ctx, dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer func() { _ = st.Close() }()
			if err := st.MigrateUp(ctx); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}
			users := auth.NewUsers(st)
			sessions := auth.NewSessions(st)
			uiH := ui.New(st, users, sessions)
			res, err := uiH.VerifyAuditChain(ctx)
			if err != nil {
				return fmt.Errorf("verify: %w", err)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "audit chain: %d total, %d chained, %d legacy (unchained)\n",
				res.Total, res.Chained, res.Unchained)
			if len(res.Broken) > 0 {
				fmt.Fprintf(out, "BROKEN — %d row(s) failed validation:\n", len(res.Broken))
				for _, id := range res.Broken {
					fmt.Fprintf(out, "  %s\n", id)
				}
				return NewExitCode(1, "audit chain broken")
			}
			fmt.Fprintln(out, "chain intact ✓")
			_ = ctx // suppress unused if context goes unreferenced after a refactor
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "./.compliancekit/serve.db", "SQLite file path or postgres://... DSN")
	return cmd
}

// _ keeps context.Context referenced in case future iterations move
// the verify body away from passing it via cmd.Context().
var _ context.Context
