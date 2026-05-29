package cli

// v1.4 Phase 12 — Daemon-bootstrap CLI subcommands.
//
// `compliancekit serve` grew into a small command group:
//
//	compliancekit serve                              run the daemon
//	compliancekit serve --demo                       boot + seed demo data
//	compliancekit serve users create --email=…      create local user
//	compliancekit serve users list                   list users
//	compliancekit serve users delete --email=…      delete user
//	compliancekit serve tokens issue --user=… --scope=…  mint API token
//	compliancekit serve tokens list                  list tokens
//	compliancekit serve tokens revoke --id=…        revoke token
//
// Closes the v1.3.1 throwaway-seeddemo gap — operators can bootstrap
// the daemon entirely from the binary, no Go program required.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/store"
)

// addBootstrapSubcommands attaches the users + tokens subcommand
// groups to the parent serve command. Called from newServeCmd.
func addBootstrapSubcommands(serve *cobra.Command) {
	serve.AddCommand(newServeUsersCmd())
	serve.AddCommand(newServeTokensCmd())
	serve.AddCommand(newServeAuditCmd())
}

// ─── users ──────────────────────────────────────────────────────

func newServeUsersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "users",
		Short: "Manage local users in the daemon's database",
	}
	cmd.AddCommand(newServeUsersCreateCmd())
	cmd.AddCommand(newServeUsersListCmd())
	cmd.AddCommand(newServeUsersDeleteCmd())
	return cmd
}

func newServeUsersCreateCmd() *cobra.Command {
	var email, password, displayName, dbPath string
	var admin bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a local user (--email + --password required)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if email == "" {
				return fmt.Errorf("--email is required")
			}
			if password == "" {
				return fmt.Errorf("--password is required (use a strong value; will be bcrypt-hashed)")
			}
			if displayName == "" {
				displayName = email
			}
			ctx := cmd.Context()
			st, err := openMigratedStore(ctx, dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer func() { _ = st.Close() }()
			users := auth.NewUsers(st)
			u, err := users.Create(ctx, email, displayName, password, admin)
			if err != nil {
				return fmt.Errorf("create user: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"created user %s (id=%s, admin=%v)\n", u.Email, u.ID, admin)
			return nil
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "email address (login id)")
	cmd.Flags().StringVar(&password, "password", "", "password (bcrypt-hashed at insert)")
	cmd.Flags().StringVar(&displayName, "name", "", "display name (defaults to email)")
	cmd.Flags().BoolVar(&admin, "admin", false, "grant administrator role")
	cmd.Flags().StringVar(&dbPath, "db", "./.compliancekit/serve.db", "SQLite file path or postgres://… DSN")
	return cmd
}

func newServeUsersListCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List local users",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			st, err := openMigratedStore(ctx, dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer func() { _ = st.Close() }()
			rows, err := st.DB().QueryContext(ctx,
				`SELECT email, COALESCE(display_name,''), is_admin, created_at
				 FROM users ORDER BY created_at ASC`)
			if err != nil {
				return fmt.Errorf("list users: %w", err)
			}
			defer func() { _ = rows.Close() }()
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-30s  %-20s  %-6s  %s\n", "EMAIL", "NAME", "ADMIN", "CREATED")
			fmt.Fprintln(w, strings.Repeat("-", 80))
			for rows.Next() {
				var email, name, created string
				var isAdmin int
				if err := rows.Scan(&email, &name, &isAdmin, &created); err != nil {
					return err
				}
				adminStr := "no"
				if isAdmin != 0 {
					adminStr = "yes"
				}
				fmt.Fprintf(w, "%-30s  %-20s  %-6s  %s\n", email, name, adminStr, created)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "./.compliancekit/serve.db", "SQLite file path or postgres://… DSN")
	return cmd
}

func newServeUsersDeleteCmd() *cobra.Command {
	var email, dbPath string
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a local user (--email)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if email == "" {
				return fmt.Errorf("--email is required")
			}
			ctx := cmd.Context()
			st, err := openMigratedStore(ctx, dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer func() { _ = st.Close() }()
			res, err := st.DB().ExecContext(ctx, `DELETE FROM users WHERE email = ?`, email)
			if err != nil {
				return fmt.Errorf("delete: %w", err)
			}
			n, _ := res.RowsAffected()
			if n == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "no user with email %q\n", email)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "deleted user %s\n", email)
			return nil
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "email of the user to delete")
	cmd.Flags().StringVar(&dbPath, "db", "./.compliancekit/serve.db", "SQLite file path or postgres://… DSN")
	return cmd
}

// ─── tokens ─────────────────────────────────────────────────────

func newServeTokensCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tokens",
		Short: "Manage API tokens for the daemon",
	}
	cmd.AddCommand(newServeTokensIssueCmd())
	cmd.AddCommand(newServeTokensListCmd())
	cmd.AddCommand(newServeTokensRevokeCmd())
	return cmd
}

func newServeTokensIssueCmd() *cobra.Command {
	var userEmail, scopeCSV, name, dbPath string
	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Issue an API token for a user (--user + --scope)",
		Long: `Issues a new API token printed once to stdout. The token is stored
as a SHA-256 hash in the daemon's database — the raw value cannot
be recovered after this command exits. Scope strings follow the
v1.3 contract: scans:read, findings:read, settings:write, etc.
"*" grants every scope (admin tokens).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if userEmail == "" {
				return fmt.Errorf("--user is required (email of an existing user)")
			}
			if scopeCSV == "" {
				return fmt.Errorf("--scope is required (comma-separated, e.g. scans:read,findings:read)")
			}
			ctx := cmd.Context()
			st, err := openMigratedStore(ctx, dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer func() { _ = st.Close() }()
			users := auth.NewUsers(st)
			usr, err := users.ByEmail(ctx, userEmail)
			if err != nil {
				return fmt.Errorf("user %q not found: %w", userEmail, err)
			}
			scopes := []auth.Scope{}
			for _, s := range strings.Split(scopeCSV, ",") {
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				scopes = append(scopes, auth.Scope(s))
			}
			tokens := auth.NewTokens(st)
			res, err := tokens.Issue(ctx, usr.ID, name, scopes, nil) // nil = no expiry
			if err != nil {
				return fmt.Errorf("issue token: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), res.Plaintext)
			fmt.Fprintln(cmd.ErrOrStderr(),
				"# token issued — save it now; it can't be displayed again.")
			return nil
		},
	}
	cmd.Flags().StringVar(&userEmail, "user", "", "email of the token's owner")
	cmd.Flags().StringVar(&scopeCSV, "scope", "", "comma-separated scopes (scans:read,findings:read,settings:write)")
	cmd.Flags().StringVar(&name, "name", "", "human-readable token label (shown in /settings/tokens)")
	cmd.Flags().StringVar(&dbPath, "db", "./.compliancekit/serve.db", "SQLite file path or postgres://… DSN")
	return cmd
}

func newServeTokensListCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List API tokens",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			st, err := openMigratedStore(ctx, dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer func() { _ = st.Close() }()
			rows, err := st.DB().QueryContext(ctx,
				`SELECT t.id, COALESCE(t.name,''), COALESCE(u.email,''),
				        COALESCE(t.scopes,''), t.created_at, COALESCE(t.last_used_at,'')
				 FROM api_tokens t LEFT JOIN users u ON u.id = t.user_id
				 ORDER BY t.created_at ASC`)
			if err != nil {
				return fmt.Errorf("list tokens: %w", err)
			}
			defer func() { _ = rows.Close() }()
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-36s  %-20s  %-25s  %-30s  %s\n", "ID", "NAME", "USER", "SCOPES", "LAST USED")
			fmt.Fprintln(w, strings.Repeat("-", 130))
			for rows.Next() {
				var id, name, user, scopes, created, last string
				if err := rows.Scan(&id, &name, &user, &scopes, &created, &last); err != nil {
					return err
				}
				if last == "" {
					last = "—"
				}
				fmt.Fprintf(w, "%-36s  %-20s  %-25s  %-30s  %s\n", id, name, user, scopes, last)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "./.compliancekit/serve.db", "SQLite file path or postgres://… DSN")
	return cmd
}

func newServeTokensRevokeCmd() *cobra.Command {
	var id, dbPath string
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke an API token (--id)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id == "" {
				return fmt.Errorf("--id is required")
			}
			ctx := cmd.Context()
			st, err := openMigratedStore(ctx, dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer func() { _ = st.Close() }()
			res, err := st.DB().ExecContext(ctx,
				`DELETE FROM api_tokens WHERE id = ?`, id)
			if err != nil {
				return fmt.Errorf("revoke: %w", err)
			}
			n, _ := res.RowsAffected()
			if n == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "no token with id %q\n", id)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "revoked token %s\n", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "token id (from `tokens list`)")
	cmd.Flags().StringVar(&dbPath, "db", "./.compliancekit/serve.db", "SQLite file path or postgres://… DSN")
	return cmd
}

// ─── --demo seed ────────────────────────────────────────────────

// seedDemoData writes a small, realistic-looking dataset into a
// fresh daemon — a demo admin user, two providers (one enabled),
// three completed scans with descending trend, and a sample inbox
// alert. Operators evaluating compliancekit see something
// interesting on every page within five seconds of `serve --demo`
// boot. Idempotent: re-running on an already-seeded DB is a no-op.
//
// Returns error today as a future-proofing affordance — when the
// real demo seeder grows beyond "best-effort INSERT" (e.g. fixture
// loader for realistic CIS-mapped findings) returning an error will
// matter. For v1.4 Phase 12 we swallow individual ON CONFLICT
// failures and always return nil.
func seedDemoData(ctx context.Context, st *store.Store) error { //nolint:unparam // see doc comment
	now := time.Now().UTC().Format(time.RFC3339)
	users := auth.NewUsers(st)
	if _, err := users.ByEmail(ctx, "demo@compliancekit.dev"); err != nil {
		_, _ = users.Create(ctx, "demo@compliancekit.dev", "Demo Admin", "demo-please-change", true)
	}

	// v1.19 phase 4 — enable a multi-provider demo fleet so the resource
	// map + provider breakdowns look real. DO/AWS/GCP/K8s scanned;
	// Hetzner + Linux configured-but-disabled to show the "connect more"
	// affordance.
	demoCfg := `{"token":"dop_demo_redacted","region":"fra1, nyc1","services":["droplets","spaces"]}`
	provQ := `INSERT INTO providers (id, enabled, config_json, last_auth_check_at, last_auth_status, created_at, updated_at)
	          VALUES (?, ?, ?, ?, ?, ?, ?)
	          ON CONFLICT(id) DO NOTHING`
	_, _ = st.DB().ExecContext(ctx, provQ, "digitalocean", 1, demoCfg, now, "ok", now, now)
	_, _ = st.DB().ExecContext(ctx, provQ, "aws", 1, `{"token":"AKIA_demo_redacted"}`, now, "ok", now, now)
	_, _ = st.DB().ExecContext(ctx, provQ, "gcp", 1, `{"token":"gcp_demo_redacted"}`, now, "ok", now, now)
	_, _ = st.DB().ExecContext(ctx, provQ, "kubernetes", 1, `{"context":"demo-cluster"}`, now, "ok", now, now)
	_, _ = st.DB().ExecContext(ctx, provQ, "hetzner", 0, `{"token":"hcloud_demo_redacted"}`, now, "ok", now, now)
	_, _ = st.DB().ExecContext(ctx, provQ, "linux", 0, `{"host":"demo-host"}`, now, "ok", now, now)

	// v1.19 phase 4 — screenshot-grade fleet: ~150 resources × 8 weekly
	// scans → ~500 findings on an improving trend (see demo_seed.go).
	seedDemoRich(ctx, st)

	_, _ = st.DB().ExecContext(ctx,
		`INSERT INTO inbox (id, user_id, created_at, severity, title, body, href)
		 VALUES (?, NULL, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO NOTHING`,
		"demo-inbox-1", now, "info",
		"Score improved from 64 to 90 over 8 weeks",
		"Nice trend — your latest scan closed with the fewest findings yet.",
		"/scores")

	return nil
}
