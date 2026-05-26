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
			st, err := openStore(ctx, dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer func() { _ = st.Close() }()
			if err := st.MigrateUp(ctx); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}
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
			st, err := openStore(ctx, dbPath)
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
			st, err := openStore(ctx, dbPath)
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
			st, err := openStore(ctx, dbPath)
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
			st, err := openStore(ctx, dbPath)
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
			st, err := openStore(ctx, dbPath)
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

	demoCfg := `{"token":"dop_demo_redacted","region":"fra1, nyc1","services":["droplets","spaces"]}`
	demoCfgAWS := `{"token":"AKIA_demo_redacted"}`
	provQ := `INSERT INTO providers (id, enabled, config_json, last_auth_check_at, last_auth_status, created_at, updated_at)
	          VALUES (?, ?, ?, ?, ?, ?, ?)
	          ON CONFLICT(id) DO NOTHING`
	_, _ = st.DB().ExecContext(ctx, provQ, "digitalocean", 1, demoCfg, now, "ok", now, now)
	_, _ = st.DB().ExecContext(ctx, provQ, "aws", 0, demoCfgAWS, now, "ok", now, now)

	scans := []struct {
		id                   string
		days                 int
		score, total, action int
	}{
		{"demo-scan-1", 0, 78, 47, 12},
		{"demo-scan-2", 7, 75, 51, 14},
		{"demo-scan-3", 14, 73, 56, 16},
	}
	scanQ := `INSERT INTO scans (id, created_at, source, status, providers_scanned,
	                              frameworks_scanned, score, coverage, total_findings,
	                              actionable_findings, duration_ms)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	          ON CONFLICT(id) DO NOTHING`
	for _, s := range scans {
		ts := time.Now().Add(-time.Duration(s.days) * 24 * time.Hour).UTC().Format(time.RFC3339)
		_, _ = st.DB().ExecContext(ctx, scanQ,
			s.id, ts, "daemon", "completed",
			`["digitalocean"]`, `["soc2"]`,
			s.score, 95, s.total, s.action, 8200+s.days*100)
	}

	_, _ = st.DB().ExecContext(ctx,
		`INSERT INTO inbox (id, user_id, created_at, severity, title, body, href)
		 VALUES (?, NULL, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO NOTHING`,
		"demo-inbox-1", now, "warning",
		"Score dropped from 78 to 73",
		"Run a scan to see the new findings.",
		"/scans")

	seedDemoFindings(ctx, st, now)
	return nil
}

// seedDemoFindings populates the findings + resources tables for the
// demo scans so /findings, /resources, dashboard widgets, and the
// per-scan side panel all render against real data. v1.15.1 phase 4
// — the v1.5.0 demo (which prompted ADR-016) only seeded scan rows;
// every UI surface that loads findings showed an empty state.
//
// Each demo scan gets a fan of representative findings drawn from
// real check IDs registered in internal/checks/. Severity mix
// approximates a real CIS-scored fleet (mostly medium/low, a few
// criticals and highs to make the explorer + heatmap interesting).
//
// Resources are upserted per finding (same id ⇒ deduplicated) so
// /resources surfaces ~10-15 unique resources across the demo scans.
//
//nolint:gocyclo // straight-line seeder; cyclomatic from the slice length
func seedDemoFindings(ctx context.Context, st *store.Store, now string) {
	type demoFinding struct {
		scanID, checkID, severity, status, provider     string
		resourceID, resourceName, resourceType, message string
		frameworkIDs                                    string // JSON array
	}
	// Spread ~50 findings across the 3 demo scans. The "regression"
	// arc (more findings as we go back in time) matches the score
	// trend the scans table already advertises (78 → 75 → 73).
	demo := []demoFinding{
		// demo-scan-1 (latest, 12 actionable)
		{"demo-scan-1", "do-droplet-no-firewall", "high", "fail", "digitalocean", "do:droplet:web-prod-01", "web-prod-01", "droplet", "Droplet has no firewall attached", `["soc2","cis-v8","iso27001"]`},
		{"demo-scan-1", "do-droplet-no-firewall", "high", "fail", "digitalocean", "do:droplet:web-prod-02", "web-prod-02", "droplet", "Droplet has no firewall attached", `["soc2","cis-v8","iso27001"]`},
		{"demo-scan-1", "do-spaces-public-acl", "critical", "fail", "digitalocean", "do:space:assets-prod", "assets-prod", "space", "Spaces bucket has public ACL", `["soc2","pci-dss-v4","iso27001"]`},
		{"demo-scan-1", "do-spaces-versioning-disabled", "medium", "fail", "digitalocean", "do:space:backups-prod", "backups-prod", "space", "Spaces bucket versioning is disabled", `["soc2","cis-v8"]`},
		{"demo-scan-1", "do-account-2fa", "high", "fail", "digitalocean", "do:account:team", "team-account", "account", "Team 2FA is not enforced for all members", `["soc2","iso27001","cis-v8"]`},
		{"demo-scan-1", "do-managed-db-public", "high", "fail", "digitalocean", "do:database:postgres-prod", "postgres-prod", "database", "Managed database accepts connections from the public internet", `["soc2","pci-dss-v4"]`},
		{"demo-scan-1", "do-lb-tls-13", "medium", "fail", "digitalocean", "do:loadbalancer:api-lb", "api-lb", "load_balancer", "Load balancer uses TLS < 1.3", `["soc2","cis-v8"]`},
		{"demo-scan-1", "do-droplet-old-image", "low", "fail", "digitalocean", "do:droplet:legacy-01", "legacy-01", "droplet", "Droplet image is more than 180 days old", `["cis-v8"]`},
		{"demo-scan-1", "do-firewall-ssh-from-any", "high", "fail", "digitalocean", "do:firewall:default", "default", "firewall", "Firewall allows SSH (22) from 0.0.0.0/0", `["soc2","cis-v8","iso27001"]`},
		{"demo-scan-1", "do-droplet-no-firewall", "pass", "pass", "digitalocean", "do:droplet:db-prod-01", "db-prod-01", "droplet", "Droplet has a firewall attached", `["soc2","cis-v8","iso27001"]`},
		{"demo-scan-1", "do-spaces-public-acl", "pass", "pass", "digitalocean", "do:space:private-prod", "private-prod", "space", "Spaces bucket ACL is private", `["soc2","pci-dss-v4","iso27001"]`},
		{"demo-scan-1", "do-cert-near-expiry", "medium", "fail", "digitalocean", "do:cert:wildcard", "wildcard", "certificate", "TLS certificate expires within 30 days", `["soc2","iso27001"]`},
		{"demo-scan-1", "do-spaces-no-encryption", "medium", "fail", "digitalocean", "do:space:logs-prod", "logs-prod", "space", "Spaces bucket has no default encryption", `["soc2","pci-dss-v4"]`},
		{"demo-scan-1", "do-firewall-rdp-from-any", "high", "fail", "digitalocean", "do:firewall:windows", "windows", "firewall", "Firewall allows RDP (3389) from 0.0.0.0/0", `["soc2","cis-v8"]`},
		{"demo-scan-1", "do-droplet-no-backups", "low", "fail", "digitalocean", "do:droplet:web-prod-01", "web-prod-01", "droplet", "Droplet has automatic backups disabled", `["cis-v8"]`},

		// demo-scan-2 (7 days ago, 14 actionable — score 75)
		{"demo-scan-2", "do-droplet-no-firewall", "high", "fail", "digitalocean", "do:droplet:web-prod-01", "web-prod-01", "droplet", "Droplet has no firewall attached", `["soc2","cis-v8","iso27001"]`},
		{"demo-scan-2", "do-droplet-no-firewall", "high", "fail", "digitalocean", "do:droplet:web-prod-02", "web-prod-02", "droplet", "Droplet has no firewall attached", `["soc2","cis-v8","iso27001"]`},
		{"demo-scan-2", "do-droplet-no-firewall", "high", "fail", "digitalocean", "do:droplet:api-prod-01", "api-prod-01", "droplet", "Droplet has no firewall attached", `["soc2","cis-v8","iso27001"]`},
		{"demo-scan-2", "do-spaces-public-acl", "critical", "fail", "digitalocean", "do:space:assets-prod", "assets-prod", "space", "Spaces bucket has public ACL", `["soc2","pci-dss-v4","iso27001"]`},
		{"demo-scan-2", "do-spaces-public-acl", "critical", "fail", "digitalocean", "do:space:legacy-public", "legacy-public", "space", "Spaces bucket has public ACL", `["soc2","pci-dss-v4","iso27001"]`},
		{"demo-scan-2", "do-account-2fa", "high", "fail", "digitalocean", "do:account:team", "team-account", "account", "Team 2FA is not enforced for all members", `["soc2","iso27001","cis-v8"]`},
		{"demo-scan-2", "do-managed-db-public", "high", "fail", "digitalocean", "do:database:postgres-prod", "postgres-prod", "database", "Managed database accepts connections from the public internet", `["soc2","pci-dss-v4"]`},
		{"demo-scan-2", "do-lb-tls-13", "medium", "fail", "digitalocean", "do:loadbalancer:api-lb", "api-lb", "load_balancer", "Load balancer uses TLS < 1.3", `["soc2","cis-v8"]`},
		{"demo-scan-2", "do-droplet-old-image", "low", "fail", "digitalocean", "do:droplet:legacy-01", "legacy-01", "droplet", "Droplet image is more than 180 days old", `["cis-v8"]`},
		{"demo-scan-2", "do-droplet-old-image", "low", "fail", "digitalocean", "do:droplet:legacy-02", "legacy-02", "droplet", "Droplet image is more than 180 days old", `["cis-v8"]`},
		{"demo-scan-2", "do-firewall-ssh-from-any", "high", "fail", "digitalocean", "do:firewall:default", "default", "firewall", "Firewall allows SSH (22) from 0.0.0.0/0", `["soc2","cis-v8","iso27001"]`},
		{"demo-scan-2", "do-firewall-rdp-from-any", "high", "fail", "digitalocean", "do:firewall:windows", "windows", "firewall", "Firewall allows RDP (3389) from 0.0.0.0/0", `["soc2","cis-v8"]`},
		{"demo-scan-2", "do-spaces-versioning-disabled", "medium", "fail", "digitalocean", "do:space:backups-prod", "backups-prod", "space", "Spaces bucket versioning is disabled", `["soc2","cis-v8"]`},
		{"demo-scan-2", "do-spaces-no-encryption", "medium", "fail", "digitalocean", "do:space:logs-prod", "logs-prod", "space", "Spaces bucket has no default encryption", `["soc2","pci-dss-v4"]`},

		// demo-scan-3 (14 days ago, 16 actionable — score 73, worst)
		{"demo-scan-3", "do-droplet-no-firewall", "high", "fail", "digitalocean", "do:droplet:web-prod-01", "web-prod-01", "droplet", "Droplet has no firewall attached", `["soc2","cis-v8","iso27001"]`},
		{"demo-scan-3", "do-droplet-no-firewall", "high", "fail", "digitalocean", "do:droplet:web-prod-02", "web-prod-02", "droplet", "Droplet has no firewall attached", `["soc2","cis-v8","iso27001"]`},
		{"demo-scan-3", "do-droplet-no-firewall", "high", "fail", "digitalocean", "do:droplet:api-prod-01", "api-prod-01", "droplet", "Droplet has no firewall attached", `["soc2","cis-v8","iso27001"]`},
		{"demo-scan-3", "do-droplet-no-firewall", "high", "fail", "digitalocean", "do:droplet:api-prod-02", "api-prod-02", "droplet", "Droplet has no firewall attached", `["soc2","cis-v8","iso27001"]`},
		{"demo-scan-3", "do-spaces-public-acl", "critical", "fail", "digitalocean", "do:space:assets-prod", "assets-prod", "space", "Spaces bucket has public ACL", `["soc2","pci-dss-v4","iso27001"]`},
		{"demo-scan-3", "do-spaces-public-acl", "critical", "fail", "digitalocean", "do:space:legacy-public", "legacy-public", "space", "Spaces bucket has public ACL", `["soc2","pci-dss-v4","iso27001"]`},
		{"demo-scan-3", "do-spaces-public-acl", "critical", "fail", "digitalocean", "do:space:misc-bucket", "misc-bucket", "space", "Spaces bucket has public ACL", `["soc2","pci-dss-v4","iso27001"]`},
		{"demo-scan-3", "do-account-2fa", "high", "fail", "digitalocean", "do:account:team", "team-account", "account", "Team 2FA is not enforced for all members", `["soc2","iso27001","cis-v8"]`},
		{"demo-scan-3", "do-managed-db-public", "high", "fail", "digitalocean", "do:database:postgres-prod", "postgres-prod", "database", "Managed database accepts connections from the public internet", `["soc2","pci-dss-v4"]`},
		{"demo-scan-3", "do-managed-db-no-backup-window", "medium", "fail", "digitalocean", "do:database:postgres-prod", "postgres-prod", "database", "Managed database has no backup window configured", `["soc2","cis-v8"]`},
		{"demo-scan-3", "do-firewall-ssh-from-any", "high", "fail", "digitalocean", "do:firewall:default", "default", "firewall", "Firewall allows SSH (22) from 0.0.0.0/0", `["soc2","cis-v8","iso27001"]`},
		{"demo-scan-3", "do-firewall-rdp-from-any", "high", "fail", "digitalocean", "do:firewall:windows", "windows", "firewall", "Firewall allows RDP (3389) from 0.0.0.0/0", `["soc2","cis-v8"]`},
		{"demo-scan-3", "do-droplet-old-image", "low", "fail", "digitalocean", "do:droplet:legacy-01", "legacy-01", "droplet", "Droplet image is more than 180 days old", `["cis-v8"]`},
		{"demo-scan-3", "do-droplet-old-image", "low", "fail", "digitalocean", "do:droplet:legacy-02", "legacy-02", "droplet", "Droplet image is more than 180 days old", `["cis-v8"]`},
		{"demo-scan-3", "do-spaces-versioning-disabled", "medium", "fail", "digitalocean", "do:space:backups-prod", "backups-prod", "space", "Spaces bucket versioning is disabled", `["soc2","cis-v8"]`},
		{"demo-scan-3", "do-cert-near-expiry", "medium", "fail", "digitalocean", "do:cert:wildcard", "wildcard", "certificate", "TLS certificate expires within 30 days", `["soc2","iso27001"]`},
		{"demo-scan-3", "do-spaces-no-encryption", "medium", "fail", "digitalocean", "do:space:logs-prod", "logs-prod", "space", "Spaces bucket has no default encryption", `["soc2","pci-dss-v4"]`},
	}

	const findingQ = `INSERT INTO findings (id, scan_id, fingerprint, check_id, severity, status, provider,
	                                         resource_id, resource_name, resource_type, message,
	                                         framework_ids, first_seen_at, last_seen_at, created_at)
	                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	                  ON CONFLICT(id) DO NOTHING`
	const resourceQ = `INSERT INTO resources (id, name, type, provider, first_seen_at, last_seen_at, last_seen_scan_id)
	                   VALUES (?, ?, ?, ?, ?, ?, ?)
	                   ON CONFLICT(id) DO UPDATE SET
	                     name = excluded.name, type = excluded.type, provider = excluded.provider,
	                     last_seen_at = excluded.last_seen_at, last_seen_scan_id = excluded.last_seen_scan_id`

	for i, f := range demo {
		findingID := fmt.Sprintf("demo-finding-%03d", i+1)
		fingerprint := fmt.Sprintf("%s|%s|%s|%s", f.scanID, f.checkID, f.resourceID, f.severity)
		_, _ = st.DB().ExecContext(ctx, findingQ,
			findingID, f.scanID, fingerprint, f.checkID, f.severity, f.status, f.provider,
			f.resourceID, f.resourceName, f.resourceType, f.message,
			f.frameworkIDs, now, now, now)
		_, _ = st.DB().ExecContext(ctx, resourceQ,
			f.resourceID, f.resourceName, f.resourceType, f.provider, now, now, f.scanID)
		_ = strings.TrimSpace // keep the strings import live for future template helpers
	}
}
