package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/server"
	"github.com/darpanzope/compliancekit/internal/server/api"
	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/events"
	"github.com/darpanzope/compliancekit/internal/server/logs"
	"github.com/darpanzope/compliancekit/internal/server/scim"
	"github.com/darpanzope/compliancekit/internal/server/store"
	"github.com/darpanzope/compliancekit/internal/server/ui"
	"github.com/darpanzope/compliancekit/internal/server/webhook"
	"github.com/darpanzope/compliancekit/internal/server/worker"
)

// newServeCmd builds `compliancekit serve`, the v1.3 daemon entry
// point. Loads a server.Config from flags + env, constructs the HTTP
// server, and blocks until SIGINT/SIGTERM trigger a graceful shutdown
// (15-second drain for in-flight requests).
//
// ADR-005: serve mode is optional forever. Every feature still ships
// to the CLI first. Day-1 internal interfaces are daemon-aware so
// landing serve here is a feature add, not a rewrite.
func newServeCmd() *cobra.Command {
	cfg := server.Default()
	var dbPath string
	var githubSecret string
	var demoSeed bool
	var insecureCookies bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the compliancekit daemon (HTTP server + web UI)",
		Long: `serve starts the long-running compliancekit daemon. Same binary,
same checks, same output formats — just a different entry point.
Hosts a REST API + web UI that the v1.4 Studio + v1.5 Explorer
phases layer on top of.

The daemon binds to 127.0.0.1 by default so the out-of-the-box
experience is loopback-only; pass --addr=0.0.0.0 to expose on every
interface. Always run behind TLS in production (terminate at a
reverse proxy like nginx/Caddy/Traefik) — the daemon ships strict
security headers including HSTS that assume TLS upstream.

Observability:

  GET /health     liveness probe, returns 200 + "ok"
  GET /metrics    Prometheus-format metrics (compliancekit_http_*, go_*)

Both endpoints are intentionally unauthenticated. Operators who need
auth-gated metrics put the daemon behind a reverse proxy that
strips them.

SIGINT / SIGTERM trigger a graceful shutdown with a 15-second grace
period for in-flight requests to drain.`,
		Example: `  compliancekit serve                     # default 127.0.0.1:8080
  compliancekit serve --port=9000
  compliancekit serve --addr=0.0.0.0 --port=8080  # bind all interfaces (review your firewall)`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), cmd.OutOrStdout(), cfg, dbPath, githubSecret, demoSeed, insecureCookies)
		},
	}
	cmd.Flags().StringVar(&cfg.Addr, "addr", cfg.Addr, "bind interface (use 0.0.0.0 to expose on every NIC)")
	cmd.Flags().IntVar(&cfg.Port, "port", cfg.Port, "TCP port")
	cmd.Flags().StringVar(&dbPath, "db", "./.compliancekit/serve.db", "SQLite file path (or postgres://... DSN; see CONFIGURATION.md)")
	cmd.Flags().StringVar(&githubSecret, "github-webhook-secret", "", "shared secret for the /webhooks/github HMAC verification (empty disables the route)")
	cmd.Flags().BoolVar(&demoSeed, "demo", false, "seed a realistic demo dataset (users / providers / scans / inbox) into a fresh SQLite — screenshot-grade evaluator UX day one")
	cmd.Flags().BoolVar(&insecureCookies, "insecure-cookies", false, "drop the Secure attribute + __Host- prefix on the session cookie — required for plain-HTTP dev / loopback; never enable in production")

	// v1.4 Phase 12: daemon-bootstrap subcommands (users / tokens).
	// `compliancekit serve users create --admin --email=…` no longer
	// requires a throwaway Go program to call auth.NewUsers().Create()
	// directly — same factories the daemon uses.
	addBootstrapSubcommands(cmd)
	return cmd
}

// runServe constructs the server, installs signal handlers, and
// blocks until shutdown. Split from newServeCmd so tests can drive
// the same code path without going through cobra.
func runServe(ctx context.Context, stdout interface {
	Write([]byte) (int, error)
}, cfg server.Config, dbPath, githubSecret string, demoSeed, insecureCookies bool) error {
	// Open the persistent store. SQLite path or postgres:// DSN —
	// both backends behind the same Store interface (phase 1 + 2).
	st, err := openStore(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = st.Close() }()
	if err := st.MigrateUp(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	// v1.4 Phase 12: --demo seeds a realistic dataset (demo admin
	// user, two providers, three completed scans w/ descending trend,
	// inbox alert) so evaluators see something interesting on every
	// page within five seconds of boot.
	if demoSeed {
		if err := seedDemoData(ctx, st); err != nil {
			return fmt.Errorf("seed demo: %w", err)
		}
		fmt.Fprintln(stdout, "  demo:    seeded (login demo@compliancekit.dev / demo-please-change)")
	}

	// Auth subjects.
	users := auth.NewUsers(st)
	sessions := auth.NewSessions(st)
	sessions.SecureCookies = !insecureCookies
	tokens := auth.NewTokens(st)

	// v1.6 phase 0: construct the shared SSE event bus + thread it
	// through every publisher (worker pool + RealRunner) and the
	// API mount (which exposes /api/v1/events). Nil-safe everywhere;
	// the daemon still boots without it, the route just 404s.
	eventBus := events.NewProducer()

	// v1.6 phase 6: in-UI log tail. Wrap the default slog handler so
	// every structured log line ALSO captures into a 500-line ring
	// buffer the /admin/logs page streams via SSE. Stderr output is
	// preserved (the wrapper writes through).
	logBuf := logs.New()
	stderrH := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(logBuf.Handler(stderrH)))

	srv := server.New(cfg)
	// Mount the v1.3 REST API on the daemon's chi router.
	apiH := api.New(st, users, tokens, sessions).WithEvents(eventBus)
	apiH.Mount(srv.Router())
	// Mount /api/auth/{login,logout,me} so the UI login form has a
	// real POST target. Missing in v1.3.0; fixed in v1.3.1.
	auth.Mount(srv.Router(), users, sessions)
	// Mount the v1.3 webhook receivers (/webhooks/github + /webhooks/{id}).
	// v1.6 phase 5: thread the event bus so accepted webhooks fan out
	// webhook.received events to /api/v1/events subscribers (toasts +
	// activity timeline + scans-list banner).
	webhookH := webhook.New(st, webhook.Config{GitHubSecret: githubSecret}).WithEvents(eventBus)
	webhookH.Mount(srv.Router())

	// Mount the v1.3 minimal UI shell (login + scans + providers + checks).
	uiH := ui.New(st, users, sessions).WithLogBuffer(logBuf)
	// v1.12 phase 8 — backup directory + Postgres DSN for pg_dump.
	uiH.SetBackupConfig(os.Getenv("CK_BACKUP_DIR"), backupDSN(dbPath))
	uiH.Mount(srv.Router())

	// v1.5.1 F15: discover OIDC providers via env vars + mount each
	// one's /oidc/{id}/{login,callback} routes. Each constructed
	// provider also produces a button entry for the /login template.
	// The OIDC handler code shipped in v1.3 with unit tests but was
	// never wired into production by NewOIDC + Mount.
	if buttons, err := loadOIDCFromEnv(ctx, srv.Router(), users, sessions, st); err != nil {
		fmt.Fprintf(stdout, "  oidc:    warning — %v\n", err)
	} else if len(buttons) > 0 {
		uiH.SetOIDCProviders(buttons)
		ids := make([]string, 0, len(buttons))
		for _, b := range buttons {
			ids = append(ids, b.ID)
		}
		fmt.Fprintf(stdout, "  oidc:    %s\n", strings.Join(ids, ", "))
	}

	// v1.12 phase 4: SCIM 2.0 user + group provisioning. Mounted
	// when CK_SCIM_BEARER_TOKEN is set so the daemon never exposes
	// the surface unauthenticated. SCIM Groups map 1:1 onto v1.12
	// phase 0 RBAC roles — adding a user to a Group grants the role.
	if bearer := os.Getenv("CK_SCIM_BEARER_TOKEN"); bearer != "" {
		scimSrv := scim.New(st, users, sessions, bearer)
		scimSrv.Mount(srv.Router())
		fmt.Fprintf(stdout, "  scim:    /scim/v2/ (bearer auth)\n")
	}

	// v1.12 phase 3: discover SAML IdPs the same way + mount each
	// /saml/{id}/{login,acs,metadata} route group.
	if buttons, err := loadSAMLFromEnv(ctx, srv.Router(), users, sessions, st); err != nil {
		fmt.Fprintf(stdout, "  saml:    warning — %v\n", err)
	} else if len(buttons) > 0 {
		uiH.SetSAMLProviders(buttons)
		ids := make([]string, 0, len(buttons))
		for _, b := range buttons {
			ids = append(ids, b.ID)
		}
		fmt.Fprintf(stdout, "  saml:    %s\n", strings.Join(ids, ", "))
	}

	// Spawn the background worker pool. v1.5.1 phase 5 swaps the
	// v1.3 StubRunner (50ms sleep + zero findings) for a RealRunner
	// that builds collectors from the DB providers table, filters
	// the check registry by checks_state, and runs engine.Run for
	// real findings. The control-plane gap that made /scans/new
	// feel like it worked but insert nothing (F1) is closed here.
	workerCfg := worker.Default()
	workerCfg.Runner = worker.NewRealRunner(st).WithEvents(eventBus)
	workerCfg.Events = eventBus
	pool := worker.New(st, workerCfg)

	// Install signal handlers on the parent context. When the user
	// hits Ctrl-C or systemd sends SIGTERM, the signal-aware context
	// cancels, which is what Server.Run() waits on to trigger its
	// graceful shutdown path.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool.Start(ctx)
	defer pool.Stop()

	fmt.Fprintf(stdout, "compliancekit daemon listening on http://%s\n", srv.Addr())
	fmt.Fprintf(stdout, "  health:  http://%s/health\n", srv.Addr())
	fmt.Fprintf(stdout, "  metrics: http://%s/metrics\n", srv.Addr())
	fmt.Fprintf(stdout, "  api:     http://%s/api/v1/\n", srv.Addr())
	fmt.Fprintf(stdout, "  ui:      http://%s/\n", srv.Addr())
	fmt.Fprintf(stdout, "  store:   %s (driver=%s)\n", dbPath, st.Driver())
	fmt.Fprintln(stdout, "(Ctrl-C to stop)")
	return srv.Run(ctx)
}

// openStore picks SQLite vs Postgres based on the dbPath prefix. A
// "postgres://" or "postgresql://" DSN selects Postgres; anything
// else is treated as a SQLite file path (parent directory created
// on demand).
func openStore(ctx context.Context, dbPath string) (*store.Store, error) {
	if isPostgresDSN(dbPath) {
		return store.OpenPostgres(ctx, dbPath)
	}
	if err := makeParentDir(dbPath); err != nil {
		return nil, err
	}
	return store.OpenSQLite(ctx, dbPath)
}

// backupDSN returns the DSN for pg_dump when the daemon's store is
// Postgres-backed; empty for SQLite (the backup manager uses VACUUM
// INTO directly in that case).
func backupDSN(dbPath string) string {
	if isPostgresDSN(dbPath) {
		return dbPath
	}
	return ""
}

func isPostgresDSN(s string) bool {
	return strings.HasPrefix(s, "postgres://") ||
		strings.HasPrefix(s, "postgresql://") ||
		strings.HasPrefix(s, "host=")
}

// makeParentDir creates the directory holding path with 0o750 perms.
// No-op when the parent already exists. Lets `compliancekit serve`
// run against a fresh checkout without a separate `mkdir` step.
func makeParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o750)
}
