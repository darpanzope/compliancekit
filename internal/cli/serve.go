package cli

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/server"
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
			return runServe(cmd.Context(), cmd.OutOrStdout(), cfg)
		},
	}
	cmd.Flags().StringVar(&cfg.Addr, "addr", cfg.Addr, "bind interface (use 0.0.0.0 to expose on every NIC)")
	cmd.Flags().IntVar(&cfg.Port, "port", cfg.Port, "TCP port")
	return cmd
}

// runServe constructs the server, installs signal handlers, and
// blocks until shutdown. Split from newServeCmd so tests can drive
// the same code path without going through cobra.
func runServe(ctx context.Context, stdout interface {
	Write([]byte) (int, error)
}, cfg server.Config) error {
	srv := server.New(cfg)

	// Install signal handlers on the parent context. When the user
	// hits Ctrl-C or systemd sends SIGTERM, the signal-aware context
	// cancels, which is what Server.Run() waits on to trigger its
	// graceful shutdown path.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(stdout, "compliancekit daemon listening on http://%s\n", srv.Addr())
	fmt.Fprintf(stdout, "  health:  http://%s/health\n", srv.Addr())
	fmt.Fprintf(stdout, "  metrics: http://%s/metrics\n", srv.Addr())
	fmt.Fprintln(stdout, "(Ctrl-C to stop)")
	return srv.Run(ctx)
}
