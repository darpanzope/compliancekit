// Package server is the v1.3 serve-mode HTTP daemon. It wires the
// chi router, security middleware, observability endpoints
// (/health + /metrics), and the read/write API + UI handlers that
// v1.3-v1.5 fill in across phases. The single entry point is New(),
// which returns a *Server whose Run(ctx) method blocks until the
// context cancels — graceful shutdown happens on SIGTERM/SIGINT
// signaled into the same context.
//
// ADR-015 codifies the UI stack (htmx + Alpine + Tailwind + Preline
// + vanilla SVG, all go:embed-ed). Single-binary invariant preserved;
// no Node runtime ships with compliancekit; no CDN is reached at
// runtime.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/darpanzope/compliancekit/internal/server/compress"
	"github.com/darpanzope/compliancekit/internal/server/etag"
)

// Config carries every knob the daemon takes at startup. Loaded by
// the CLI subcommand from a mix of compliancekit.yaml + flags + env.
// Defaults below in Default().
type Config struct {
	// Addr is the bind interface; default "127.0.0.1" so the
	// out-of-the-box experience is loopback-only (operator opts into
	// 0.0.0.0 explicitly).
	Addr string

	// Port is the TCP port; default 8080. Override via --port.
	Port int

	// ReadHeaderTimeout caps the time a peer may take to send request
	// headers; protects against slowloris-style starvation.
	ReadHeaderTimeout time.Duration

	// IdleTimeout caps keep-alive idle duration.
	IdleTimeout time.Duration
}

// Default returns the recommended baseline Config. Tests construct
// their own; the CLI overlays flags + env onto a Default().
func Default() Config {
	return Config{
		Addr:              "127.0.0.1",
		Port:              8080,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// Server is the running daemon. Construct via New(); start via Run().
type Server struct {
	cfg     Config
	router  chi.Router
	httpSrv *http.Server
	metrics *metricsRegistry
}

// New builds the daemon. Wires middleware in the right order
// (recovery → request-id → real-ip → metrics → security headers),
// mounts /health + /metrics, and leaves the rest of the routing for
// future phases to attach via the returned *Server's Router() method.
func New(cfg Config) *Server {
	r := chi.NewRouter()
	m := newMetrics()

	// Middleware order matters; the chain runs top-down on the way in
	// and bottom-up on the way out.
	r.Use(middleware.RequestID) // every request gets an X-Request-ID for log correlation
	// middleware.RealIP was removed at v1.14.1 per GHSA-3fxj-6jh8-hvhx /
	// GHSA-rjr7-jggh-pgcp / GHSA-9g5q-2w5x-hmxf: it overwrites r.RemoteAddr
	// from X-Forwarded-For / X-Real-IP / True-Client-IP unconditionally,
	// which means an attacker on a daemon exposed without a trusted
	// reverse-proxy in front can forge the source IP in audit_log + the
	// activity timeline. The audit_log + login handler now use the raw
	// TCP peer (r.RemoteAddr). Operators behind a proxy see the proxy's
	// IP in audit_log; the proxy's own access log carries the real
	// client. A properly-vetted forwarded-header middleware (trust-list
	// configured) lands in v1.15.x.
	r.Use(middleware.Recoverer) // panics → 500 + stack in the log
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(securityHeaders)     // CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
	r.Use(etag.Middleware)     // v1.11 phase 5 — weak ETag + If-None-Match 304 short-circuit
	r.Use(compress.Middleware) // v1.11 phase 4 — brotli + gzip + Vary, SSE-passthrough
	r.Use(m.middleware)        // count requests + observe latency

	// Observability — both endpoints are intentionally unauthenticated.
	// /health is for Kubernetes liveness/readiness probes + uptime
	// checkers; /metrics is for Prometheus scrapers. Operators who want
	// auth-gated metrics put the daemon behind a reverse proxy that
	// strips them.
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	r.Method(http.MethodGet, "/metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))

	httpSrv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Addr, cfg.Port),
		Handler:           r,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}
	return &Server{cfg: cfg, router: r, httpSrv: httpSrv, metrics: m}
}

// Router returns the chi router so later-phase packages (api/, auth/,
// ui/) can mount their routes without re-importing the middleware
// stack. Callers should attach routes before Run().
func (s *Server) Router() chi.Router { return s.router }

// QueueDepthObserver returns the daemon's worker.DepthObserver
// implementation so cmd/serve can wire it into the worker pool's
// autoscale sampler. nil-safe — if the metrics registry isn't yet
// constructed (zero-value Server), the worker pool silently no-ops.
//
// The interface signature lives in internal/server/worker; we
// satisfy it without importing the package to avoid a circular dep.
func (s *Server) QueueDepthObserver() interface{ ObserveQueueDepth(int) } {
	return s.metrics
}

// Addr returns the bound listen address; useful for tests that need
// the concrete port when cfg.Port == 0 (ephemeral) is requested.
func (s *Server) Addr() string { return s.httpSrv.Addr }

// Run starts the HTTP listener and blocks until ctx is canceled.
// On cancellation it triggers a graceful shutdown with a 15-second
// grace period for in-flight requests to drain. Returns nil on a
// clean shutdown; the underlying http.Server error otherwise.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		if err := s.httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := s.httpSrv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
}

// metricsRegistry holds the Prometheus collectors the middleware
// updates per request. Kept on its own type so future-phase handlers
// can register their own counters without touching server.go.
type metricsRegistry struct {
	registry   *prometheus.Registry
	reqs       *prometheus.CounterVec
	dur        *prometheus.HistogramVec
	queueDepth prometheus.Gauge // v1.11 phase 8 — worker queue depth
}

// ObserveQueueDepth implements worker.DepthObserver so the worker
// pool's autoscale sampler updates the daemon's Prometheus gauge.
func (m *metricsRegistry) ObserveQueueDepth(d int) {
	if m == nil || m.queueDepth == nil {
		return
	}
	m.queueDepth.Set(float64(d))
}

func newMetrics() *metricsRegistry {
	reg := prometheus.NewRegistry()
	reqs := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "compliancekit",
		Subsystem: "http",
		Name:      "requests_total",
		Help:      "Total HTTP requests served, labeled by method + path template + status code.",
	}, []string{"method", "path", "status"})
	dur := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "compliancekit",
		Subsystem: "http",
		Name:      "request_duration_seconds",
		Help:      "Wall-clock duration of HTTP requests, labeled by method + path template.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"method", "path"})
	queueDepth := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "compliancekit",
		Subsystem: "worker",
		Name:      "queue_depth",
		Help:      "Current count of scans in queued+running state. Drives the v1.11 phase 8 autoscale.",
	})
	// Standard Go process + runtime collectors so an operator gets
	// goroutine count, GC pause, FD count, etc. out of the box.
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(reqs, dur, queueDepth)
	return &metricsRegistry{registry: reg, reqs: reqs, dur: dur, queueDepth: queueDepth}
}

// middleware observes each request — counts + latency histogram. Path
// label uses the chi route pattern (e.g. /api/v1/scans/{id}) rather
// than the raw URL so the cardinality stays bounded.
func (m *metricsRegistry) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		path := chi.RouteContext(r.Context()).RoutePattern()
		if path == "" {
			path = "unknown"
		}
		m.reqs.WithLabelValues(r.Method, path, statusBucket(ww.Status())).Inc()
		m.dur.WithLabelValues(r.Method, path).Observe(time.Since(start).Seconds())
	})
}

// statusBucket coarsens an HTTP status to its 2xx/3xx/4xx/5xx family
// so the requests_total cardinality doesn't explode with every
// observed status code. The per-status detail is still in the access
// log if anyone needs it.
func statusBucket(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	case code >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}

// securityHeaders sets every header that the OWASP secure-headers
// project recommends as a baseline. CSP is strict (no inline scripts;
// 'unsafe-eval' is needed for Alpine 3's expression evaluator and
// 'unsafe-inline' for Tailwind's utility-class style attributes).
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// CSP shape: 'self' for everything by default; 'unsafe-eval' on
		// script-src because Alpine 3's default build evaluates x-data /
		// x-show / @keydown expressions via `(async function(){}).constructor(...)`
		// (the indirect AsyncFunction trick), which CSP gates the same
		// way it gates `new Function`. The CSP-friendly Alpine build
		// (@alpinejs/csp) is the only way to drop 'unsafe-eval', and it
		// requires every binding to be precompiled — out of scope for
		// the htmx + Alpine stack ADR-015 codified. 'unsafe-inline' on
		// style-src covers Tailwind's compiled utility classes that
		// land as inline `style=` attributes. No inline `<script>` tags
		// ship — the No-FOUC bootstrap + cmdk factory live in
		// /assets/app.js (v1.5.1).
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"img-src 'self' data:; "+
				"style-src 'self' 'unsafe-inline'; "+
				"script-src 'self' 'unsafe-eval'; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'; "+
				"form-action 'self'")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains") // operator MUST run behind TLS in prod
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		next.ServeHTTP(w, r)
	})
}
