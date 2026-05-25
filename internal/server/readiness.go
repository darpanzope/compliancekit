package server

// v1.15 phase 7 — Deep /health/ready endpoint.
//
// /health stays the cheap liveness check (always 200 + "ok" when
// the HTTP server is up). /health/ready runs a configurable set of
// named probes and returns 200 only when every check passes, 503
// with the per-check status otherwise.
//
// The daemon registers two checks by default:
//
//   db          DB writable + migrations current (ping + version
//               query that lives in internal/server/store).
//   migrations  migration count matches the embedded schema (the
//               same gate the boot path runs).
//
// cmd/serve appends:
//
//   queue       worker pool's most-recent depth sample fresh
//               (heartbeat) — proves the autoscale sampler is alive.
//   leader      (HA mode only) elector.IsLeader() — standbys answer
//               200 from /health/ready too so the LB can round-robin
//               read traffic; the leader is the only one claiming
//               work. Operators who want LB-leader-only routing add
//               the v1.15.x ServeHTTP header X-Compliancekit-Leader.

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// ReadinessCheck names a single probe. Name appears in the JSON
// response body + the v1.15.x compliancekit_readiness_* metric.
type ReadinessCheck struct {
	Name string
	// Check returns nil when the probe is healthy. The error string
	// surfaces in the /health/ready JSON body (sanitized — no
	// secrets in the message; the daemon already controls every
	// caller).
	Check func(ctx context.Context) error
	// Timeout caps the probe execution. Zero falls back to 3s.
	Timeout time.Duration
}

// ReadinessRegistry holds the daemon's readiness checks. Safe for
// concurrent Add / Run.
type ReadinessRegistry struct {
	mu     sync.RWMutex
	checks []ReadinessCheck
}

// Add appends a check. Thread-safe.
func (r *ReadinessRegistry) Add(c ReadinessCheck) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checks = append(r.checks, c)
}

// readinessReport is the JSON body /health/ready returns.
type readinessReport struct {
	Status string             `json:"status"`
	Checks []readinessOutcome `json:"checks"`
}

type readinessOutcome struct {
	Name   string `json:"name"`
	Status string `json:"status"`        // "ok" or "fail"
	Err    string `json:"err,omitempty"` // sanitized error message
}

// WithReadiness registers a readiness check on the server. Chainable.
func (s *Server) WithReadiness(c ReadinessCheck) *Server {
	if s.readiness == nil {
		s.readiness = &ReadinessRegistry{}
	}
	s.readiness.Add(c)
	return s
}

// healthReadyHandler renders the JSON report. Returns 200 when
// every check is ok, 503 when any fail.
func (s *Server) healthReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.readiness == nil {
			// No checks registered — treat as ready (the legacy
			// /health endpoint already returned 200 in that case).
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(readinessReport{
				Status: "ok",
				Checks: []readinessOutcome{},
			})
			return
		}
		s.readiness.mu.RLock()
		checks := append([]ReadinessCheck(nil), s.readiness.checks...)
		s.readiness.mu.RUnlock()

		out := readinessReport{Status: "ok", Checks: make([]readinessOutcome, 0, len(checks))}
		failed := false
		for _, c := range checks {
			tm := c.Timeout
			if tm == 0 {
				tm = 3 * time.Second
			}
			ctx, cancel := context.WithTimeout(r.Context(), tm)
			err := c.Check(ctx)
			cancel()
			outcome := readinessOutcome{Name: c.Name, Status: "ok"}
			if err != nil {
				failed = true
				outcome.Status = "fail"
				outcome.Err = err.Error()
			}
			out.Checks = append(out.Checks, outcome)
		}
		w.Header().Set("Content-Type", "application/json")
		if failed {
			out.Status = "fail"
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(out)
	}
}
