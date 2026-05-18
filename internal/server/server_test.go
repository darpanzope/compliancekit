package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestServer_HealthAndMetrics spins up the daemon on an ephemeral
// port, hits /health + /metrics, and verifies the security headers
// + correct response bodies are in place.
func TestServer_HealthAndMetrics(t *testing.T) {
	cfg := Default()
	cfg.Addr = "127.0.0.1"
	cfg.Port = 0 // ephemeral; we'll resolve via the listener below

	// Bind a listener ourselves so we know the port before starting
	// the daemon — Server doesn't expose a "started" channel yet.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cfg.Port = port
	srv := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-runErr:
			if err != nil {
				t.Logf("server returned: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server didn't shut down within 5s")
		}
	})

	base := "http://" + srv.Addr()
	waitReady(t, base+"/health")

	t.Run("health", func(t *testing.T) {
		body, hdrs := mustGet(t, base+"/health")
		if strings.TrimSpace(body) != "ok" {
			t.Errorf("/health body = %q, want \"ok\"", body)
		}
		assertSecurityHeaders(t, hdrs)
	})

	t.Run("metrics", func(t *testing.T) {
		body, hdrs := mustGet(t, base+"/metrics")
		if !strings.Contains(body, "compliancekit_http_requests_total") {
			t.Error("/metrics missing compliancekit_http_requests_total counter")
		}
		if !strings.Contains(body, "go_goroutines") {
			t.Error("/metrics missing go_goroutines (standard Go collector)")
		}
		assertSecurityHeaders(t, hdrs)
	})
}

// waitReady polls the URL until it returns 200 or the deadline hits.
// Necessary because Run() starts the listener in a goroutine; the
// HTTP request may race the listener.
func waitReady(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:gosec,noctx // test fixture
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server never became ready at %s", url)
}

// mustGet does an HTTP GET, fails the test on error, returns the
// body + headers.
func mustGet(t *testing.T, url string) (string, http.Header) {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec,noctx // test fixture
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d (body: %s)", resp.StatusCode, string(body))
	}
	return string(body), resp.Header
}

// assertSecurityHeaders verifies the OWASP-baseline headers are all
// present on the response. New headers added in securityHeaders()
// should also land here so the test fails when one is silently
// dropped during a refactor.
func assertSecurityHeaders(t *testing.T, h http.Header) {
	t.Helper()
	expected := map[string]string{
		"Content-Security-Policy":   "default-src 'self'",
		"Strict-Transport-Security": "max-age=31536000",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
	}
	for header, mustContain := range expected {
		got := h.Get(header)
		if got == "" {
			t.Errorf("missing security header %s", header)
			continue
		}
		if !strings.Contains(got, mustContain) {
			t.Errorf("%s = %q, want substring %q", header, got, mustContain)
		}
	}
}
