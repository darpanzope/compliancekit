package compress

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
)

// jsonHandler serves a fixed >1 KiB JSON body; the body needs to be
// large enough to clear the minCompressSize floor.
func jsonHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
}

func TestNegotiate(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"", ""},
		{"identity", ""},
		{"gzip", "gzip"},
		{"br", "br"},
		{"gzip, br", "br"}, // br always wins when both present
		{"deflate, gzip;q=0.5", "gzip"},
		{"gzip;q=1.0, br;q=0.9", "br"}, // we don't honor q-values; br wins on presence
	}
	for _, c := range cases {
		if got := negotiate(c.header); got != c.want {
			t.Errorf("negotiate(%q) = %q, want %q", c.header, got, c.want)
		}
	}
}

func TestMiddleware_GzipFallback(t *testing.T) {
	body := strings.Repeat(`{"k":"v"} `, 200) // ~2 KiB
	srv := httptest.NewServer(Middleware(jsonHandler(body)))
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", resp.Header.Get("Content-Encoding"))
	}
	if !strings.Contains(resp.Header.Get("Vary"), "Accept-Encoding") {
		t.Errorf("Vary header missing Accept-Encoding: %q", resp.Header.Get("Vary"))
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	out, _ := io.ReadAll(gz)
	if string(out) != body {
		t.Errorf("decompressed body mismatch (got %d bytes, want %d)", len(out), len(body))
	}
}

func TestMiddleware_BrotliPreferred(t *testing.T) {
	body := strings.Repeat(`{"k":"v"} `, 200)
	srv := httptest.NewServer(Middleware(jsonHandler(body)))
	defer srv.Close()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	req.Header.Set("Accept-Encoding", "br, gzip")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Content-Encoding"); got != "br" {
		t.Fatalf("Content-Encoding = %q, want br", got)
	}
	br := brotli.NewReader(resp.Body)
	out, _ := io.ReadAll(br)
	if string(out) != body {
		t.Errorf("decompressed body mismatch")
	}
}

func TestMiddleware_SmallBodySkipped(t *testing.T) {
	body := `{"ok":true}` // <1 KiB
	srv := httptest.NewServer(Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "11")
		_, _ = w.Write([]byte(body))
	})))
	defer srv.Close()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	resp, _ := http.DefaultTransport.RoundTrip(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.Header.Get("Content-Encoding") != "" {
		t.Errorf("small body should not be compressed; got Content-Encoding=%q", resp.Header.Get("Content-Encoding"))
	}
	out, _ := io.ReadAll(resp.Body)
	if string(out) != body {
		t.Errorf("body = %q, want %q", out, body)
	}
}

func TestMiddleware_SSEPassthrough(t *testing.T) {
	srv := httptest.NewServer(Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(strings.Repeat("data: ping\n\n", 200)))
	})))
	defer srv.Close()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	req.Header.Set("Accept-Encoding", "br, gzip")
	resp, _ := http.DefaultTransport.RoundTrip(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.Header.Get("Content-Encoding") != "" {
		t.Errorf("SSE should pass through; got Content-Encoding=%q", resp.Header.Get("Content-Encoding"))
	}
}

func TestMiddleware_BinaryPassthrough(t *testing.T) {
	body := bytes.Repeat([]byte{0x89, 0x50, 0x4E, 0x47}, 500) // PNG header repeated
	srv := httptest.NewServer(Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(body)
	})))
	defer srv.Close()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	req.Header.Set("Accept-Encoding", "br, gzip")
	resp, _ := http.DefaultTransport.RoundTrip(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.Header.Get("Content-Encoding") != "" {
		t.Errorf("PNG should pass through; got Content-Encoding=%q", resp.Header.Get("Content-Encoding"))
	}
}

func TestIsCompressible(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"text/html; charset=utf-8", true},
		{"image/svg+xml", true},
		{"image/png", false},
		{"application/octet-stream", false},
		{"font/woff2", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isCompressible(c.ct); got != c.want {
			t.Errorf("isCompressible(%q) = %v, want %v", c.ct, got, c.want)
		}
	}
}
