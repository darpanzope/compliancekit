package etag

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func jsonHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
}

// TestMiddleware_AddsETag confirms the first request returns 200
// with an ETag header derived from the body.
func TestMiddleware_AddsETag(t *testing.T) {
	srv := httptest.NewServer(Middleware(jsonHandler(`{"hello":"world"}`)))
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("ETag"), `W/"`) {
		t.Errorf("ETag = %q, want weak prefix", resp.Header.Get("ETag"))
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"hello":"world"}` {
		t.Errorf("body = %q", body)
	}
}

// TestMiddleware_IfNoneMatch304 confirms a repeat request with the
// previous ETag returns 304 + empty body.
func TestMiddleware_IfNoneMatch304(t *testing.T) {
	srv := httptest.NewServer(Middleware(jsonHandler(`{"x":1}`)))
	defer srv.Close()

	req1, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	resp1, _ := http.DefaultTransport.RoundTrip(req1)
	_ = resp1.Body.Close()
	tag := resp1.Header.Get("ETag")
	if tag == "" {
		t.Fatal("first request missing ETag")
	}

	req2, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	req2.Header.Set("If-None-Match", tag)
	resp2, _ := http.DefaultTransport.RoundTrip(req2)
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != 304 {
		t.Errorf("status = %d, want 304", resp2.StatusCode)
	}
	body, _ := io.ReadAll(resp2.Body)
	if len(body) != 0 {
		t.Errorf("304 body should be empty, got %d bytes", len(body))
	}
	if resp2.Header.Get("ETag") != tag {
		t.Errorf("304 should preserve ETag")
	}
}

// TestMiddleware_DifferentBodyDifferentTag confirms two responses
// with different bodies produce different ETags.
func TestMiddleware_DifferentBodyDifferentTag(t *testing.T) {
	srv1 := httptest.NewServer(Middleware(jsonHandler(`{"a":1}`)))
	defer srv1.Close()
	srv2 := httptest.NewServer(Middleware(jsonHandler(`{"a":2}`)))
	defer srv2.Close()

	req1, _ := http.NewRequestWithContext(context.Background(), "GET", srv1.URL, nil)
	resp1, _ := http.DefaultTransport.RoundTrip(req1)
	_ = resp1.Body.Close()
	req2, _ := http.NewRequestWithContext(context.Background(), "GET", srv2.URL, nil)
	resp2, _ := http.DefaultTransport.RoundTrip(req2)
	_ = resp2.Body.Close()
	if resp1.Header.Get("ETag") == resp2.Header.Get("ETag") {
		t.Errorf("different bodies should produce different ETags")
	}
}

// TestMiddleware_SSESkipped confirms event-stream passes through.
func TestMiddleware_SSESkipped(t *testing.T) {
	srv := httptest.NewServer(Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: ping\n\n"))
	})))
	defer srv.Close()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	resp, _ := http.DefaultTransport.RoundTrip(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.Header.Get("ETag") != "" {
		t.Errorf("SSE should not get ETag")
	}
}

// TestMiddleware_PostSkipped confirms POST passes through.
func TestMiddleware_PostSkipped(t *testing.T) {
	srv := httptest.NewServer(Middleware(jsonHandler(`{}`)))
	defer srv.Close()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", srv.URL, nil)
	resp, _ := http.DefaultTransport.RoundTrip(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.Header.Get("ETag") != "" {
		t.Errorf("POST should not get ETag")
	}
}

// TestMatchesIfNoneMatch exercises the header parser.
func TestMatchesIfNoneMatch(t *testing.T) {
	tag := `W/"deadbeef"`
	cases := []struct {
		hdr  string
		want bool
	}{
		{"", false},
		{"*", true},
		{`W/"deadbeef"`, true},
		{`"deadbeef"`, true}, // weak comparison
		{`W/"deadbeef", W/"feedface"`, true},
		{`W/"feedface"`, false},
	}
	for _, c := range cases {
		if got := matchesIfNoneMatch(c.hdr, tag); got != c.want {
			t.Errorf("matchesIfNoneMatch(%q, %q) = %v, want %v", c.hdr, tag, got, c.want)
		}
	}
}
