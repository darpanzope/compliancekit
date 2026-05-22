package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestSessionsRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountSessionsRoutes(r)
	req := httptest.NewRequest("GET", "/settings/sessions", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Errorf("GET /settings/sessions: 404 (route not mounted)")
	}
}

func TestSessionsListEmpty(t *testing.T) {
	u, _ := newUIForTests(t)
	got, err := u.sessions.ListAllActive(context.Background())
	if err != nil {
		t.Fatalf("ListAllActive: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("fresh store: expected 0 sessions, got %d", len(got))
	}
}

func TestGuessBrowser(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/121": "Edge",
		"Mozilla/5.0 AppleWebKit/537 Chrome/121":                               "Chrome",
		"Mozilla/5.0 (Macintosh) Firefox/118":                                  "Firefox",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/605 Safari/605":   "Safari",
		"curl/8.4.0":         "curl",
		"Go-http-client/1.1": "Go HTTP client",
		"":                   "",
	}
	for ua, want := range cases {
		if got := guessBrowser(ua); got != want {
			t.Errorf("guessBrowser(%q) = %q, want %q", ua, got, want)
		}
	}
}
