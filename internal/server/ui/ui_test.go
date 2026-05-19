package ui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestInitialsFromEmail covers the cases the topbar avatar renders:
// double-word locals, single-word locals, separator splits, and the
// empty-input fallback. Drives the gradient avatar in base.html.
func TestInitialsFromEmail(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"jane.doe@acme.com", "JD"},
		{"alice@acme.com", "A"},
		{"alice", "A"},
		{"first.middle.last@x", "FM"},
		{"al+filter@acme.com", "AF"},
		{"", "?"},
		{"@no-local.com", "?"},
		{"jane_doe@x", "JD"},
		{"a-b-c@x", "AB"},
	}
	for _, c := range cases {
		if got := initialsFromEmail(c.in); got != c.want {
			t.Errorf("initialsFromEmail(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestAssetsRoute confirms the /assets/* route serves the embedded
// bundle compiled by `make ui` — verifies the v1.4 Phase 0 wiring
// from internal/server/assets/ through the chi route mount.
func TestAssetsRoute(t *testing.T) {
	r := chi.NewRouter()
	r.Get("/assets/*", assetsHandler())

	cases := []struct {
		path        string
		wantSnippet string
	}{
		// app.css carries the Tailwind preflight + our token CSS vars.
		// "preflight" doesn't appear in minified output; the --primary
		// custom property does because we set it as a token.
		{"/assets/app.css", "--primary"},
		// htmx + alpine both include their version string near the top
		// of the minified bundle.
		{"/assets/htmx.min.js", "htmx"},
		{"/assets/alpine.min.js", "Alpine"},
		// preline.js (the un-minified vendored copy) starts with the
		// IIFE wrapper.
		{"/assets/preline.js", "preline"},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", c.path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", c.path, w.Code)
			continue
		}
		body, _ := io.ReadAll(w.Body)
		if !strings.Contains(strings.ToLower(string(body)), strings.ToLower(c.wantSnippet)) {
			t.Errorf("%s: body missing %q", c.path, c.wantSnippet)
		}
		if got := w.Header().Get("Cache-Control"); !strings.Contains(got, "max-age") {
			t.Errorf("%s: missing Cache-Control max-age (got %q)", c.path, got)
		}
	}

	// Unknown asset returns 404, not a panic.
	req := httptest.NewRequest("GET", "/assets/does-not-exist.js", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("/assets/does-not-exist.js: status %d, want 404", w.Code)
	}
}

// TestDefaultNavStable guards against accidental nav-row deletion in
// base.html refactors — every page key the .Active sentinel uses must
// have a matching nav entry, otherwise the sidebar quietly stops
// highlighting that page.
func TestDefaultNavStable(t *testing.T) {
	want := map[string]string{
		"scans":     "/scans",
		"providers": "/providers",
		"checks":    "/checks",
	}
	got := map[string]string{}
	for _, n := range defaultNav {
		got[n.Key] = n.Href
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("defaultNav[%q] = %q, want %q", k, got[k], v)
		}
	}
}
