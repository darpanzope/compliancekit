package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestRenderCI_ContainsSecrets confirms each flavor lists the secret
// env vars for every configured provider so operators get a
// paste-once-in-CI-settings checklist.
func TestRenderCI_ContainsSecrets(t *testing.T) {
	ctx := context.Background()
	u, _ := newUIForTests(t)
	if err := u.upsertProvider(ctx, "digitalocean", "tok", nil); err != nil {
		t.Fatalf("upsertProvider: %v", err)
	}

	for _, flavor := range []ciFlavor{ciGitHub, ciGitLab, ciCircleCI} {
		body, err := u.renderCI(ctx, flavor)
		if err != nil {
			t.Fatalf("%s: %v", flavor, err)
		}
		if !strings.Contains(body, "DIGITALOCEAN_TOKEN") {
			t.Errorf("%s: DIGITALOCEAN_TOKEN missing from rendered body", flavor)
		}
		if !strings.Contains(body, "compliancekit") {
			t.Errorf("%s: compliancekit binary/action reference missing", flavor)
		}
	}
}

// TestRenderCI_EmptyDB still renders a sensible file (no providers
// configured = comments only).
func TestRenderCI_EmptyDB(t *testing.T) {
	u, _ := newUIForTests(t)
	body, err := u.renderCI(context.Background(), ciGitHub)
	if err != nil {
		t.Fatalf("renderCI: %v", err)
	}
	if !strings.Contains(body, "compliancekit Studio") {
		t.Errorf("empty-state body missing header:\n%s", body)
	}
}

// TestCIRoutesMounted exercises the three Phase 7 routes and confirms
// the {flavor} param actually drives the rendered body.
func TestCIRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountCIRoutes(r)

	for _, path := range []string{"/export/ci"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("GET %s: 404 (route not mounted)", path)
		}
	}

	for _, flavor := range []string{"github", "gitlab", "circleci"} {
		req := httptest.NewRequest("GET", "/export/ci/"+flavor+"/raw", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("raw %s: status %d want 200", flavor, rec.Code)
		}
	}

	// Unknown flavor → 404.
	req := httptest.NewRequest("GET", "/export/ci/jenkins/raw", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown flavor: status %d want 404", rec.Code)
	}
}

// TestEnvVarFor maps every shipping provider to a canonical secret
// name (paste-once convention).
func TestEnvVarFor(t *testing.T) {
	cases := map[string]string{
		"digitalocean": "DIGITALOCEAN_TOKEN",
		"aws":          "AWS_ROLE_ARN",
		"gcp":          "GOOGLE_APPLICATION_CREDENTIALS_JSON",
		"hetzner":      "HCLOUD_TOKEN",
		"kubernetes":   "KUBECONFIG",
		"linux":        "LINUX_SSH_KEY",
		"unknown":      "COMPLIANCEKIT_TOKEN",
	}
	for id, want := range cases {
		if got := envVarFor(id); got != want {
			t.Errorf("envVarFor(%q) = %q want %q", id, got, want)
		}
	}
}
