package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestRolesRoutesMounted: mount regression guard. The routes resolve;
// the response code is 403 because the test request has no admin
// session, which is the right answer.
func TestRolesRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountRolesRoutes(r)

	for _, path := range []string{"/settings/roles"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("GET %s: 404 (route not mounted)", path)
		}
	}
}

// TestRolesListSeed verifies the rolesRepo reports the 4 built-in
// roles seeded by migration 0018.
func TestRolesListSeed(t *testing.T) {
	u, _ := newUIForTests(t)
	roles, err := u.rolesRepo().ListRoles(context.Background())
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) < 4 {
		t.Errorf("expected at least 4 built-in roles, got %d", len(roles))
	}
}

func TestErrSlug(t *testing.T) {
	if got := errSlug(nil); got != "" {
		t.Errorf("nil err: got %q want ''", got)
	}
}
