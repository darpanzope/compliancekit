package ui

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestDashboardsRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountDashboardsRoutes(r)
	for _, path := range []string{"/dashboards"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("GET %s: 404 (route not mounted)", path)
		}
	}
}

func TestAtoiOr(t *testing.T) {
	if got := atoiOr("", 7); got != 7 {
		t.Errorf("atoiOr empty: got %d want 7", got)
	}
	if got := atoiOr("42", 7); got != 42 {
		t.Errorf("atoiOr 42: got %d want 42", got)
	}
	if got := atoiOr("nope", 7); got != 7 {
		t.Errorf("atoiOr nope: got %d want 7 (fallback)", got)
	}
}
