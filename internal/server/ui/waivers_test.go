package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// TestWaiversCreate_HappyPath confirms a full form POST lands a row
// with the right fields + a redirect to flash=created.
func TestWaiversCreate_HappyPath(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)

	form := url.Values{
		"check_id":    []string{"do-spaces-public-acl"},
		"resource_id": []string{"droplet/test-*"},
		"reason":      []string{"Staging only; synthetic data."},
		"approver":    []string{"security@example.com"},
		"expires_at":  []string{"2099-12-31"},
	}
	req := httptest.NewRequest("POST", "/waivers", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	u.waiversCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d want 303", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=created") {
		t.Errorf("Location=%q expected flash=created", rec.Header().Get("Location"))
	}

	var check, resource, approver, expires string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT check_id, resource_id, approver, COALESCE(expires_at,'') FROM waivers`).
		Scan(&check, &resource, &approver, &expires); err != nil {
		t.Fatalf("query: %v", err)
	}
	if check != "do-spaces-public-acl" || resource != "droplet/test-*" || approver != "security@example.com" {
		t.Errorf("fields mismatch: check=%q resource=%q approver=%q", check, resource, approver)
	}
	if !strings.HasPrefix(expires, "2099-12-31") {
		t.Errorf("expires=%q expected to start with 2099-12-31", expires)
	}
}

// TestWaiversCreate_MissingFields → ?err=missing-fields, no row.
func TestWaiversCreate_MissingFields(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)
	form := url.Values{"check_id": []string{"only-check"}}
	req := httptest.NewRequest("POST", "/waivers", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	u.waiversCreate(rec, req)
	if !strings.Contains(rec.Header().Get("Location"), "err=missing-fields") {
		t.Errorf("Location=%q expected err=missing-fields", rec.Header().Get("Location"))
	}
	var n int
	_ = st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM waivers`).Scan(&n)
	if n != 0 {
		t.Errorf("expected 0 waivers after invalid create, got %d", n)
	}
}

// TestWaiversRevoke_SoftDelete: revoke sets revoked_at; row stays.
func TestWaiversRevoke_SoftDelete(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)

	// Seed a waiver directly.
	form := url.Values{
		"check_id":    []string{"x"},
		"resource_id": []string{"*"},
		"reason":      []string{"r"},
		"approver":    []string{"a"},
	}
	req := httptest.NewRequest("POST", "/waivers", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	u.waiversCreate(httptest.NewRecorder(), req)

	var id string
	if err := st.DB().QueryRowContext(ctx, `SELECT id FROM waivers LIMIT 1`).Scan(&id); err != nil {
		t.Fatalf("query id: %v", err)
	}

	req = httptest.NewRequest("POST", "/waivers/"+id+"/revoke", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	u.waiversRevoke(rec, req)
	if !strings.Contains(rec.Header().Get("Location"), "flash=revoked") {
		t.Errorf("Location=%q expected flash=revoked", rec.Header().Get("Location"))
	}

	var n int
	_ = st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM waivers WHERE revoked_at IS NOT NULL`).Scan(&n)
	if n != 1 {
		t.Errorf("revoked_at not set: count=%d want 1", n)
	}
}

// TestLoadWaivers_StatusSorting confirms active rows come before
// expired which come before revoked.
func TestLoadWaivers_StatusSorting(t *testing.T) {
	ctx := context.Background()
	u, _ := newUIForTests(t)

	mk := func(check string, expires time.Time, revoked bool) {
		form := url.Values{
			"check_id":    []string{check},
			"resource_id": []string{"*"},
			"reason":      []string{"r"},
			"approver":    []string{"a"},
			"expires_at":  []string{expires.Format("2006-01-02")},
		}
		req := httptest.NewRequest("POST", "/waivers", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		u.waiversCreate(httptest.NewRecorder(), req)
	}
	mk("active-check", time.Now().Add(30*24*time.Hour), false)
	mk("expired-check", time.Now().Add(-30*24*time.Hour), false)
	mk("future-check", time.Now().Add(7*24*time.Hour), false)

	got, err := u.loadWaivers(ctx)
	if err != nil {
		t.Fatalf("loadWaivers: %v", err)
	}
	if len(got) < 3 {
		t.Fatalf("expected 3 rows, got %d", len(got))
	}
	if got[0].Status != "active" || got[1].Status != "active" {
		t.Errorf("expected active rows first; got statuses [%s %s %s]",
			got[0].Status, got[1].Status, got[2].Status)
	}
	if got[2].Status != "expired" {
		t.Errorf("expected expired last; got %s", got[2].Status)
	}
}

// TestWaiversRoutesMounted: mount regression guard.
func TestWaiversRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountWaiversRoutes(r)
	req := httptest.NewRequest("GET", "/waivers", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Errorf("GET /waivers: 404 (route not mounted)")
	}
}
