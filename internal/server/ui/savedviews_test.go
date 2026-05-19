package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestSavedViewsCreate_HappyPath drives the POST handler with an
// explicit query_string + pinned=1 and confirms the row lands.
func TestSavedViewsCreate_HappyPath(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)

	form := url.Values{
		"name":         []string{"My critical AWS findings"},
		"query_string": []string{"severity=critical,high&provider=aws"},
		"pinned":       []string{"1"},
	}
	req := httptest.NewRequest("POST", "/findings/views", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	u.savedViewsCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d want 303", rec.Code)
	}

	var name, qs string
	var pinned int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT name, query_string, pinned FROM saved_views`).
		Scan(&name, &qs, &pinned); err != nil {
		t.Fatalf("query: %v", err)
	}
	if name != "My critical AWS findings" {
		t.Errorf("name=%q", name)
	}
	if !strings.Contains(qs, "severity=critical,high") {
		t.Errorf("query=%q", qs)
	}
	if pinned != 1 {
		t.Errorf("pinned=%d want 1", pinned)
	}
}

// TestSavedViewsCreate_FallsBackToReferer copies the query string
// from Referer when the form omits query_string.
func TestSavedViewsCreate_FallsBackToReferer(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)
	form := url.Values{"name": []string{"From referer"}}
	req := httptest.NewRequest("POST", "/findings/views", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "http://localhost:8080/findings?severity=critical&provider=aws")
	rec := httptest.NewRecorder()
	u.savedViewsCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rec.Code)
	}
	var qs string
	if err := st.DB().QueryRowContext(ctx, `SELECT query_string FROM saved_views`).Scan(&qs); err != nil {
		t.Fatalf("query: %v", err)
	}
	if qs != "severity=critical&provider=aws" {
		t.Errorf("query=%q", qs)
	}
}

// TestSavedViewsPin_FlipsValue toggles pinned on then off.
func TestSavedViewsPin_FlipsValue(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)

	// Seed via the create handler.
	form := url.Values{"name": []string{"x"}, "query_string": []string{""}, "pinned": []string{"1"}}
	req := httptest.NewRequest("POST", "/findings/views", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	u.savedViewsCreate(httptest.NewRecorder(), req)

	var id string
	if err := st.DB().QueryRowContext(ctx, `SELECT id FROM saved_views LIMIT 1`).Scan(&id); err != nil {
		t.Fatalf("query id: %v", err)
	}

	flip := func() {
		req := httptest.NewRequest("POST", "/findings/views/"+id+"/pin", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", id)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		u.savedViewsPin(httptest.NewRecorder(), req)
	}

	flip() // 1 → 0
	var pinned int
	_ = st.DB().QueryRowContext(ctx, `SELECT pinned FROM saved_views WHERE id = ?`, id).Scan(&pinned)
	if pinned != 0 {
		t.Errorf("after first flip: pinned=%d want 0", pinned)
	}
	flip() // 0 → 1
	_ = st.DB().QueryRowContext(ctx, `SELECT pinned FROM saved_views WHERE id = ?`, id).Scan(&pinned)
	if pinned != 1 {
		t.Errorf("after second flip: pinned=%d want 1", pinned)
	}
}

// TestPinnedSavedViews returns only pinned rows visible to the user.
func TestPinnedSavedViews(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)

	// Three views: 2 pinned (one team-wide), 1 unpinned.
	now := "2026-05-19T00:00:00Z"
	_, _ = st.DB().ExecContext(ctx,
		`INSERT INTO saved_views (id, owner_user_id, created_at, name, query_string, pinned)
		 VALUES (?, NULL, ?, ?, ?, ?)`,
		"v1", now, "Team view", "severity=critical", 1)
	_, _ = st.DB().ExecContext(ctx,
		`INSERT INTO saved_views (id, owner_user_id, created_at, name, query_string, pinned)
		 VALUES (?, NULL, ?, ?, ?, ?)`,
		"v2", now, "Unpinned", "", 0)

	got := u.pinnedSavedViews(ctx, "")
	if len(got) != 1 {
		t.Errorf("got %d pinned views, want 1 (broadcast-only)", len(got))
	}
	if got[0].Name != "Team view" {
		t.Errorf("got %q want Team view", got[0].Name)
	}
}

// TestSavedViewsRoutesMounted: mount regression guard.
func TestSavedViewsRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountSavedViewRoutes(r)
	req := httptest.NewRequest("GET", "/findings/views", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Errorf("GET /findings/views: 404 (route not mounted)")
	}
}
