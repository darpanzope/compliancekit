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

// TestScanNewSubmit_NoProviders → /scans/new?err=no-providers.
func TestScanNewSubmit_NoProviders(t *testing.T) {
	u, _ := newUIForTests(t)
	form := url.Values{}
	req := httptest.NewRequest("POST", "/scans/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	u.scanNewSubmit(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d want 303", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "err=no-providers") {
		t.Errorf("Location=%q expected err=no-providers", rec.Header().Get("Location"))
	}
}

// TestScanNewSubmit_NoEnabledProviders fires when the picked id isn't
// in the enabled set (e.g. disabled provider posted via the form).
func TestScanNewSubmit_NoEnabledProviders(t *testing.T) {
	u, _ := newUIForTests(t)
	form := url.Values{"provider": []string{"digitalocean"}}
	req := httptest.NewRequest("POST", "/scans/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	u.scanNewSubmit(rec, req)
	if !strings.Contains(rec.Header().Get("Location"), "err=none-enabled") {
		t.Errorf("Location=%q expected err=none-enabled", rec.Header().Get("Location"))
	}
}

// TestScanNewSubmit_HappyPath: enabled provider → queued scan row +
// redirect to /scans/{id}.
func TestScanNewSubmit_HappyPath(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)
	if err := u.upsertProvider(ctx, "digitalocean", "tok", nil); err != nil {
		t.Fatalf("upsertProvider: %v", err)
	}

	form := url.Values{"provider": []string{"digitalocean"}}
	req := httptest.NewRequest("POST", "/scans/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	u.scanNewSubmit(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d want 303", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/scans/") {
		t.Errorf("Location=%q expected /scans/{id}", loc)
	}

	var status string
	if err := st.DB().QueryRowContext(ctx, `SELECT status FROM scans LIMIT 1`).Scan(&status); err != nil {
		t.Fatalf("query: %v", err)
	}
	if status != "queued" {
		t.Errorf("status=%q want queued", status)
	}
}

// TestScanStream_EmitsInitialStatus confirms the SSE stream emits at
// least one event before the test cancels the context.
func TestScanStream_EmitsInitialStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u, _ := newUIForTests(t)

	scanID, err := u.enqueueWizardScanMulti(ctx, []string{"digitalocean"})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	req := httptest.NewRequest("GET", "/scans/"+scanID+"/stream", nil).WithContext(ctx)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", scanID)
	req = req.WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	// Cancel after ~250ms so the handler exits via r.Context().Done().
	go func() {
		time.Sleep(250 * time.Millisecond)
		cancel()
	}()
	u.scanStream(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "event: status") {
		t.Errorf("stream missing initial status event:\n%s", body)
	}
	if !strings.Contains(body, scanID) {
		t.Errorf("stream missing scan id %s", scanID)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/event-stream") {
		t.Errorf("Content-Type=%q expected text/event-stream", rec.Header().Get("Content-Type"))
	}
}

// TestScanNewRoutesMounted: mount regression guard.
func TestScanNewRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountScanNewRoutes(r)

	req := httptest.NewRequest("GET", "/scans/new", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Errorf("GET /scans/new: 404 (route not mounted)")
	}
}
