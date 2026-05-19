package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/frameworks"
)

// TestFrameworksList_LoadsCatalog confirms the catalog handler
// returns at least one framework (the embedded YAML files).
func TestFrameworksList_LoadsCatalog(t *testing.T) {
	u, _ := newUIForTests(t)
	req := httptest.NewRequest("GET", "/settings/frameworks", nil)
	rec := httptest.NewRecorder()
	u.frameworksList(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Frameworks") {
		t.Errorf("body missing header")
	}
}

// TestFrameworkControlUpdate_ExcludeRequiresJustification confirms
// the "you must explain why" guard fires on empty input.
func TestFrameworkControlUpdate_ExcludeRequiresJustification(t *testing.T) {
	u, _ := newUIForTests(t)
	cat, _ := frameworks.All()
	var fwID, controlID string
	for id, fw := range cat {
		if len(fw.Controls) == 0 {
			continue
		}
		fwID = id
		for cID := range fw.Controls {
			controlID = cID
			break
		}
		break
	}
	if fwID == "" {
		t.Skip("no framework with controls loaded")
	}

	form := url.Values{"action": []string{"exclude"}, "justification": []string{"  "}}
	req := httptest.NewRequest("POST",
		"/settings/frameworks/"+fwID+"/control/"+controlID,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", fwID)
	rctx.URLParams.Add("control", controlID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	u.frameworkControlUpdate(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d want 303", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "err=need-justification") {
		t.Errorf("Location=%q expected err=need-justification", rec.Header().Get("Location"))
	}
}

// TestFrameworkControlUpdate_RoundTrip walks exclude → restore →
// confirms the row vanishes after restore (back to shipped default).
func TestFrameworkControlUpdate_RoundTrip(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)
	cat, _ := frameworks.All()
	var fwID, controlID string
	for id, fw := range cat {
		if len(fw.Controls) == 0 {
			continue
		}
		fwID = id
		for cID := range fw.Controls {
			controlID = cID
			break
		}
		break
	}
	if fwID == "" {
		t.Skip("no framework with controls loaded")
	}

	post := func(action, just string) *httptest.ResponseRecorder {
		form := url.Values{"action": []string{action}, "justification": []string{just}}
		req := httptest.NewRequest("POST",
			"/settings/frameworks/"+fwID+"/control/"+controlID,
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", fwID)
		rctx.URLParams.Add("control", controlID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()
		u.frameworkControlUpdate(rec, req)
		return rec
	}

	// Exclude with justification → row exists with included=0.
	rec := post("exclude", "Not applicable; cardholder data is out of scope.")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("exclude: status %d", rec.Code)
	}
	var inc int
	var just string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT included, justification FROM framework_tailoring WHERE framework_id = ? AND control_id = ?`,
		fwID, controlID).Scan(&inc, &just); err != nil {
		t.Fatalf("query after exclude: %v", err)
	}
	if inc != 0 || just == "" {
		t.Errorf("excluded row: included=%d, justification=%q", inc, just)
	}

	// Restore → row deleted.
	rec = post("include", "")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("restore: status %d", rec.Code)
	}
	var n int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM framework_tailoring WHERE framework_id = ? AND control_id = ?`,
		fwID, controlID).Scan(&n); err != nil {
		t.Fatalf("query after restore: %v", err)
	}
	if n != 0 {
		t.Errorf("post-restore: %d rows remain, want 0 (back to shipped default)", n)
	}
}

// TestFrameworksRoutesMounted iterates Phase 5 routes — mount
// regression guard.
func TestFrameworksRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountFrameworksRoutes(r)

	for _, path := range []string{"/settings/frameworks"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("GET %s: 404 (route not mounted)", path)
		}
	}
}
