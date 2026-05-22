package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/store"
)

func newTestServer(t *testing.T) (*Server, *chi.Mux) {
	t.Helper()
	st, err := store.OpenSQLite(context.Background(), "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.MigrateUp(context.Background()); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	srv := New(st, auth.NewUsers(st), auth.NewSessions(st), "test-bearer")
	r := chi.NewRouter()
	srv.Mount(r)
	return srv, r
}

func TestSCIM_BearerRequired(t *testing.T) {
	_, r := newTestServer(t)
	req := httptest.NewRequest("GET", "/scim/v2/Users", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status=%d want 401 (missing bearer)", rec.Code)
	}
}

func TestSCIM_CreateAndGetUser(t *testing.T) {
	_, r := newTestServer(t)

	body, _ := json.Marshal(map[string]any{
		"schemas":     []string{SchemaUser},
		"userName":    "alice@example.com",
		"displayName": "Alice",
		"active":      true,
	})
	req := httptest.NewRequest("POST", "/scim/v2/Users", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-bearer")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != ContentType {
		t.Errorf("Content-Type=%q want %q", ct, ContentType)
	}
	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created: %v", err)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("created user missing id")
	}

	getReq := httptest.NewRequest("GET", "/scim/v2/Users/"+id, nil)
	getReq.Header.Set("Authorization", "Bearer test-bearer")
	getRec := httptest.NewRecorder()
	r.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Errorf("GET: status=%d body=%s", getRec.Code, getRec.Body.String())
	}
}

func TestSCIM_ServiceProviderConfig(t *testing.T) {
	_, r := newTestServer(t)
	req := httptest.NewRequest("GET", "/scim/v2/ServiceProviderConfig", nil)
	req.Header.Set("Authorization", "Bearer test-bearer")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d want 200", rec.Code)
	}
}

func TestSCIM_GroupListSeeded(t *testing.T) {
	_, r := newTestServer(t)
	req := httptest.NewRequest("GET", "/scim/v2/Groups", nil)
	req.Header.Set("Authorization", "Bearer test-bearer")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	resources, _ := resp["Resources"].([]any)
	if len(resources) < 4 {
		t.Errorf("expected at least 4 groups (built-in roles), got %d", len(resources))
	}
}
