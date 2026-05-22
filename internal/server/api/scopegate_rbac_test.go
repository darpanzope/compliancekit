package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	srvrbac "github.com/darpanzope/compliancekit/internal/server/rbac"
	"github.com/darpanzope/compliancekit/internal/server/store"
	pubrbac "github.com/darpanzope/compliancekit/pkg/compliancekit/rbac"
)

// newRBACAPI sets up an API + the v1.12 RBAC tables for the gate tests.
func newRBACAPI(t *testing.T) (*API, *store.Store) {
	t.Helper()
	st, err := store.OpenSQLite(context.Background(),
		"file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.MigrateUp(context.Background()); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	a := New(st, auth.NewUsers(st), auth.NewTokens(st), auth.NewSessions(st))
	return a, st
}

// seedUserWithRole inserts a user + grants roleID to them.
func seedUserWithRole(t *testing.T, st *store.Store, rb *srvrbac.Store, email, roleID string) string {
	t.Helper()
	id := "u-" + email
	if _, err := st.DB().ExecContext(context.Background(),
		`INSERT INTO users (id, email, display_name, is_admin, created_at) VALUES (?, ?, ?, 0, ?)`,
		id, email, email, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if roleID != "" {
		if err := rb.AssignRole(context.Background(), id, roleID, ""); err != nil {
			t.Fatalf("assign role: %v", err)
		}
	}
	return id
}

// TestScopeGate_SessionRoleDerivedRead: a viewer-role session sees a
// :read endpoint (200) but not :write (403).
func TestScopeGate_SessionRoleDerivedRead(t *testing.T) {
	a, _ := newRBACAPI(t)
	uid := seedUserWithRole(t, a.store, a.rbac, "viewer@example.com", "role-viewer")

	called := false
	handler := a.scopeGate(auth.ScopeScansRead, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/api/v1/scans", nil)
	req = req.WithContext(auth.InjectTestSession(req.Context(), uid))
	rec := httptest.NewRecorder()
	handler(rec, req)
	if !called {
		t.Errorf("viewer should reach :read handler, got status %d", rec.Code)
	}

	// Write attempt — should be 403.
	called = false
	wHandler := a.scopeGate(auth.ScopeScansWrite, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req2 := httptest.NewRequest("POST", "/api/v1/scans", nil)
	req2 = req2.WithContext(auth.InjectTestSession(req2.Context(), uid))
	rec2 := httptest.NewRecorder()
	wHandler(rec2, req2)
	if called {
		t.Error("viewer should NOT reach :write handler")
	}
	if rec2.Code != http.StatusForbidden {
		t.Errorf("write attempt: status=%d want 403", rec2.Code)
	}
}

// TestScopeGate_SessionRoleDerivedAdmin: an admin-role session passes
// :write.
func TestScopeGate_SessionRoleDerivedAdmin(t *testing.T) {
	a, _ := newRBACAPI(t)
	uid := seedUserWithRole(t, a.store, a.rbac, "admin@example.com", "role-admin")

	called := false
	handler := a.scopeGate(auth.ScopeScansWrite, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest("POST", "/api/v1/scans", nil)
	req = req.WithContext(auth.InjectTestSession(req.Context(), uid))
	rec := httptest.NewRecorder()
	handler(rec, req)
	if !called {
		t.Errorf("admin-role session should reach :write handler, got status %d", rec.Code)
	}
}

// TestScopeGate_LegacyBootstrap: a user with NO role assignments
// falls back to the v1.5.1 behavior — IsAdmin = full, non-admin =
// read-only.
func TestScopeGate_LegacyBootstrap(t *testing.T) {
	a, _ := newRBACAPI(t)
	uid := seedUserWithRole(t, a.store, a.rbac, "legacy@example.com", "") // no roles

	called := false
	handler := a.scopeGate(auth.ScopeScansRead, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest("GET", "/api/v1/scans", nil)
	req = req.WithContext(auth.InjectTestSession(req.Context(), uid))
	rec := httptest.NewRecorder()
	handler(rec, req)
	if !called {
		t.Errorf("legacy non-admin session should hit :read, got %d", rec.Code)
	}

	// Write should be 403 (non-admin, no role).
	called = false
	wHandler := a.scopeGate(auth.ScopeScansWrite, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req2 := httptest.NewRequest("POST", "/api/v1/scans", nil)
	req2 = req2.WithContext(auth.InjectTestSession(req2.Context(), uid))
	rec2 := httptest.NewRecorder()
	wHandler(rec2, req2)
	if called {
		t.Error("legacy non-admin session should NOT reach :write")
	}
	if rec2.Code != http.StatusForbidden {
		t.Errorf("write attempt: status=%d want 403", rec2.Code)
	}
}

// TestSetExhaustivePermissions: when the user holds the admin role,
// every defined Scope passes the gate.
func TestSetExhaustivePermissions(t *testing.T) {
	a, _ := newRBACAPI(t)
	uid := seedUserWithRole(t, a.store, a.rbac, "all@example.com", "role-admin")
	set, err := a.rbac.PermissionSetForUser(context.Background(), uid)
	if err != nil {
		t.Fatalf("PermissionSetForUser: %v", err)
	}
	for _, sc := range []auth.Scope{
		auth.ScopeScansRead, auth.ScopeScansWrite,
		auth.ScopeFindingsRead,
		auth.ScopeWaiversRead, auth.ScopeWaiversWrite,
		auth.ScopeSettingsRead, auth.ScopeSettingsWrite,
	} {
		res, act, ok := sc.ScopeRBAC()
		if !ok {
			t.Errorf("%s should map to a tuple", sc)
		}
		if !set.Has(pubrbac.Resource(res), pubrbac.Action(act)) {
			t.Errorf("admin set lacks %s:%s", res, act)
		}
	}
}
