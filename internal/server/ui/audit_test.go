package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestAuditLog_RoundTrip writes a row + reads it back via the
// audit_log table.
func TestAuditLog_RoundTrip(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)

	u.AuditLog(ctx, "scan.trigger", "scan", "scan-123",
		map[string]any{"provider": "digitalocean"})

	var action, entity string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT action, entity_id FROM audit_log LIMIT 1`).
		Scan(&action, &entity); err != nil {
		t.Fatalf("query: %v", err)
	}
	if action != "scan.trigger" || entity != "scan-123" {
		t.Errorf("row mismatch: action=%q entity=%q", action, entity)
	}
}

// TestNotifyInbox_BroadcastAndPerUser confirms broadcast (user_id
// NULL) + per-user shapes both land. Uses a real users row to
// satisfy the inbox→users foreign key.
func TestNotifyInbox_BroadcastAndPerUser(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)
	usr, err := u.users.Create(ctx, "alice@example.com", "Alice", "p@ssw0rd-strong", true)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	u.NotifyInbox(ctx, "", "info", "Broadcast", "Body", "/scans")
	u.NotifyInbox(ctx, usr.ID, "warning", "Per-user", "Body", "")

	var broadcastCount, perUserCount int
	_ = st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM inbox WHERE user_id IS NULL`).Scan(&broadcastCount)
	_ = st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM inbox WHERE user_id = ?`, usr.ID).Scan(&perUserCount)
	if broadcastCount != 1 {
		t.Errorf("broadcast=%d want 1", broadcastCount)
	}
	if perUserCount != 1 {
		t.Errorf("per-user=%d want 1", perUserCount)
	}
}

// TestInboxMarkRead sets read_at on the picked id.
func TestInboxMarkRead(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)
	u.NotifyInbox(ctx, "", "info", "X", "Y", "")

	var id string
	if err := st.DB().QueryRowContext(ctx, `SELECT id FROM inbox LIMIT 1`).Scan(&id); err != nil {
		t.Fatalf("query: %v", err)
	}

	req := httptest.NewRequest("POST", "/inbox/"+id+"/read", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	u.inboxMarkRead(rec, req)

	var readAt *string
	_ = st.DB().QueryRowContext(ctx, `SELECT read_at FROM inbox WHERE id = ?`, id).Scan(&readAt)
	if readAt == nil || *readAt == "" {
		t.Errorf("read_at empty after mark-read")
	}
}

// TestCountUnreadInbox returns broadcast + per-user count.
func TestCountUnreadInbox(t *testing.T) {
	ctx := context.Background()
	u, _ := newUIForTests(t)
	u1, err := u.users.Create(ctx, "u1@x.com", "U1", "p@ssw0rd-strong", true)
	if err != nil {
		t.Fatalf("create u1: %v", err)
	}
	u2, err := u.users.Create(ctx, "u2@x.com", "U2", "p@ssw0rd-strong", true)
	if err != nil {
		t.Fatalf("create u2: %v", err)
	}
	u.NotifyInbox(ctx, "", "info", "B1", "", "")
	u.NotifyInbox(ctx, "", "info", "B2", "", "")
	u.NotifyInbox(ctx, u1.ID, "info", "P1", "", "")

	if got := u.CountUnreadInbox(ctx, u1.ID); got != 3 {
		t.Errorf("CountUnreadInbox(u1)=%d want 3 (broadcasts + own)", got)
	}
	if got := u.CountUnreadInbox(ctx, u2.ID); got != 2 {
		t.Errorf("CountUnreadInbox(u2)=%d want 2 (broadcasts only)", got)
	}
}

// TestAuditRoutesMounted: mount regression guard.
func TestAuditRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountAuditRoutes(r)

	for _, path := range []string{"/audit", "/inbox"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("GET %s: 404 (route not mounted)", path)
		}
	}
}
