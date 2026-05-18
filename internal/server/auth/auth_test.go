package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// TestHashAndVerifyPassword covers the round-trip + the
// minimum-length gate + the constant-time mismatch path.
func TestHashAndVerifyPassword(t *testing.T) {
	t.Run("round-trip", func(t *testing.T) {
		h, err := HashPassword("correct-horse-battery-staple")
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		if err := VerifyPassword(h, "correct-horse-battery-staple"); err != nil {
			t.Errorf("verify expected nil, got %v", err)
		}
	})
	t.Run("min length", func(t *testing.T) {
		_, err := HashPassword("short")
		if !errors.Is(err, ErrPasswordTooShort) {
			t.Errorf("expected ErrPasswordTooShort, got %v", err)
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		h, _ := HashPassword("correct-horse-battery-staple")
		if err := VerifyPassword(h, "Tr0ub4dor&3-Wrong"); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got %v", err)
		}
	})
	t.Run("empty hash is always invalid", func(t *testing.T) {
		if err := VerifyPassword("", "anything"); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials for empty hash, got %v", err)
		}
	})
}

// TestSessions_Lifecycle creates a user, opens a session, loads it
// back, lets it expire (via direct DB poke), and confirms Load
// reports ErrSessionExpired.
func TestSessions_Lifecycle(t *testing.T) {
	ctx := context.Background()
	st := openMigratedStore(t)
	t.Cleanup(func() { _ = st.Close() })

	users := NewUsers(st)
	sessions := NewSessions(st)

	u, err := users.Create(ctx, "ops@example.com", "Ops Person", "correct-horse-battery-staple", true)
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}
	sess, err := sessions.Create(ctx, u.ID, "test-ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	if len(sess.ID) != 64 {
		t.Errorf("session.ID length = %d, want 64 hex chars", len(sess.ID))
	}
	if len(sess.CSRFToken) != 64 {
		t.Errorf("session.CSRFToken length = %d, want 64 hex chars", len(sess.CSRFToken))
	}

	loaded, err := sessions.Load(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.UserID != u.ID {
		t.Errorf("loaded UserID = %s, want %s", loaded.UserID, u.ID)
	}

	// Forge an expired row. Sqlite-only test — placeholder is "?".
	_, err = st.DB().ExecContext(ctx,
		"UPDATE sessions SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?",
		sess.ID)
	if err != nil {
		t.Fatalf("force expire: %v", err)
	}
	_, err = sessions.Load(ctx, sess.ID)
	if !errors.Is(err, ErrSessionExpired) {
		t.Errorf("Load on expired session = %v, want ErrSessionExpired", err)
	}

	// Re-create + destroy.
	sess2, err := sessions.Create(ctx, u.ID, "ua2", "127.0.0.1")
	if err != nil {
		t.Fatalf("Create second session: %v", err)
	}
	if err := sessions.Destroy(ctx, sess2.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := sessions.Load(ctx, sess2.ID); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Load after Destroy = %v, want ErrSessionNotFound", err)
	}
}

// TestLoginHandler_HappyPath covers the JSON login → cookies set →
// /api/auth/me round-trip, plus the wrong-password 401 path.
func TestLoginHandler_HappyPath(t *testing.T) {
	ctx := context.Background()
	st := openMigratedStore(t)
	t.Cleanup(func() { _ = st.Close() })
	users := NewUsers(st)
	sessions := NewSessions(st)
	if _, err := users.Create(ctx, "ops@example.com", "Ops", "correct-horse-battery-staple", false); err != nil {
		t.Fatalf("Create user: %v", err)
	}

	loginH := LoginHandler(users, sessions)
	meH := MeHandler(users)

	// Happy path
	body := strings.NewReader(`{"email":"ops@example.com","password":"correct-horse-battery-staple"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	loginH(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200 (body: %s)", resp.StatusCode, w.Body.String())
	}
	var lr LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if lr.Email != "ops@example.com" {
		t.Errorf("response Email = %q, want ops@example.com", lr.Email)
	}
	var sessionCookie, csrfCookie *http.Cookie
	for _, c := range resp.Cookies() {
		switch c.Name {
		case SessionCookieName:
			sessionCookie = c
		case CSRFCookieName:
			csrfCookie = c
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatalf("missing %s cookie on login response", SessionCookieName)
	}
	if !sessionCookie.HttpOnly {
		t.Error("session cookie should be HttpOnly")
	}
	if !sessionCookie.Secure {
		t.Error("session cookie should be Secure (__Host- prefix mandates)")
	}
	if csrfCookie == nil || csrfCookie.Value == "" {
		t.Fatalf("missing %s cookie on login response", CSRFCookieName)
	}
	if csrfCookie.HttpOnly {
		t.Error("CSRF cookie must NOT be HttpOnly (client JS reads it)")
	}

	// /api/auth/me requires the session — wire via the middleware.
	req2 := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req2.AddCookie(sessionCookie)
	w2 := httptest.NewRecorder()
	sessions.RequireAuth(meH).ServeHTTP(w2, req2)
	if w2.Result().StatusCode != http.StatusOK {
		t.Errorf("/me status = %d, want 200 (body: %s)", w2.Result().StatusCode, w2.Body.String())
	}

	// Wrong password
	body = strings.NewReader(`{"email":"ops@example.com","password":"NOPE-not-it-12345"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	loginH(w, req)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong-password status = %d, want 401", w.Result().StatusCode)
	}
}

// TestRequireCSRF asserts the double-submit cookie check rejects
// POSTs without the header / with a wrong header value, and accepts
// POSTs with the right value.
func TestRequireCSRF(t *testing.T) {
	ctx := context.Background()
	st := openMigratedStore(t)
	t.Cleanup(func() { _ = st.Close() })
	users := NewUsers(st)
	sessions := NewSessions(st)
	u, _ := users.Create(ctx, "ops@example.com", "Ops", "correct-horse-battery-staple", false)
	sess, _ := sessions.Create(ctx, u.ID, "ua", "127.0.0.1")

	handlerCalled := false
	protected := sessions.RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("GET is exempt", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(withSession(req.Context(), sess))
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, req)
		if !handlerCalled {
			t.Error("expected GET to pass through")
		}
	})
	t.Run("POST without header is rejected", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req = req.WithContext(withSession(req.Context(), sess))
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, req)
		if handlerCalled {
			t.Error("expected POST without CSRF header to be rejected")
		}
		if w.Result().StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", w.Result().StatusCode)
		}
	})
	t.Run("POST with wrong header is rejected", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(CSRFHeaderName, "wrongwrongwrongwrongwrongwrongwrongwrongwrongwrongwrongwrongwrong")
		req = req.WithContext(withSession(req.Context(), sess))
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, req)
		if handlerCalled {
			t.Error("expected POST with wrong CSRF to be rejected")
		}
	})
	t.Run("POST with correct header passes", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(CSRFHeaderName, sess.CSRFToken)
		req = req.WithContext(withSession(req.Context(), sess))
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, req)
		if !handlerCalled {
			t.Errorf("expected POST with correct CSRF to pass, got status %d body %q",
				w.Result().StatusCode, w.Body.String())
		}
	})
}

// TestUsers_EmailUniqueness covers the duplicate-email path.
func TestUsers_EmailUniqueness(t *testing.T) {
	ctx := context.Background()
	st := openMigratedStore(t)
	t.Cleanup(func() { _ = st.Close() })
	users := NewUsers(st)

	if _, err := users.Create(ctx, "ops@example.com", "Ops", "correct-horse-battery-staple", false); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := users.Create(ctx, "ops@example.com", "Ops Dup", "correct-horse-battery-staple", false)
	if !errors.Is(err, ErrEmailAlreadyTaken) {
		t.Errorf("expected ErrEmailAlreadyTaken, got %v", err)
	}
	// Case + whitespace folding
	_, err = users.Create(ctx, "  OPS@EXAMPLE.COM  ", "Ops Mixed", "correct-horse-battery-staple", false)
	if !errors.Is(err, ErrEmailAlreadyTaken) {
		t.Errorf("expected ErrEmailAlreadyTaken on case+ws variant, got %v", err)
	}
}

// openMigratedStore returns an in-memory SQLite Store with the v1.3
// schema applied. Each test gets its own DB.
func openMigratedStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.OpenSQLite(context.Background(),
		"file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	if err := st.MigrateUp(context.Background()); err != nil {
		_ = st.Close()
		t.Fatalf("MigrateUp: %v", err)
	}
	return st
}
