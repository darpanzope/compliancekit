package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTokens_IssueListRevoke(t *testing.T) {
	ctx := context.Background()
	st := openMigratedStore(t)
	t.Cleanup(func() { _ = st.Close() })
	users := NewUsers(st)
	toks := NewTokens(st)

	u, err := users.Create(ctx, "ops@example.com", "Ops", "correct-horse-battery-staple", true)
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}

	scopes := []Scope{ScopeScansRead, ScopeFindingsRead, ScopeSettingsRead}
	result, err := toks.Issue(ctx, u.ID, "ci-readonly", scopes, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !strings.HasPrefix(result.Plaintext, "ck_") || len(result.Plaintext) != 35 { // "ck_" + 32 hex
		t.Errorf("plaintext shape unexpected: %q (len=%d)", result.Plaintext, len(result.Plaintext))
	}
	if result.Token.Prefix != result.Plaintext[:11] {
		t.Errorf("Prefix = %q, want first 11 chars of plaintext (%q)", result.Token.Prefix, result.Plaintext[:11])
	}

	// Verify happy path.
	verified, err := toks.Verify(ctx, result.Plaintext)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.UserID != u.ID {
		t.Errorf("verified.UserID = %q, want %q", verified.UserID, u.ID)
	}
	if len(verified.Scopes) != len(scopes) {
		t.Errorf("scopes count = %d, want %d", len(verified.Scopes), len(scopes))
	}

	// List.
	list, err := toks.List(ctx, u.ID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List length = %d, want 1", len(list))
	}
	if list[0].ID != result.Token.ID {
		t.Errorf("List returned wrong token ID")
	}

	// Revoke + verify the revoked path.
	if err := toks.Revoke(ctx, result.Token.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err = toks.Verify(ctx, result.Plaintext)
	if !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("Verify on revoked token = %v, want ErrTokenRevoked", err)
	}
}

func TestTokens_VerifyExpired(t *testing.T) {
	ctx := context.Background()
	st := openMigratedStore(t)
	t.Cleanup(func() { _ = st.Close() })
	users := NewUsers(st)
	toks := NewTokens(st)
	u, _ := users.Create(ctx, "ops@example.com", "Ops", "correct-horse-battery-staple", false)

	past := time.Now().UTC().Add(-1 * time.Hour)
	result, err := toks.Issue(ctx, u.ID, "stale", []Scope{ScopeScansRead}, &past)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, err = toks.Verify(ctx, result.Plaintext)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("Verify on expired token = %v, want ErrTokenExpired", err)
	}
}

func TestTokens_VerifyUnknown(t *testing.T) {
	ctx := context.Background()
	st := openMigratedStore(t)
	t.Cleanup(func() { _ = st.Close() })
	toks := NewTokens(st)

	_, err := toks.Verify(ctx, "ck_deadbeefdeadbeefdeadbeefdeadbeef")
	if !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("Verify on unknown token = %v, want ErrTokenNotFound", err)
	}
	_, err = toks.Verify(ctx, "wrong-prefix-token")
	if !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("Verify on wrong-prefix token = %v, want ErrTokenNotFound", err)
	}
}

func TestHasScope(t *testing.T) {
	tok := &Token{Scopes: []Scope{ScopeScansRead, "waivers:*"}}

	cases := []struct {
		name string
		s    Scope
		want bool
	}{
		{"exact match", ScopeScansRead, true},
		{"no match", ScopeScansWrite, false},
		{"wildcard within resource", ScopeWaiversWrite, true}, // covered by waivers:*
		{"wildcard within resource 2", ScopeWaiversRead, true},
		{"wildcard does not cross resources", ScopeSettingsWrite, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tok.HasScope(tc.s); got != tc.want {
				t.Errorf("HasScope(%s) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}

	t.Run("admin grants everything", func(t *testing.T) {
		admin := &Token{Scopes: []Scope{ScopeAdmin}}
		for _, s := range []Scope{ScopeScansRead, ScopeScansWrite, ScopeWaiversWrite, ScopeSettingsWrite, "made:up"} {
			if !admin.HasScope(s) {
				t.Errorf("admin HasScope(%s) = false, want true", s)
			}
		}
	})
}

func TestRequireToken_Middleware(t *testing.T) {
	ctx := context.Background()
	st := openMigratedStore(t)
	t.Cleanup(func() { _ = st.Close() })
	users := NewUsers(st)
	toks := NewTokens(st)
	u, _ := users.Create(ctx, "ops@example.com", "Ops", "correct-horse-battery-staple", false)
	r, _ := toks.Issue(ctx, u.ID, "test", []Scope{ScopeScansRead}, nil)

	called := false
	handler := toks.RequireToken(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		called = true
		tok := TokenFromContext(req.Context())
		if tok == nil || tok.UserID != u.ID {
			t.Errorf("expected token in context with userID %s, got %+v", u.ID, tok)
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("missing header → 401", func(t *testing.T) {
		called = false
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if called {
			t.Error("handler should not be called without header")
		}
		if w.Result().StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", w.Result().StatusCode)
		}
	})
	t.Run("malformed header → 401", func(t *testing.T) {
		called = false
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "NotBearer xxx")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if called {
			t.Error("handler should not be called with malformed header")
		}
	})
	t.Run("good token → 200", func(t *testing.T) {
		called = false
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+r.Plaintext)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if !called {
			t.Errorf("handler not called; status=%d body=%q", w.Result().StatusCode, w.Body.String())
		}
	})
}

func TestRequireScope_Middleware(t *testing.T) {
	ctx := context.Background()
	st := openMigratedStore(t)
	t.Cleanup(func() { _ = st.Close() })
	users := NewUsers(st)
	toks := NewTokens(st)
	u, _ := users.Create(ctx, "ops@example.com", "Ops", "correct-horse-battery-staple", false)
	readonly, _ := toks.Issue(ctx, u.ID, "ro", []Scope{ScopeScansRead}, nil)
	writable, _ := toks.Issue(ctx, u.ID, "rw", []Scope{ScopeScansRead, ScopeScansWrite}, nil)

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	protected := toks.RequireToken(RequireScope(ScopeScansWrite, inner))

	t.Run("read-only token gets 403 on write route", func(t *testing.T) {
		called = false
		req := httptest.NewRequest(http.MethodPost, "/scans", nil)
		req.Header.Set("Authorization", "Bearer "+readonly.Plaintext)
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, req)
		if called {
			t.Error("handler should be denied for missing scope")
		}
		if w.Result().StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", w.Result().StatusCode)
		}
	})
	t.Run("read+write token passes", func(t *testing.T) {
		called = false
		req := httptest.NewRequest(http.MethodPost, "/scans", nil)
		req.Header.Set("Authorization", "Bearer "+writable.Plaintext)
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, req)
		if !called {
			t.Errorf("expected handler to be called; status=%d body=%q",
				w.Result().StatusCode, w.Body.String())
		}
	})
}
