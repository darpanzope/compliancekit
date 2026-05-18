package auth

import (
	"context"
	"errors"
	"testing"
)

// TestOIDC_FindOrCreateUser exercises the three branches of the
// upstream-identity → users-row resolver without needing a real
// upstream OIDC provider. The OAuth2 / id_token / GitHub HTTP paths
// are covered by integration tests against real providers + the
// upstream SDKs.
func TestOIDC_FindOrCreateUser(t *testing.T) {
	ctx := context.Background()
	st := openMigratedStore(t)
	t.Cleanup(func() { _ = st.Close() })

	users := NewUsers(st)
	sessions := NewSessions(st)

	// Construct an OIDC handle without real provider discovery — we
	// only use the find-or-create path, which doesn't touch the
	// oauth2 / verifier fields.
	o := &OIDC{
		cfg:      OIDCConfig{ID: "test", Provider: OIDCProviderGoogle},
		users:    users,
		sessions: sessions,
		store:    st,
	}

	t.Run("branch 1: insert fresh OIDC-only user", func(t *testing.T) {
		ident := oidcIdentity{
			Provider: OIDCProviderGoogle,
			Subject:  "google-sub-1",
			Email:    "alice@example.com",
			Name:     "Alice",
		}
		u, err := o.findOrCreateUser(ctx, ident)
		if err != nil {
			t.Fatalf("findOrCreateUser: %v", err)
		}
		if u.OIDCProvider != "google" {
			t.Errorf("OIDCProvider = %q, want google", u.OIDCProvider)
		}
		if u.OIDCSubject != "google-sub-1" {
			t.Errorf("OIDCSubject = %q, want google-sub-1", u.OIDCSubject)
		}
		if u.PasswordHash != "" {
			t.Errorf("PasswordHash should be empty for OIDC-only user, got %q", u.PasswordHash)
		}
	})

	t.Run("branch 2: looked up by (provider, subject) on re-login", func(t *testing.T) {
		ident := oidcIdentity{
			Provider: OIDCProviderGoogle,
			Subject:  "google-sub-1",
			Email:    "alice-changed@example.com", // changed email — should still hit by sub
		}
		u, err := o.findOrCreateUser(ctx, ident)
		if err != nil {
			t.Fatalf("findOrCreateUser: %v", err)
		}
		// Email on the existing row stays as the original; we don't
		// update on re-login (operator can change it via the v1.4
		// settings page).
		if u.Email != "alice@example.com" {
			t.Errorf("Email = %q, want alice@example.com (existing row preserved)", u.Email)
		}
	})

	t.Run("branch 3: link OIDC onto pre-existing local-auth user", func(t *testing.T) {
		// Operator pre-creates a local-auth account.
		if _, err := users.Create(ctx, "bob@example.com", "Bob", "correct-horse-battery-staple", false); err != nil {
			t.Fatalf("seed local user: %v", err)
		}
		ident := oidcIdentity{
			Provider: OIDCProviderGoogle,
			Subject:  "google-sub-2",
			Email:    "bob@example.com",
		}
		u, err := o.findOrCreateUser(ctx, ident)
		if err != nil {
			t.Fatalf("findOrCreateUser: %v", err)
		}
		if u.OIDCProvider != "google" || u.OIDCSubject != "google-sub-2" {
			t.Errorf("link path: OIDCProvider=%q OIDCSubject=%q", u.OIDCProvider, u.OIDCSubject)
		}
		if u.PasswordHash == "" {
			t.Error("link path: existing PasswordHash should be preserved (account remains usable via local auth too)")
		}
	})

	t.Run("provider isolation: different provider, same subject = different user", func(t *testing.T) {
		// Same subject string as branch 1 but different provider —
		// should NOT collide.
		ident := oidcIdentity{
			Provider: OIDCProviderOkta,
			Subject:  "google-sub-1",
			Email:    "carol@example.com",
		}
		u, err := o.findOrCreateUser(ctx, ident)
		if err != nil {
			t.Fatalf("findOrCreateUser: %v", err)
		}
		if u.OIDCProvider != "okta" {
			t.Errorf("OIDCProvider = %q, want okta", u.OIDCProvider)
		}
		if u.Email != "carol@example.com" {
			t.Errorf("Email = %q, want carol@example.com (separate user)", u.Email)
		}
	})
}

// TestNewOIDC_ValidatesRequiredFields makes sure operator
// misconfiguration is caught loudly at boot time, not on the first
// callback.
func TestNewOIDC_ValidatesRequiredFields(t *testing.T) {
	users := NewUsers(nil)
	sessions := NewSessions(nil)

	cases := []struct {
		name string
		cfg  OIDCConfig
	}{
		{"missing ID", OIDCConfig{Provider: OIDCProviderGoogle, ClientID: "c", ClientSecret: "s", RedirectURL: "https://x"}},
		{"missing ClientID", OIDCConfig{ID: "x", Provider: OIDCProviderGoogle, ClientSecret: "s", RedirectURL: "https://x"}},
		{"missing ClientSecret", OIDCConfig{ID: "x", Provider: OIDCProviderGoogle, ClientID: "c", RedirectURL: "https://x"}},
		{"missing RedirectURL", OIDCConfig{ID: "x", Provider: OIDCProviderGoogle, ClientID: "c", ClientSecret: "s"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewOIDC(context.Background(), tc.cfg, users, sessions, nil)
			if err == nil {
				t.Error("expected NewOIDC to reject the malformed config, got nil")
			}
		})
	}

	t.Run("OIDC provider requires IssuerURL", func(t *testing.T) {
		cfg := OIDCConfig{
			ID: "x", Provider: OIDCProviderGoogle,
			ClientID: "c", ClientSecret: "s", RedirectURL: "https://x",
			// IssuerURL intentionally empty
		}
		_, err := NewOIDC(context.Background(), cfg, users, sessions, nil)
		if err == nil {
			t.Error("expected NewOIDC to reject OIDC provider w/o IssuerURL")
		} else if !errors.Is(err, err) { // tautology — just assert we got *some* error
			t.Errorf("unexpected error shape: %v", err)
		}
	})
}
