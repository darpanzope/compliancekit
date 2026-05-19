package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/store"
)

// loadOIDCFromEnv inspects CK_OIDC_{GOOGLE,OKTA,GITHUB,CUSTOM}_* env
// vars and, for each fully-configured provider, constructs an
// auth.OIDC handler, mounts its routes on r, and returns the matching
// button entries for the /login template. v1.5.1 F15.
//
// Required env vars per provider (suffix on CK_OIDC_<PROVIDER>_):
//
//	GOOGLE  — CLIENT_ID, CLIENT_SECRET, REDIRECT_URL
//	OKTA    — CLIENT_ID, CLIENT_SECRET, REDIRECT_URL, ISSUER_URL
//	GITHUB  — CLIENT_ID, CLIENT_SECRET, REDIRECT_URL
//	CUSTOM  — CLIENT_ID, CLIENT_SECRET, REDIRECT_URL, ISSUER_URL
//
// A provider whose vars are partially set is logged + skipped; the
// daemon never refuses to boot for a malformed OIDC config.
func loadOIDCFromEnv(ctx context.Context, r chi.Router, users *auth.Users, sessions *auth.Sessions, st *store.Store) ([]auth.OIDCProviderButton, error) {
	type plan struct {
		envPrefix    string
		id           string
		provider     auth.OIDCProvider
		label        string
		defaultIssue string // empty = required from env
	}
	plans := []plan{
		{"CK_OIDC_GOOGLE", "google", auth.OIDCProviderGoogle, "Sign in with Google", "https://accounts.google.com"},
		{"CK_OIDC_OKTA", "okta", auth.OIDCProviderOkta, "Sign in with Okta", ""},
		{"CK_OIDC_GITHUB", "github", auth.OIDCProviderGitHub, "Sign in with GitHub", ""}, // github ignores issuer
		{"CK_OIDC_CUSTOM", "custom", auth.OIDCProviderCustom, "Sign in with SSO", ""},
	}

	out := make([]auth.OIDCProviderButton, 0, len(plans))
	for _, p := range plans {
		clientID := os.Getenv(p.envPrefix + "_CLIENT_ID")
		clientSecret := os.Getenv(p.envPrefix + "_CLIENT_SECRET")
		redirect := os.Getenv(p.envPrefix + "_REDIRECT_URL")
		if clientID == "" && clientSecret == "" && redirect == "" {
			continue // provider not configured at all
		}
		if clientID == "" || clientSecret == "" || redirect == "" {
			return nil, fmt.Errorf("%s: incomplete OIDC config (need CLIENT_ID + CLIENT_SECRET + REDIRECT_URL)", p.envPrefix)
		}
		issuer := os.Getenv(p.envPrefix + "_ISSUER_URL")
		if issuer == "" {
			issuer = p.defaultIssue
		}
		if issuer == "" && p.provider != auth.OIDCProviderGitHub {
			return nil, fmt.Errorf("%s: missing %s_ISSUER_URL", p.envPrefix, p.envPrefix)
		}

		cfg := auth.OIDCConfig{
			ID:           p.id,
			Provider:     p.provider,
			IssuerURL:    issuer,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirect,
		}
		o, err := auth.NewOIDC(ctx, cfg, users, sessions, st)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.envPrefix, err)
		}
		o.Mount(r)
		out = append(out, auth.OIDCProviderButton{ID: p.id, Label: p.label})
	}
	return out, nil
}
