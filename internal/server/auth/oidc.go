package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// OIDCProvider names the upstream identity service. Google + Okta +
// "custom" use the standard OIDC discovery flow against an issuer
// URL; GitHub uses a separate OAuth2-only path (it doesn't ship
// OpenID Connect, only OAuth2 + a /user endpoint we read separately).
type OIDCProvider string

// OIDCProviderButton is the display-side projection of an OIDC config
// for rendering on the /login page. v1.5.1 F15 — populated by the
// daemon at boot for every configured provider and passed to the UI
// via UI.SetOIDCProviders.
type OIDCProviderButton struct {
	ID    string // url-safe id; matches the path segment in /oidc/{id}/login
	Label string // human display label, e.g. "Sign in with Google"
}

const (
	OIDCProviderGoogle OIDCProvider = "google"
	OIDCProviderOkta   OIDCProvider = "okta"
	OIDCProviderGitHub OIDCProvider = "github"
	OIDCProviderCustom OIDCProvider = "custom"
)

// OIDCConfig is one configured OIDC integration. Operators register
// one of these per upstream they accept logins from; the daemon
// supports many simultaneously (the routes are
// /oidc/{provider-id}/login and /oidc/{provider-id}/callback).
type OIDCConfig struct {
	// ID is the URL-safe identifier ("google", "okta-corp",
	// "github-enterprise") that namespaces the callback URL.
	ID string

	// Provider drives the discovery + userinfo strategy.
	Provider OIDCProvider

	// IssuerURL is the OIDC issuer (for Google, Okta, generic).
	// Ignored when Provider == OIDCProviderGitHub.
	IssuerURL string

	// ClientID + ClientSecret are the OAuth2 app credentials issued
	// by the upstream provider.
	ClientID     string
	ClientSecret string

	// RedirectURL is the absolute callback URL the upstream invokes
	// after the user grants consent. Must match what the operator
	// registered with the provider exactly (scheme + host + path).
	RedirectURL string

	// Scopes default to the standard OIDC set ("openid", "profile",
	// "email") for OIDC providers and {"user:email"} for GitHub. Set
	// to override.
	Scopes []string
}

// oidcStateCookieName carries the CSRF-bound state between the
// /login redirect and the /callback handler. Tiny lifespan (5 min)
// so an unused / stale state can't be re-used.
const oidcStateCookieName = "ck_oidc_state"

// OIDC encapsulates the runtime state for one configured upstream.
// Build via NewOIDC; mount its handlers on the chi router.
type OIDC struct {
	cfg      OIDCConfig
	oauth2   *oauth2.Config
	verifier *oidc.IDTokenVerifier // nil for github (no OIDC)
	users    *Users
	sessions *Sessions
	store    *store.Store
}

// NewOIDC discovers the provider's metadata and returns a ready-to-
// mount handler set. GitHub takes a short-circuit path (no OIDC
// discovery, only OAuth2 + a userinfo HTTP fetch).
func NewOIDC(ctx context.Context, cfg OIDCConfig, users *Users, sessions *Sessions, st *store.Store) (*OIDC, error) {
	if cfg.ID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURL == "" {
		return nil, errors.New("oidc: ID, ClientID, ClientSecret, RedirectURL are all required")
	}
	o := &OIDC{cfg: cfg, users: users, sessions: sessions, store: st}

	switch cfg.Provider {
	case OIDCProviderGitHub:
		scopes := cfg.Scopes
		if len(scopes) == 0 {
			scopes = []string{"read:user", "user:email"}
		}
		o.oauth2 = &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://github.com/login/oauth/authorize",
				TokenURL: "https://github.com/login/oauth/access_token",
			},
		}
	default:
		// OIDC discovery for everyone else (Google, Okta, custom).
		if cfg.IssuerURL == "" {
			return nil, fmt.Errorf("oidc: IssuerURL required for provider %q", cfg.Provider)
		}
		provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery for %s: %w", cfg.IssuerURL, err)
		}
		scopes := cfg.Scopes
		if len(scopes) == 0 {
			scopes = []string{oidc.ScopeOpenID, "profile", "email"}
		}
		o.oauth2 = &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
			Endpoint:     provider.Endpoint(),
		}
		o.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	}
	return o, nil
}

// Config returns the OIDCConfig the handler was constructed with;
// useful for the v1.4 settings page to surface what's configured.
func (o *OIDC) Config() OIDCConfig { return o.cfg }

// Mount wires the per-provider routes under /oidc/{id}/login and
// /oidc/{id}/callback. v1.5.1 F15 — `auth.NewOIDC` + every handler
// shipped in v1.3 with unit tests, but the routes were never mounted
// onto the daemon's chi router. The login template even advertised
// OIDC; the corresponding paths returned 404 in production.
func (o *OIDC) Mount(r chi.Router) {
	r.Get("/oidc/"+o.cfg.ID+"/login", o.LoginHandler())
	r.Get("/oidc/"+o.cfg.ID+"/callback", o.CallbackHandler())
}

// LoginHandler kicks off the authorization-code flow: generates a
// random state, sets it in a short-lived cookie, redirects the user
// to the upstream's authorize URL.
func (o *OIDC) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := randomToken(16)
		if err != nil {
			http.Error(w, "generate state: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     oidcStateCookieName,
			Value:    state,
			Path:     "/",
			MaxAge:   300, // 5 min
			HttpOnly: true,
			Secure:   o.sessions.SecureCookies,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, o.oauth2.AuthCodeURL(state), http.StatusSeeOther)
	}
}

// CallbackHandler completes the flow: verifies state, exchanges the
// code for tokens, resolves the user identity (from id_token claims
// or upstream /user endpoint depending on provider), find-or-creates
// a row in users, issues a session, sets cookies, redirects to "/".
func (o *OIDC) CallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// State verification (CSRF protection for the OAuth flow).
		c, err := r.Cookie(oidcStateCookieName)
		if err != nil {
			http.Error(w, "missing oidc state cookie", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("state") != c.Value {
			http.Error(w, "oidc state mismatch", http.StatusBadRequest)
			return
		}
		// Best-effort delete of the state cookie.
		http.SetCookie(w, &http.Cookie{Name: oidcStateCookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: o.sessions.SecureCookies, SameSite: http.SameSiteLaxMode})

		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}
		tok, err := o.oauth2.Exchange(r.Context(), code)
		if err != nil {
			http.Error(w, "exchange code: "+err.Error(), http.StatusBadGateway)
			return
		}

		identity, err := o.identityFromToken(r.Context(), tok)
		if err != nil {
			http.Error(w, "resolve identity: "+err.Error(), http.StatusBadGateway)
			return
		}

		user, err := o.findOrCreateUser(r.Context(), identity)
		if err != nil {
			http.Error(w, "find-or-create user: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_ = o.users.TouchLastLogin(r.Context(), user.ID)
		sess, err := o.sessions.Create(r.Context(), user.ID, r.UserAgent(), clientIP(r))
		if err != nil {
			http.Error(w, "create session: "+err.Error(), http.StatusInternalServerError)
			return
		}
		o.sessions.SetCookies(w, sess)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// oidcIdentity is the trimmed subject the rest of the auth pipeline
// works with — namespaced by provider so two upstreams that issue the
// same numeric subject ID don't collide.
type oidcIdentity struct {
	Provider OIDCProvider
	Subject  string
	Email    string
	Name     string
}

// identityFromToken extracts the upstream subject + email via the
// id_token (OIDC) or the userinfo endpoint (GitHub OAuth2).
func (o *OIDC) identityFromToken(ctx context.Context, tok *oauth2.Token) (oidcIdentity, error) {
	if o.cfg.Provider == OIDCProviderGitHub {
		return o.identityFromGitHub(ctx, tok)
	}
	// OIDC: id_token claims.
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		return oidcIdentity{}, errors.New("no id_token in response")
	}
	idTok, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		return oidcIdentity{}, fmt.Errorf("verify id_token: %w", err)
	}
	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := idTok.Claims(&claims); err != nil {
		return oidcIdentity{}, fmt.Errorf("decode claims: %w", err)
	}
	if claims.Sub == "" {
		return oidcIdentity{}, errors.New("id_token has no sub claim")
	}
	return oidcIdentity{
		Provider: o.cfg.Provider,
		Subject:  claims.Sub,
		Email:    claims.Email,
		Name:     claims.Name,
	}, nil
}

// identityFromGitHub fetches /user + /user/emails using the OAuth2
// access token. GitHub returns the primary email separately from the
// user record so an emailless profile (privacy-locked) still lands a
// usable identity.
func (o *OIDC) identityFromGitHub(ctx context.Context, tok *oauth2.Token) (oidcIdentity, error) {
	cli := o.oauth2.Client(ctx, tok)
	// /user
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", http.NoBody)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := cli.Do(req)
	if err != nil {
		return oidcIdentity{}, fmt.Errorf("github /user: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return oidcIdentity{}, fmt.Errorf("github /user status %d", resp.StatusCode)
	}
	var u struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return oidcIdentity{}, fmt.Errorf("decode github user: %w", err)
	}
	email := u.Email
	if email == "" {
		// Hit /user/emails for the primary verified address.
		req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", http.NoBody)
		req2.Header.Set("Accept", "application/vnd.github+json")
		resp2, err := cli.Do(req2)
		if err == nil {
			defer func() { _ = resp2.Body.Close() }()
			if resp2.StatusCode == http.StatusOK {
				var emails []struct {
					Email    string `json:"email"`
					Primary  bool   `json:"primary"`
					Verified bool   `json:"verified"`
				}
				if err := json.NewDecoder(resp2.Body).Decode(&emails); err == nil {
					for _, e := range emails {
						if e.Primary && e.Verified {
							email = e.Email
							break
						}
					}
				}
			}
		}
	}
	if email == "" {
		// Fall back to a synthetic GitHub-noreply email so the user
		// row still satisfies the NOT NULL email constraint. The
		// operator can correct it via the v1.4 settings page.
		email = fmt.Sprintf("%d+%s@users.noreply.github.com", u.ID, u.Login)
	}
	return oidcIdentity{
		Provider: OIDCProviderGitHub,
		Subject:  fmt.Sprintf("%d", u.ID),
		Email:    email,
		Name:     firstNonEmpty(u.Name, u.Login),
	}, nil
}

// findOrCreateUser resolves an upstream identity to a row in users.
// Lookup priority:
//  1. By (oidc_provider, oidc_subject) — the canonical join key.
//  2. By email when no row matches (1) — covers the "operator
//     already has a local-auth account, now linking OIDC" path.
//  3. Insert a fresh OIDC-only row otherwise.
func (o *OIDC) findOrCreateUser(ctx context.Context, ident oidcIdentity) (*User, error) {
	// 1. By (provider, subject).
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, email, display_name, password_hash, oidc_subject, oidc_provider, is_admin, created_at, last_login_at
		 FROM users WHERE oidc_provider = %s AND oidc_subject = %s`,
		o.users.ph(1), o.users.ph(2))
	if u, err := o.users.scanOne(ctx, q, string(ident.Provider), ident.Subject); err == nil {
		return u, nil
	} else if !errors.Is(err, ErrUserNotFound) {
		return nil, err
	}

	// 2. By email — link OIDC onto the existing local account.
	if ident.Email != "" {
		if existing, err := o.users.ByEmail(ctx, ident.Email); err == nil {
			linkQ := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
				`UPDATE users SET oidc_provider = %s, oidc_subject = %s WHERE id = %s`,
				o.users.ph(1), o.users.ph(2), o.users.ph(3))
			if _, err := o.store.DB().ExecContext(ctx, linkQ, string(ident.Provider), ident.Subject, existing.ID); err != nil {
				return nil, fmt.Errorf("link oidc to existing user: %w", err)
			}
			existing.OIDCProvider = string(ident.Provider)
			existing.OIDCSubject = ident.Subject
			return existing, nil
		} else if !errors.Is(err, ErrUserNotFound) {
			return nil, err
		}
	}

	// 3. Insert a fresh OIDC-only user (password_hash NULL).
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339)
	email := strings.ToLower(strings.TrimSpace(ident.Email))
	q = fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`INSERT INTO users (id, email, display_name, oidc_subject, oidc_provider, is_admin, created_at)
		 VALUES (%s, %s, %s, %s, %s, %s, %s)`,
		o.users.ph(1), o.users.ph(2), o.users.ph(3), o.users.ph(4), o.users.ph(5), o.users.ph(6), o.users.ph(7))
	if _, err := o.store.DB().ExecContext(ctx, q, id, email, ident.Name, ident.Subject, string(ident.Provider), 0, now); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrEmailAlreadyTaken
		}
		return nil, fmt.Errorf("insert oidc user: %w", err)
	}
	return o.users.ByID(ctx, id)
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}
