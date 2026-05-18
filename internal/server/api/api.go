// Package api implements the v1.3+ REST API. Routes mount under
// /api/v1. The API is JSON-only, returns a consistent error envelope
// {"error":"..."} on every non-2xx, supports pagination via ?page +
// ?per_page query params, and emits ETag headers for cacheable read
// endpoints so well-behaved clients (and the v1.4 studio UI) skip
// re-rendering identical responses.
//
// Auth: every route is gated on either a session cookie (browser
// flows) or a Bearer token with the right scope (machine flows).
// The Mount() function wires both middlewares; downstream handlers
// resolve the actor via auth.TokenFromContext + auth.FromContext.
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/store"
)

// API is the surface the daemon mounts onto its chi router. Holds
// references to the persistence + auth dependencies the handlers
// need.
type API struct {
	store    *store.Store
	users    *auth.Users
	tokens   *auth.Tokens
	sessions *auth.Sessions
}

// New constructs the API handle. The Mount() method wires every
// route on r under the /api/v1 prefix.
func New(st *store.Store, users *auth.Users, tokens *auth.Tokens, sessions *auth.Sessions) *API {
	return &API{store: st, users: users, tokens: tokens, sessions: sessions}
}

// Mount installs the v1 routes on r. Phase 6 ships the read surface;
// phase 7 layers the write endpoints on this same prefix. Phase 11
// (UI shell) calls Mount before starting the server.
func (a *API) Mount(r chi.Router) {
	r.Route("/api/v1", func(r chi.Router) {
		// Auth: a request may carry either a session cookie or a
		// Bearer token. The eitherAuth middleware tries both in
		// sequence; downstream RequireScope checks the token (when
		// present) or a fallback admin bit for the session user.
		r.Use(a.eitherAuth)

		r.Get("/scans", a.scopeGate(auth.ScopeScansRead, a.listScans))
		r.Get("/scans/{id}", a.scopeGate(auth.ScopeScansRead, a.getScan))
		r.Get("/scans/{id}/findings", a.scopeGate(auth.ScopeScansRead, a.listScanFindings))

		r.Get("/findings", a.scopeGate(auth.ScopeFindingsRead, a.listFindings))
		r.Get("/findings/{id}", a.scopeGate(auth.ScopeFindingsRead, a.getFinding))

		r.Get("/resources", a.scopeGate(auth.ScopeScansRead, a.listResources))
		r.Get("/resources/{id}", a.scopeGate(auth.ScopeScansRead, a.getResource))

		r.Get("/providers", a.scopeGate(auth.ScopeSettingsRead, a.listProviders))
		r.Get("/checks", a.scopeGate(auth.ScopeSettingsRead, a.listChecks))
		r.Get("/waivers", a.scopeGate(auth.ScopeWaiversRead, a.listWaivers))
	})
}

// eitherAuth tries token auth first (Authorization: Bearer), falling
// back to session auth (cookie). Either one satisfies the route;
// downstream handlers see whichever installed itself in context.
//
// Bear in mind both middlewares write 401 on failure. We need to
// pick exactly one. The pattern: peek at the Authorization header
// — if present, use the token path (and report token-specific errors
// loudly); otherwise use the session path.
func (a *API) eitherAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			a.tokens.RequireToken(next).ServeHTTP(w, r)
			return
		}
		a.sessions.RequireAuth(next).ServeHTTP(w, r)
	})
}

// scopeGate enforces auth.RequireScope for token-auth callers; for
// session-auth callers it just runs next (session users get the
// scopes they're entitled to elsewhere — phase 7 / v1.4 settings).
// The result is that the same handler is mountable for both flows.
func (a *API) scopeGate(needed auth.Scope, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tok := auth.TokenFromContext(r.Context()); tok != nil {
			if !tok.HasScope(needed) {
				respondError(w, http.StatusForbidden, "missing scope: "+string(needed))
				return
			}
		}
		next(w, r)
	}
}

// respondJSON marshals v + writes it with status. Caches via ETag
// when v is non-empty + the body is < 1 MB.
//
//nolint:unparam // phase 7 write endpoints will use 201/204; keeping the parameter avoids a churny rewrite
func respondJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "marshal response: "+err.Error())
		return
	}
	// Compute a weak ETag from the body. 64-bit truncation of the
	// SHA-256 sum is plenty for cache busting.
	if len(body) < 1<<20 { // < 1MB
		sum := sha256.Sum256(body)
		etag := `W/"` + hex.EncodeToString(sum[:8]) + `"`
		w.Header().Set("ETag", etag)
		if match := r.Header.Get("If-None-Match"); match == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// respondError writes a consistent {"error":"..."} envelope.
func respondError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":` + jsonString(msg) + `}` + "\n"))
}

// jsonString JSON-encodes a string value (with surrounding quotes).
// Avoids importing fmt + reflect for a hot-path helper.
func jsonString(s string) string {
	buf, _ := json.Marshal(s)
	return string(buf)
}

// parsePage reads ?page=N&per_page=M from the request. Both default
// to (1, 50). per_page caps at 500 to prevent operators from
// accidentally pulling 100k findings in one shot.
func parsePage(r *http.Request) (page, perPage int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ = strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 {
		perPage = 50
	}
	if perPage > 500 {
		perPage = 500
	}
	return page, perPage
}
