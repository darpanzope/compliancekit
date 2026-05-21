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
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/events"
	"github.com/darpanzope/compliancekit/internal/server/respcache"
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
	events   *events.Producer // v1.6: SSE event bus (nil OK — handler returns 503)
	cache    *respcache.Cache // v1.11: LRU; nil OK — cache lookup short-circuits
}

// New constructs the API handle. The Mount() method wires every
// route on r under the /api/v1 prefix.
func New(st *store.Store, users *auth.Users, tokens *auth.Tokens, sessions *auth.Sessions) *API {
	return &API{store: st, users: users, tokens: tokens, sessions: sessions}
}

// WithEvents installs the v1.6 SSE Producer. Returns the receiver for
// chaining. When set, the /api/v1/events route is mounted; otherwise
// it 404s and the daemon's polling paths still work.
func (a *API) WithEvents(p *events.Producer) *API {
	a.events = p
	return a
}

// WithCache installs the v1.11 phase 6 LRU response cache. Returns
// the receiver for chaining. When set, hot list responses are
// served from cache (60s TTL, busted on SSE mutation events).
// Nil/unset means every request hits the DB — the v1.10 default.
func (a *API) WithCache(c *respcache.Cache) *API {
	a.cache = c
	return a
}

// Mount installs the v1 routes on r. Phase 6 ships the read surface;
// phase 7 layers the write endpoints on this same prefix. Phase 11
// (UI shell) calls Mount before starting the server.
func (a *API) Mount(r chi.Router) {
	r.Route("/api/v1", func(r chi.Router) {
		// Auth: a request may carry either a session cookie or a
		// Bearer token. The eitherAuth middleware tries both in
		// sequence; downstream scopeGate enforces the right policy
		// for each flow.
		r.Use(a.eitherAuth)

		// CSRF: protects cookie-auth callers from cross-site mutating
		// requests. Skips automatically for token callers (bearer
		// tokens aren't browser-resident, so cross-site requests
		// can't smuggle them). v1.5.1 F16 — middleware was defined
		// in v1.3 but never wired.
		r.Use(a.sessions.RequireCSRF)

		r.Get("/scans", a.scopeGate(auth.ScopeScansRead, a.listScans))
		r.Get("/scans/{id}", a.scopeGate(auth.ScopeScansRead, a.getScan))
		r.Get("/scans/{id}/findings", a.scopeGate(auth.ScopeScansRead, a.listScanFindings))
		r.Post("/scans", a.scopeGate(auth.ScopeScansWrite, a.triggerScan))
		r.Post("/scans/ingest", a.scopeGate(auth.ScopeScansWrite, a.ingestScan))

		r.Get("/findings", a.scopeGate(auth.ScopeFindingsRead, a.listFindings))
		r.Get("/findings/{id}", a.scopeGate(auth.ScopeFindingsRead, a.getFinding))

		r.Get("/resources", a.scopeGate(auth.ScopeScansRead, a.listResources))
		r.Get("/resources/{id}", a.scopeGate(auth.ScopeScansRead, a.getResource))

		r.Get("/providers", a.scopeGate(auth.ScopeSettingsRead, a.listProviders))
		r.Put("/providers/{id}", a.scopeGate(auth.ScopeSettingsWrite, a.updateProvider))

		r.Get("/checks", a.scopeGate(auth.ScopeSettingsRead, a.listChecks))
		// v1.8 phase 4 — @mention autocomplete in the comments composer.
		r.Get("/users/search", a.scopeGate(auth.ScopeSettingsRead, a.searchUsers))
		r.Post("/checks/{id}/toggle", a.scopeGate(auth.ScopeSettingsWrite, a.toggleCheck))

		r.Get("/waivers", a.scopeGate(auth.ScopeWaiversRead, a.listWaivers))
		r.Post("/waivers", a.scopeGate(auth.ScopeWaiversWrite, a.createWaiver))
		r.Put("/waivers/{id}", a.scopeGate(auth.ScopeWaiversWrite, a.updateWaiver))
		r.Delete("/waivers/{id}", a.scopeGate(auth.ScopeWaiversWrite, a.revokeWaiver))

		// v1.6 phase 0: SSE event bus. Mounted only when WithEvents
		// installed a Producer; otherwise the route is absent +
		// clients fall back to polling. Auth-gated by eitherAuth +
		// scopeGate(ScopeScansRead) like the rest of /api/v1.
		if a.events != nil {
			r.Get("/events", a.scopeGate(auth.ScopeScansRead, a.events.Handler()))
		}
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

// scopeGate enforces the needed scope for both auth flows. For token
// auth (Authorization: Bearer ck_…) it consults tok.HasScope. For
// session auth (cookie) it loads the session's user and treats admin
// users as having every scope (parity with token's `*` scope); non-
// admin session users get every `:read` scope but are forbidden from
// any `:write` action. F18 fix for v1.5.1 — the v1.3 implementation
// silently fell through for session callers, letting any logged-in
// local user trigger scans, mutate providers, and revoke waivers.
func (a *API) scopeGate(needed auth.Scope, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tok := auth.TokenFromContext(r.Context()); tok != nil {
			if !tok.HasScope(needed) {
				respondError(w, http.StatusForbidden, "missing scope: "+string(needed))
				return
			}
			next(w, r)
			return
		}
		// Session-auth path: load the user, check IsAdmin.
		sess := auth.FromContext(r.Context())
		if sess == nil {
			respondError(w, http.StatusUnauthorized, "auth required")
			return
		}
		user, err := a.users.ByID(r.Context(), sess.UserID)
		if err != nil || user == nil {
			respondError(w, http.StatusUnauthorized, "session user lookup failed")
			return
		}
		if !user.IsAdmin && isWriteScope(needed) {
			respondError(w, http.StatusForbidden, "admin required for scope: "+string(needed))
			return
		}
		next(w, r)
	}
}

// isWriteScope returns true for scopes that mutate state. Used by
// scopeGate to gate non-admin session users to read-only routes.
func isWriteScope(s auth.Scope) bool {
	return strings.HasSuffix(string(s), ":write") || s == auth.ScopeAdmin
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
