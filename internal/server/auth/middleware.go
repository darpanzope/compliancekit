package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// contextKey is the unexported type guarding the per-request session
// stash; standard idiom to avoid context-key collisions across
// packages.
type contextKey int

const (
	sessionContextKey contextKey = iota
)

// FromContext retrieves the *Session installed by RequireAuth.
// Returns nil when the route is unauthenticated.
func FromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionContextKey).(*Session)
	return s
}

// withSession returns a child context carrying sess. Test helper +
// middleware internal.
func withSession(ctx context.Context, sess *Session) context.Context {
	return context.WithValue(ctx, sessionContextKey, sess)
}

// InjectTestSession returns a context carrying a minimal Session for
// userID. Exported as a test helper so package-external tests (e.g.
// the scopeGate RBAC tests) can simulate a logged-in user without
// reaching for the cookie + Load round-trip.
func InjectTestSession(ctx context.Context, userID string) context.Context {
	return withSession(ctx, &Session{ID: "test-session", UserID: userID})
}

// RequireAuth is the chi middleware factory that gates a route on a
// valid session cookie. On missing / expired session the cookies are
// cleared and the response is 401 (for /api routes) or a 303 redirect
// to /login (for everything else). The decision is driven by the
// request's Accept header + path prefix — pure-JSON callers get the
// machine-friendly status; browser callers get the human redirect.
func (s *Sessions) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(s.CookieName())
		if err != nil || c.Value == "" {
			s.deny(w, r, http.StatusUnauthorized)
			return
		}
		sess, err := s.Load(r.Context(), c.Value)
		if err != nil {
			s.ClearCookies(w)
			switch {
			case errors.Is(err, ErrSessionNotFound), errors.Is(err, ErrSessionExpired):
				s.deny(w, r, http.StatusUnauthorized)
			default:
				http.Error(w, "session lookup failed", http.StatusInternalServerError)
			}
			return
		}
		next.ServeHTTP(w, r.WithContext(withSession(r.Context(), sess)))
	})
}

// RequireCSRF gates state-mutating requests on the double-submit
// cookie check. Reads the X-CSRF-Token header (set by client JS from
// the readable ck_csrf cookie) and compares it constant-time against
// the session's csrf_token. The session must already be installed by
// RequireAuth — chain RequireAuth before RequireCSRF.
//
// Safe methods (GET / HEAD / OPTIONS) pass through unchecked; the
// browser doesn't trigger CSRF on those.
//
// Token-auth callers (Authorization: Bearer ck_…) skip the CSRF
// check entirely — bearer tokens are not browser-resident credentials
// so cross-site requests can't smuggle them; CSRF protects only
// against cookie-based session hijacks.
func (s *Sessions) RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		// Token auth: skip CSRF (see doc comment).
		if TokenFromContext(r.Context()) != nil {
			next.ServeHTTP(w, r)
			return
		}
		sess := FromContext(r.Context())
		if sess == nil {
			// Should not happen if RequireAuth ran first; defensive.
			http.Error(w, "csrf: no session in context", http.StatusForbidden)
			return
		}
		header := r.Header.Get(CSRFHeaderName)
		formField := r.FormValue("csrf_token") // form fallback for non-JS clients
		given := header
		if given == "" {
			given = formField
		}
		if given == "" || !constantTimeEqual(given, sess.CSRFToken) {
			http.Error(w, "csrf: token mismatch", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// deny writes the appropriate denial response based on the request's
// Accept header + URL path. API callers get 401; browser callers get
// a 303 to /login with a `next=` redirect target.
func (s *Sessions) deny(w http.ResponseWriter, r *http.Request, status int) {
	if status == http.StatusUnauthorized && wantsHTML(r) {
		// Browser-style redirect to /login w/ the originally-requested
		// path so post-login lands them back where they came from.
		http.Redirect(w, r, "/login?next="+r.URL.Path, http.StatusSeeOther)
		return
	}
	http.Error(w, http.StatusText(status), status)
}

// wantsHTML returns true when the client looks like a browser — used
// to pick between JSON 401 and 303-to-/login.
func wantsHTML(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return false
	}
	accept := r.Header.Get("Accept")
	return accept == "" || strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

// constantTimeEqual is a string-friendly wrapper around
// crypto/subtle.ConstantTimeCompare. Both strings must be the same
// length to compare equal; padding to a fixed length is irrelevant
// since we control the token generator (always 64 hex chars).
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
