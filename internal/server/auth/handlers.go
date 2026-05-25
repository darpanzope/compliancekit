package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// LoginRequest is the JSON body POST /api/auth/login accepts.
// The HTML login form (phase 11) submits the same fields via
// application/x-www-form-urlencoded — the handler accepts both.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Next     string `json:"next,omitempty"` // post-login redirect path
}

// LoginResponse is the JSON body on a successful POST. Browser flows
// receive a 303 redirect to LoginRequest.Next instead.
type LoginResponse struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	IsAdmin     bool   `json:"is_admin"`
	DisplayName string `json:"display_name,omitempty"`
}

// LoginHandler builds the POST /api/auth/login handler. Validates
// the credentials via Users + VerifyPassword, issues a Session via
// Sessions.Create, sets the session + CSRF cookies, and responds
// with JSON (or a 303 to next= for browser POSTs).
func LoginHandler(users *Users, sessions *Sessions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, err := parseLogin(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		user, err := users.ByEmail(r.Context(), req.Email)
		if err != nil {
			// Same error for "wrong email" + "wrong password" — never
			// leak which one missed.
			if errors.Is(err, ErrUserNotFound) {
				http.Error(w, ErrInvalidCredentials.Error(), http.StatusUnauthorized)
				return
			}
			http.Error(w, "lookup user: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := VerifyPassword(user.PasswordHash, req.Password); err != nil {
			http.Error(w, ErrInvalidCredentials.Error(), http.StatusUnauthorized)
			return
		}
		sess, err := sessions.Create(r.Context(), user.ID, r.UserAgent(), clientIP(r))
		if err != nil {
			http.Error(w, "create session: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Best-effort.
		_ = users.TouchLastLogin(r.Context(), user.ID)

		sessions.SetCookies(w, sess)

		// HTML form → redirect; JSON caller → JSON body.
		if isFormPost(r) {
			next := req.Next
			if next == "" || !strings.HasPrefix(next, "/") {
				next = "/"
			}
			http.Redirect(w, r, next, http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(LoginResponse{
			UserID:      user.ID,
			Email:       user.Email,
			IsAdmin:     user.IsAdmin,
			DisplayName: user.DisplayName,
		})
	}
}

// LogoutHandler builds the POST /api/auth/logout handler. Destroys
// the current session + clears cookies. Browser flows redirect to
// /login; JSON callers get 204.
func LogoutHandler(sessions *Sessions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessions.CookieName()); err == nil && c.Value != "" {
			_ = sessions.Destroy(r.Context(), c.Value)
		}
		sessions.ClearCookies(w)
		if isFormPost(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// MeHandler builds the GET /api/auth/me handler. Returns the current
// session's user info; should be behind RequireAuth.
func MeHandler(users *Users) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := FromContext(r.Context())
		if sess == nil {
			http.Error(w, "no session", http.StatusUnauthorized)
			return
		}
		u, err := users.ByID(r.Context(), sess.UserID)
		if err != nil {
			http.Error(w, "lookup user: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(LoginResponse{
			UserID:      u.ID,
			Email:       u.Email,
			IsAdmin:     u.IsAdmin,
			DisplayName: u.DisplayName,
		})
	}
}

// parseLogin decodes a LoginRequest from either JSON or form body
// based on Content-Type.
func parseLogin(r *http.Request) (*LoginRequest, error) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		return &req, nil
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	return &LoginRequest{
		Email:    r.FormValue("email"),
		Password: r.FormValue("password"),
		Next:     r.FormValue("next"),
	}, nil
}

func isFormPost(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(ct, "multipart/form-data")
}

// clientIP returns the request's TCP peer IP (host portion of
// r.RemoteAddr). v1.14.1 removed the upstream middleware.RealIP
// dependency per GHSA-3fxj-6jh8-hvhx — X-Forwarded-For is no longer
// trusted automatically. When the daemon runs behind a proxy the
// audit_log shows the proxy's IP; the proxy's own access log keeps
// the real client. A v1.15.x trust-list middleware will reinstate
// the forwarded-header path opt-in.
func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host
}
