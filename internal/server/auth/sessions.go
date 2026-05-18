package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// SessionCookieName is the cookie carrying the opaque session ID.
// Prefixed __Host- to opt into the strictest browser cookie policy:
// HTTPS-only, no Domain attribute, Path=/. Modern browsers refuse to
// honor __Host- prefixed cookies that violate the rules — fail-loud
// is the right default for an auth cookie.
const SessionCookieName = "__Host-ck_session"

// CSRFCookieName is the readable companion cookie for the double-
// submit CSRF pattern. Not prefixed __Host- because JS needs to read
// it for the form/header value submission.
const CSRFCookieName = "ck_csrf"

// CSRFHeaderName is the request header the middleware checks for the
// CSRF token on state-mutating requests. The JS side reads
// CSRFCookieName and sets the header on every fetch.
const CSRFHeaderName = "X-CSRF-Token"

// sessionTTL is how long a session lives before forced re-login.
// 12 hours is a sensible balance for an operator daemon — long enough
// to survive a work day, short enough to limit the blast radius of a
// stolen cookie.
const sessionTTL = 12 * time.Hour

// SessionTokenBytes / CSRFTokenBytes — both produce 256-bit tokens.
const (
	sessionTokenBytes = 32
	csrfTokenBytes    = 32
)

// Session is the in-memory shape returned by LoadSession + companion
// methods. Field set matches the sessions table.
type Session struct {
	ID         string
	UserID     string
	CSRFToken  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	UserAgent  string
	IP         string
}

// ErrSessionExpired is returned by LoadSession when the cookie's
// session ID resolves to a row that's past its expires_at.
var ErrSessionExpired = errors.New("session expired")

// ErrSessionNotFound is returned by LoadSession when there's no row
// for the cookie's session ID (revoked, expired-and-cleaned, or
// forged cookie).
var ErrSessionNotFound = errors.New("session not found")

// Sessions is the persistence layer for the session table. Both the
// http middleware and the login/logout handlers go through this type.
type Sessions struct {
	store *store.Store
}

// NewSessions returns a Sessions handle bound to st.
func NewSessions(st *store.Store) *Sessions {
	return &Sessions{store: st}
}

// Create issues a new session row for userID. Returns the session +
// the plaintext cookie value the caller must set on the response.
// Both the session ID and the CSRF token are 256-bit hex strings.
func (s *Sessions) Create(ctx context.Context, userID, userAgent, ip string) (*Session, error) {
	sid, err := randomToken(sessionTokenBytes)
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken(csrfTokenBytes)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	expires := now.Add(sessionTTL)

	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`INSERT INTO sessions (id, user_id, csrf_token, created_at, last_seen_at, expires_at, user_agent, ip)
		 VALUES (%s, %s, %s, %s, %s, %s, %s, %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8))
	_, err = s.store.DB().ExecContext(ctx, q, sid, userID, csrf,
		now.Format(time.RFC3339), now.Format(time.RFC3339), expires.Format(time.RFC3339),
		userAgent, ip)
	if err != nil {
		return nil, fmt.Errorf("insert session: %w", err)
	}
	return &Session{
		ID:         sid,
		UserID:     userID,
		CSRFToken:  csrf,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  expires,
		UserAgent:  userAgent,
		IP:         ip,
	}, nil
}

// Load fetches the session row by ID. Touches last_seen_at on
// success so an active session doesn't drift toward expiry. Returns
// ErrSessionNotFound / ErrSessionExpired distinct from other errors
// so the middleware can clear the cookie cleanly.
func (s *Sessions) Load(ctx context.Context, sid string) (*Session, error) {
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, user_id, csrf_token, created_at, last_seen_at, expires_at, user_agent, ip
		 FROM sessions WHERE id = %s`, s.ph(1))
	row := s.store.DB().QueryRowContext(ctx, q, sid)
	var (
		out                        Session
		created, lastSeen, expires string
		ua, ip                     sql.NullString
	)
	if err := row.Scan(&out.ID, &out.UserID, &out.CSRFToken, &created, &lastSeen, &expires, &ua, &ip); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("scan session: %w", err)
	}
	out.CreatedAt = parseTime(created)
	out.LastSeenAt = parseTime(lastSeen)
	out.ExpiresAt = parseTime(expires)
	out.UserAgent = ua.String
	out.IP = ip.String

	if time.Now().UTC().After(out.ExpiresAt) {
		// Best-effort delete; the row will also get swept by a periodic
		// cleanup job in phase 8.
		_ = s.delete(ctx, sid)
		return nil, ErrSessionExpired
	}

	// Touch last_seen_at; ignore the error — the load succeeded, the
	// session is valid, the update is a soft signal.
	updateQ := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`UPDATE sessions SET last_seen_at = %s WHERE id = %s`, s.ph(1), s.ph(2))
	_, _ = s.store.DB().ExecContext(ctx, updateQ, time.Now().UTC().Format(time.RFC3339), sid)
	return &out, nil
}

// Destroy invalidates a session row. Idempotent.
func (s *Sessions) Destroy(ctx context.Context, sid string) error {
	return s.delete(ctx, sid)
}

// DestroyForUser deletes every session for userID — used by password
// change + the "log me out everywhere" affordance the v1.4 settings
// page will eventually expose.
func (s *Sessions) DestroyForUser(ctx context.Context, userID string) error {
	q := fmt.Sprintf(`DELETE FROM sessions WHERE user_id = %s`, s.ph(1)) //nolint:gosec // placeholders only; no user input
	_, err := s.store.DB().ExecContext(ctx, q, userID)
	return err
}

func (s *Sessions) delete(ctx context.Context, sid string) error {
	q := fmt.Sprintf(`DELETE FROM sessions WHERE id = %s`, s.ph(1)) //nolint:gosec // placeholders only; no user input
	_, err := s.store.DB().ExecContext(ctx, q, sid)
	return err
}

// ph is a tiny shim into the store's placeholder helper so the SQL
// strings above stay terse.
func (s *Sessions) ph(n int) string {
	// Method on Store is currently package-private; we use the
	// driver-aware public helper via a small adapter.
	if s.store.Driver() == store.DriverPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

// SetCookies writes the SessionCookieName + CSRFCookieName onto w.
// __Host-ck_session is HttpOnly + Secure + SameSite=Lax + Path=/ +
// no Domain (the __Host- prefix mandates these). ck_csrf is the
// readable companion (not HttpOnly) so client-side JS can mirror it
// into the X-CSRF-Token header on every state-mutating request.
func SetCookies(w http.ResponseWriter, sess *Session) {
	maxAge := int(time.Until(sess.ExpiresAt).Seconds())
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sess.ID,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    sess.CSRFToken,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookies tells the browser to drop both cookies. Used by
// logout + by middleware when a stored session is missing / expired.
func ClearCookies(w http.ResponseWriter) {
	for _, name := range []string{SessionCookieName, CSRFCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: name == SessionCookieName,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

// parseTime parses an RFC-3339 timestamp; returns zero time on any
// error (the caller will treat it as expired which is the safe
// default).
func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
