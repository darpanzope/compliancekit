// Package auth handles every authentication concern for the v1.3
// serve-mode daemon: bcrypt password hashing, DB-backed sessions,
// double-submit-cookie CSRF protection, and the chi middleware that
// gates non-public routes.
//
// Phase 3 lands local-auth (email + password) + sessions + CSRF.
// Phase 4 adds OIDC subjects on top of the same users table.
// Phase 5 adds bearer-token auth for the REST API.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// bcryptCost is the per-password compute cost. 12 is a 2026-safe
// default — ~250ms per HashPassword on commodity hardware, which is
// the right ballpark for a login form (user-perceived snappy + slow
// enough to throttle brute-force). var instead of const so tests can
// override (the race detector + cost-12 blows past `make test`'s
// 60s timeout when every TestUsers_*/Sessions_* test bcrypts a
// password).
var bcryptCost = 12

// minPasswordLength is enforced at SetPassword time. compliancekit
// doesn't ship a SaaS password rotator; we trust the operator to
// pair this with a real password manager.
const minPasswordLength = 12

// ErrPasswordTooShort is returned when a password fails the length
// check. The handler should surface this as a field-level validation
// error, not a 500.
var ErrPasswordTooShort = fmt.Errorf("password must be at least %d characters", minPasswordLength)

// ErrInvalidCredentials is the single error returned by VerifyPassword
// for both "wrong user" and "wrong password" — never leak which one
// it was.
var ErrInvalidCredentials = errors.New("invalid email or password")

// HashPassword produces a bcrypt hash suitable for storage in
// users.password_hash. Returns ErrPasswordTooShort when the input is
// below the minimum.
func HashPassword(password string) (string, error) {
	if len(password) < minPasswordLength {
		return "", ErrPasswordTooShort
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("bcrypt: %w", err)
	}
	return string(h), nil
}

// VerifyPassword constant-time-compares the candidate against the
// stored bcrypt hash. Returns nil on match, ErrInvalidCredentials on
// mismatch (also returned when the stored hash is empty — accounts
// provisioned via OIDC only).
func VerifyPassword(storedHash, candidate string) error {
	if strings.TrimSpace(storedHash) == "" {
		return ErrInvalidCredentials
	}
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(candidate))
	if err != nil {
		return ErrInvalidCredentials
	}
	return nil
}

// randomToken returns a hex-encoded n-byte cryptographically random
// token. Used for session IDs + CSRF tokens — both want n=32 (256
// bits) which is well past collision risk for the lifetime of a
// session.
func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
