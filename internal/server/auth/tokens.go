package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// TokenPrefix is the human-recognizable tag every issued token
// carries. Operators see "ck_<32 hex chars>" and know it's a
// compliancekit token even if they don't recall the source.
const TokenPrefix = "ck_"

// Scope identifies a granular permission an API token can carry.
// Scopes are namespaced "<resource>:<verb>" with the convention that
// "*" wildcard at any segment grants every value at that level.
// Granted scopes are checked at the route handler via RequireScope.
type Scope string

const (
	// ScopeScansRead lists / reads scans + their findings + resources.
	ScopeScansRead Scope = "scans:read"

	// ScopeScansWrite triggers new scans (POST /api/v1/scans).
	ScopeScansWrite Scope = "scans:write"

	// ScopeFindingsRead reads findings standalone (also covered by
	// scans:read on the per-scan path; this scope is for the global
	// filtered explorer endpoints v1.5 ships).
	ScopeFindingsRead Scope = "findings:read"

	// ScopeWaiversRead lists waivers.
	ScopeWaiversRead Scope = "waivers:read"

	// ScopeWaiversWrite mutates the waivers set (add / edit / expire).
	ScopeWaiversWrite Scope = "waivers:write"

	// ScopeSettingsRead reads provider + check + framework + schedule
	// config.
	ScopeSettingsRead Scope = "settings:read"

	// ScopeSettingsWrite mutates the same.
	ScopeSettingsWrite Scope = "settings:write"

	// ScopeAdmin is the operator-superpower bit: covers everything,
	// plus user + token + webhook management. Tokens issued by the
	// v1.4 settings page top out at non-admin unless the operator
	// explicitly grants this.
	ScopeAdmin Scope = "*"
)

// Token is the in-memory shape returned by Tokens.Verify (the row
// minus token_hash, which never leaves the package). Scopes are
// already parsed.
type Token struct {
	ID         string
	UserID     string
	Name       string
	Prefix     string
	Scopes     []Scope
	CreatedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time
}

// HasScope reports whether t grants the given scope. ScopeAdmin
// short-circuits to true. Otherwise the granted scope must equal
// requested OR be the "<resource>:*" wildcard for the same resource.
func (t *Token) HasScope(s Scope) bool {
	for _, g := range t.Scopes {
		if g == ScopeAdmin || g == s {
			return true
		}
		// "<resource>:*" wildcard
		if strings.HasSuffix(string(g), ":*") {
			prefix := strings.TrimSuffix(string(g), ":*")
			if strings.HasPrefix(string(s), prefix+":") {
				return true
			}
		}
	}
	return false
}

// ErrTokenNotFound is returned by Verify when the bearer doesn't
// match any row. The middleware treats this as 401.
var ErrTokenNotFound = errors.New("api token not recognized")

// ErrTokenExpired is returned by Verify when the row's expires_at
// has elapsed.
var ErrTokenExpired = errors.New("api token expired")

// ErrTokenRevoked is returned by Verify when the row's revoked_at
// is non-null.
var ErrTokenRevoked = errors.New("api token revoked")

// Tokens is the persistence layer for the api_tokens table.
type Tokens struct {
	store *store.Store
}

// NewTokens returns a Tokens handle bound to st.
func NewTokens(st *store.Store) *Tokens { return &Tokens{store: st} }

// IssueResult is what Issue returns to the caller — including the
// plaintext token, which is shown to the operator ONCE and never
// stored unhashed.
type IssueResult struct {
	Token     *Token
	Plaintext string // "ck_<32 hex chars>" — show to operator once, never re-displayable
}

// Issue creates a new token for userID with the given scopes.
// The plaintext is returned exactly once via IssueResult; the
// daemon stores only a SHA-256 hash (fast + deterministic — bcrypt's
// per-request cost is wrong for tokens since they're presented every
// API call; the secrecy comes from the 128-bit random body).
func (t *Tokens) Issue(ctx context.Context, userID, name string, scopes []Scope, expiresAt *time.Time) (*IssueResult, error) {
	if userID == "" || name == "" || len(scopes) == 0 {
		return nil, errors.New("Issue: userID, name, and at least one scope are required")
	}
	body, err := randomToken(16) // 16 bytes = 32 hex chars = 128 bits of entropy
	if err != nil {
		return nil, err
	}
	plain := TokenPrefix + body
	hashed := hashToken(plain)
	prefix := plain[:11] // "ck_" + first 8 hex chars; enough for visual ID, not enough to verify

	id := uuid.NewString()
	now := time.Now().UTC()
	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return nil, fmt.Errorf("marshal scopes: %w", err)
	}
	var expiresAtCol any
	if expiresAt != nil {
		expiresAtCol = expiresAt.UTC().Format(time.RFC3339)
	} else {
		expiresAtCol = nil
	}
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`INSERT INTO api_tokens (id, user_id, name, token_hash, prefix, scopes, created_at, expires_at)
		 VALUES (%s, %s, %s, %s, %s, %s, %s, %s)`,
		t.ph(1), t.ph(2), t.ph(3), t.ph(4), t.ph(5), t.ph(6), t.ph(7), t.ph(8))
	_, err = t.store.DB().ExecContext(ctx, q,
		id, userID, name, hashed, prefix, string(scopesJSON), now.Format(time.RFC3339), expiresAtCol)
	if err != nil {
		return nil, fmt.Errorf("insert api_token: %w", err)
	}
	result := &IssueResult{
		Token: &Token{
			ID: id, UserID: userID, Name: name, Prefix: prefix,
			Scopes: scopes, CreatedAt: now,
		},
		Plaintext: plain,
	}
	if expiresAt != nil {
		result.Token.ExpiresAt = expiresAt.UTC()
	}
	return result, nil
}

// Verify resolves a presented bearer token to a Token + the owning
// user ID. Hashes the input + compares to token_hash (UNIQUE in the
// schema). Updates last_used_at best-effort. Returns the typed
// sentinels ErrTokenNotFound / ErrTokenExpired / ErrTokenRevoked so
// the middleware picks the right HTTP status.
func (t *Tokens) Verify(ctx context.Context, presented string) (*Token, error) {
	if !strings.HasPrefix(presented, TokenPrefix) {
		return nil, ErrTokenNotFound
	}
	hashed := hashToken(presented)
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, user_id, name, prefix, scopes, created_at, last_used_at, expires_at, revoked_at
		 FROM api_tokens WHERE token_hash = %s`, t.ph(1))
	row := t.store.DB().QueryRowContext(ctx, q, hashed)
	var (
		tok                            Token
		scopesJSON                     string
		createdAt                      string
		lastUsed, expiresAt, revokedAt sql.NullString
	)
	if err := row.Scan(&tok.ID, &tok.UserID, &tok.Name, &tok.Prefix, &scopesJSON,
		&createdAt, &lastUsed, &expiresAt, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("scan api_token: %w", err)
	}
	if err := json.Unmarshal([]byte(scopesJSON), &tok.Scopes); err != nil {
		return nil, fmt.Errorf("decode scopes: %w", err)
	}
	tok.CreatedAt = parseTime(createdAt)
	if lastUsed.Valid {
		tok.LastUsedAt = parseTime(lastUsed.String)
	}
	if revokedAt.Valid {
		tok.RevokedAt = parseTime(revokedAt.String)
		return nil, ErrTokenRevoked
	}
	if expiresAt.Valid {
		tok.ExpiresAt = parseTime(expiresAt.String)
		if time.Now().UTC().After(tok.ExpiresAt) {
			return nil, ErrTokenExpired
		}
	}
	// Best-effort touch — ignore the error.
	touchQ := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`UPDATE api_tokens SET last_used_at = %s WHERE id = %s`, t.ph(1), t.ph(2))
	_, _ = t.store.DB().ExecContext(ctx, touchQ, time.Now().UTC().Format(time.RFC3339), tok.ID)
	return &tok, nil
}

// List returns every (non-revoked) token issued for userID. Doesn't
// include the hash — operators have no use for it post-issue.
func (t *Tokens) List(ctx context.Context, userID string) ([]*Token, error) {
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, name, prefix, scopes, created_at, last_used_at, expires_at, revoked_at
		 FROM api_tokens WHERE user_id = %s ORDER BY created_at DESC`, t.ph(1))
	rows, err := t.store.DB().QueryContext(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("list api_tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Token
	for rows.Next() {
		var (
			tok                            Token
			scopesJSON                     string
			createdAt                      string
			lastUsed, expiresAt, revokedAt sql.NullString
		)
		if err := rows.Scan(&tok.ID, &tok.Name, &tok.Prefix, &scopesJSON,
			&createdAt, &lastUsed, &expiresAt, &revokedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(scopesJSON), &tok.Scopes); err != nil {
			return nil, err
		}
		tok.UserID = userID
		tok.CreatedAt = parseTime(createdAt)
		if lastUsed.Valid {
			tok.LastUsedAt = parseTime(lastUsed.String)
		}
		if expiresAt.Valid {
			tok.ExpiresAt = parseTime(expiresAt.String)
		}
		if revokedAt.Valid {
			tok.RevokedAt = parseTime(revokedAt.String)
		}
		out = append(out, &tok)
	}
	return out, rows.Err()
}

// Revoke marks tokenID as revoked. Idempotent — already-revoked
// returns nil. Subsequent Verify of the same plaintext returns
// ErrTokenRevoked.
func (t *Tokens) Revoke(ctx context.Context, tokenID string) error {
	q := fmt.Sprintf(`UPDATE api_tokens SET revoked_at = %s WHERE id = %s AND revoked_at IS NULL`, t.ph(1), t.ph(2)) //nolint:gosec // placeholders only; no user input
	_, err := t.store.DB().ExecContext(ctx, q, time.Now().UTC().Format(time.RFC3339), tokenID)
	return err
}

func (t *Tokens) ph(n int) string {
	if t.store.Driver() == store.DriverPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

// hashToken returns the hex-encoded SHA-256 of the plaintext token.
// SHA-256 (not bcrypt) is the right choice here because:
//  1. The plaintext is 128 bits of crypto-random — no dictionary
//     attack to defend against. Bcrypt's per-request cost would only
//     slow down legitimate API traffic.
//  2. Verify runs on every API call; a 200 ms bcrypt per request
//     destroys throughput.
//  3. SHA-256 keeps the hash deterministic so the UNIQUE constraint
//     on token_hash actually works (bcrypt produces a different
//     hash on every call).
func hashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// tokenContextKey stashes the verified token in the request context
// for downstream handlers + scope checks.
type tokenContextKey struct{}

// TokenFromContext retrieves the *Token installed by RequireToken.
// Returns nil when the route is unauthenticated or session-auth was
// used instead.
func TokenFromContext(ctx context.Context) *Token {
	t, _ := ctx.Value(tokenContextKey{}).(*Token)
	return t
}

// RequireToken is the middleware that gates a route on a valid
// bearer token. Reads Authorization: Bearer <token>, verifies via
// Tokens.Verify, stashes the token + the owning user in context.
//
// If both RequireAuth and RequireToken are mounted on the same route,
// either path of authentication satisfies it — the handler should
// resolve "who am I" by first checking TokenFromContext, falling
// back to FromContext for session auth.
func (t *Tokens) RequireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		if hdr == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}
		parts := strings.SplitN(hdr, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "Authorization must be Bearer <token>", http.StatusUnauthorized)
			return
		}
		tok, err := t.Verify(r.Context(), parts[1])
		if err != nil {
			switch {
			case errors.Is(err, ErrTokenExpired), errors.Is(err, ErrTokenRevoked), errors.Is(err, ErrTokenNotFound):
				http.Error(w, err.Error(), http.StatusUnauthorized)
			default:
				http.Error(w, "token lookup: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}
		ctx := context.WithValue(r.Context(), tokenContextKey{}, tok)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireScope wraps next in a 403-on-missing-scope check. Pull the
// token from context (RequireToken must have run first); fail loud
// when the token's grants don't cover the route's requirement.
func RequireScope(needed Scope, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := TokenFromContext(r.Context())
		if tok == nil {
			http.Error(w, "RequireScope: no token in context (RequireToken must run first)", http.StatusForbidden)
			return
		}
		if !tok.HasScope(needed) {
			http.Error(w, "missing scope: "+string(needed), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
