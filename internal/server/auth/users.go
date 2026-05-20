package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// User is the in-memory shape returned by Users.ByEmail + ByID.
type User struct {
	ID           string
	Email        string
	DisplayName  string
	PasswordHash string // empty for OIDC-only accounts
	OIDCSubject  string // empty for local-only accounts
	OIDCProvider string // empty for local-only accounts
	IsAdmin      bool
	CreatedAt    time.Time
	LastLoginAt  time.Time
}

// ErrUserNotFound is returned by ByEmail / ByID when no row matches.
// Distinct from a query error so handlers can produce the right HTTP
// status without leaking the difference between "wrong email" + DB
// glitch.
var ErrUserNotFound = errors.New("user not found")

// ErrEmailAlreadyTaken is returned by Create when a row already
// exists for the given email.
var ErrEmailAlreadyTaken = errors.New("email already taken")

// Users is the persistence layer for the users table. Kept tiny in
// phase 3 — phase 11 (UI shell) + v1.4 settings page add the full
// CRUD surface.
type Users struct {
	store *store.Store
}

// NewUsers returns a Users handle bound to st.
func NewUsers(st *store.Store) *Users { return &Users{store: st} }

// Create inserts a new local-auth user with the given email + plain
// password (the password is hashed via HashPassword before storage).
// Returns the persisted User. isAdmin grants admin rights.
func (u *Users) Create(ctx context.Context, email, displayName, password string, isAdmin bool) (*User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil, errors.New("email is required")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`INSERT INTO users (id, email, display_name, password_hash, is_admin, created_at)
		 VALUES (%s, %s, %s, %s, %s, %s)`,
		u.ph(1), u.ph(2), u.ph(3), u.ph(4), u.ph(5), u.ph(6))
	_, err = u.store.DB().ExecContext(ctx, q, id, email, displayName, hash, boolToInt(isAdmin), now.Format(time.RFC3339))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrEmailAlreadyTaken
		}
		return nil, fmt.Errorf("insert user: %w", err)
	}
	return &User{
		ID:           id,
		Email:        email,
		DisplayName:  displayName,
		PasswordHash: hash,
		IsAdmin:      isAdmin,
		CreatedAt:    now,
	}, nil
}

// ByEmail looks up a user by exact (case-folded) email.
func (u *Users) ByEmail(ctx context.Context, email string) (*User, error) {
	return u.scanOne(ctx, fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, email, display_name, password_hash, oidc_subject, oidc_provider, is_admin, created_at, last_login_at
		 FROM users WHERE email = %s`, u.ph(1)),
		strings.ToLower(strings.TrimSpace(email)))
}

// ByID looks up a user by primary key.
func (u *Users) ByID(ctx context.Context, id string) (*User, error) {
	return u.scanOne(ctx, fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, email, display_name, password_hash, oidc_subject, oidc_provider, is_admin, created_at, last_login_at
		 FROM users WHERE id = %s`, u.ph(1)), id)
}

// All returns every user in the directory, ordered by display_name
// then email. v1.8 phase 2 — drives the assignee dropdown + the
// resource-owner picker. Cap at 500 rows; daemon admin uses a more
// targeted query if the directory ever grows past that.
func (u *Users) All(ctx context.Context) ([]*User, error) {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT id, email, COALESCE(display_name,''), is_admin
		 FROM users
		 ORDER BY COALESCE(NULLIF(display_name,''), email)
		 LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*User
	for rows.Next() {
		var (
			us      User
			isAdmin int
		)
		if err := rows.Scan(&us.ID, &us.Email, &us.DisplayName, &isAdmin); err != nil {
			return nil, err
		}
		us.IsAdmin = isAdmin != 0
		out = append(out, &us)
	}
	return out, rows.Err()
}

// TouchLastLogin updates last_login_at for the user. Best-effort —
// callers ignore the error; a missed update doesn't break login.
func (u *Users) TouchLastLogin(ctx context.Context, id string) error {
	q := fmt.Sprintf(`UPDATE users SET last_login_at = %s WHERE id = %s`, u.ph(1), u.ph(2)) //nolint:gosec // placeholders only; no user input
	_, err := u.store.DB().ExecContext(ctx, q, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

func (u *Users) scanOne(ctx context.Context, q string, args ...any) (*User, error) {
	row := u.store.DB().QueryRowContext(ctx, q, args...)
	var (
		out                                                     User
		displayName, hash, oidcSubject, oidcProvider, lastLogin sql.NullString
		isAdmin                                                 int
		createdAt                                               string
	)
	if err := row.Scan(&out.ID, &out.Email, &displayName, &hash, &oidcSubject, &oidcProvider, &isAdmin, &createdAt, &lastLogin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("scan user: %w", err)
	}
	out.DisplayName = displayName.String
	out.PasswordHash = hash.String
	out.OIDCSubject = oidcSubject.String
	out.OIDCProvider = oidcProvider.String
	out.IsAdmin = isAdmin != 0
	out.CreatedAt = parseTime(createdAt)
	if lastLogin.Valid {
		out.LastLoginAt = parseTime(lastLogin.String)
	}
	return &out, nil
}

func (u *Users) ph(n int) string {
	if u.store.Driver() == store.DriverPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// isUniqueViolation detects the dialect-specific "UNIQUE constraint
// failed" / "duplicate key" error so Create can return
// ErrEmailAlreadyTaken instead of a generic "insert user: ..." wrap.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || // sqlite
		strings.Contains(msg, "duplicate key value violates") // postgres
}
