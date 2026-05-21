// Package rbac is the v1.12 phase 0 daemon-side persistence + lookup
// layer for the role/permission grid defined in
// pkg/compliancekit/rbac. The public-pkg types describe the shape;
// this package owns the SQL.
//
// The store is intentionally small in phase 0 — list roles, list a
// user's grants, list every role's permissions — because phase 1
// (matrix UI) and phase 2 (scope-gate refactor) layer on top without
// needing role mutation. Custom-role mutation lands in phase 1 once
// the UI exists to drive it.
package rbac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/darpanzope/compliancekit/internal/server/store"
	pubrbac "github.com/darpanzope/compliancekit/pkg/compliancekit/rbac"
)

// ErrRoleNotFound is returned by ByID + ByName when the requested
// role doesn't exist.
var ErrRoleNotFound = errors.New("role not found")

// ErrBuiltinRoleImmutable is returned by Update / Delete when the
// target is a built-in role.
var ErrBuiltinRoleImmutable = errors.New("built-in role cannot be modified")

// Store is the SQL-side handle bound to the daemon's *store.Store.
type Store struct {
	store *store.Store
}

// New returns a Store handle.
func New(st *store.Store) *Store { return &Store{store: st} }

// ListRoles returns every role in the directory, sorted by builtin-
// first then name. Each row carries its permission list pre-loaded
// so a single call powers the matrix UI without N+1 queries.
func (s *Store) ListRoles(ctx context.Context) ([]*pubrbac.Role, error) {
	rows, err := s.store.DB().QueryContext(ctx,
		`SELECT id, name, description, is_builtin, created_at, updated_at
		 FROM roles
		 ORDER BY is_builtin DESC, name`)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*pubrbac.Role
	idIndex := make(map[string]int)
	for rows.Next() {
		var (
			r           pubrbac.Role
			isBuiltin   int
			createdAt   string
			updatedAt   string
			description sql.NullString
		)
		if err := rows.Scan(&r.ID, &r.Name, &description, &isBuiltin, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		r.Description = description.String
		r.IsBuiltin = isBuiltin != 0
		r.CreatedAt = parseTime(createdAt)
		r.UpdatedAt = parseTime(updatedAt)
		idIndex[r.ID] = len(out)
		out = append(out, &r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	// Backfill permissions in one round-trip.
	permRows, err := s.store.DB().QueryContext(ctx,
		`SELECT role_id, resource, action FROM role_permissions ORDER BY role_id, resource, action`)
	if err != nil {
		return nil, fmt.Errorf("list role_permissions: %w", err)
	}
	defer func() { _ = permRows.Close() }()
	for permRows.Next() {
		var roleID, resource, action string
		if err := permRows.Scan(&roleID, &resource, &action); err != nil {
			return nil, err
		}
		idx, ok := idIndex[roleID]
		if !ok {
			continue
		}
		out[idx].Permissions = append(out[idx].Permissions, pubrbac.Permission{
			Resource: pubrbac.Resource(resource),
			Action:   pubrbac.Action(action),
		})
	}
	return out, permRows.Err()
}

// ByID looks up a single role + its permissions.
func (s *Store) ByID(ctx context.Context, id string) (*pubrbac.Role, error) {
	row := s.store.DB().QueryRowContext(ctx, fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, name, description, is_builtin, created_at, updated_at FROM roles WHERE id = %s`, s.ph(1)), id)
	r, err := scanRole(row)
	if err != nil {
		return nil, err
	}
	perms, err := s.permissionsFor(ctx, id)
	if err != nil {
		return nil, err
	}
	r.Permissions = perms
	return r, nil
}

// ByName looks up a role by its unique name (typically used for
// "find the admin role").
func (s *Store) ByName(ctx context.Context, name string) (*pubrbac.Role, error) {
	row := s.store.DB().QueryRowContext(ctx, fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, name, description, is_builtin, created_at, updated_at FROM roles WHERE name = %s`, s.ph(1)), name)
	r, err := scanRole(row)
	if err != nil {
		return nil, err
	}
	perms, err := s.permissionsFor(ctx, r.ID)
	if err != nil {
		return nil, err
	}
	r.Permissions = perms
	return r, nil
}

// CreateRole inserts a new custom role. Built-in role names ("admin"
// / "editor" / "viewer" / "auditor") are reserved — attempting to
// create one returns ErrBuiltinRoleImmutable. Permissions slice may
// be empty; later UpdatePermissions populates it.
func (s *Store) CreateRole(ctx context.Context, name, description string, perms []pubrbac.Permission) (*pubrbac.Role, error) {
	if isBuiltinName(name) {
		return nil, ErrBuiltinRoleImmutable
	}
	id := "role-" + uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`INSERT INTO roles (id, name, description, is_builtin, created_at, updated_at) VALUES (%s, %s, %s, 0, %s, %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5)),
		id, name, description, now, now); err != nil {
		return nil, fmt.Errorf("insert role: %w", err)
	}
	for _, p := range perms {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf( //nolint:gosec // placeholders only; no user input
			`INSERT INTO role_permissions (role_id, resource, action) VALUES (%s, %s, %s)`,
			s.ph(1), s.ph(2), s.ph(3)),
			id, string(p.Resource), string(p.Action)); err != nil {
			return nil, fmt.Errorf("insert role_permission: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &pubrbac.Role{
		ID:          id,
		Name:        name,
		Description: description,
		IsBuiltin:   false,
		Permissions: perms,
		CreatedAt:   parseTime(now),
		UpdatedAt:   parseTime(now),
	}, nil
}

// UpdatePermissions replaces the permission grid for a custom role.
// Atomically deletes the existing rows + inserts the new set. Built-
// in roles are immutable.
func (s *Store) UpdatePermissions(ctx context.Context, roleID string, perms []pubrbac.Permission) error {
	r, err := s.ByID(ctx, roleID)
	if err != nil {
		return err
	}
	if r.IsBuiltin {
		return ErrBuiltinRoleImmutable
	}
	tx, err := s.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`DELETE FROM role_permissions WHERE role_id = %s`, s.ph(1)), roleID); err != nil {
		return fmt.Errorf("delete role_permissions: %w", err)
	}
	for _, p := range perms {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf( //nolint:gosec // placeholders only; no user input
			`INSERT INTO role_permissions (role_id, resource, action) VALUES (%s, %s, %s)`,
			s.ph(1), s.ph(2), s.ph(3)),
			roleID, string(p.Resource), string(p.Action)); err != nil {
			return fmt.Errorf("insert role_permission: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`UPDATE roles SET updated_at = %s WHERE id = %s`, s.ph(1), s.ph(2)),
		time.Now().UTC().Format(time.RFC3339), roleID); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteRole removes a custom role + its assignments + permissions
// (cascaded). Built-in roles are immutable.
func (s *Store) DeleteRole(ctx context.Context, roleID string) error {
	r, err := s.ByID(ctx, roleID)
	if err != nil {
		return err
	}
	if r.IsBuiltin {
		return ErrBuiltinRoleImmutable
	}
	_, err = s.store.DB().ExecContext(ctx, fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`DELETE FROM roles WHERE id = %s`, s.ph(1)), roleID)
	return err
}

// AssignRole grants roleID to userID. Idempotent — re-granting the
// same assignment is a no-op (relies on the PRIMARY KEY).
func (s *Store) AssignRole(ctx context.Context, userID, roleID, grantedBy string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	var grantedByCol any
	if grantedBy != "" {
		grantedByCol = grantedBy
	}
	var q string
	if s.store.Driver() == store.DriverPostgres {
		q = `INSERT INTO user_roles (user_id, role_id, granted_at, granted_by_user_id)
		     VALUES ($1, $2, $3, $4)
		     ON CONFLICT (user_id, role_id) DO NOTHING`
	} else {
		q = `INSERT OR IGNORE INTO user_roles (user_id, role_id, granted_at, granted_by_user_id)
		     VALUES (?, ?, ?, ?)`
	}
	_, err := s.store.DB().ExecContext(ctx, q, userID, roleID, now, grantedByCol)
	return err
}

// RevokeRole removes the (userID, roleID) assignment.
func (s *Store) RevokeRole(ctx context.Context, userID, roleID string) error {
	_, err := s.store.DB().ExecContext(ctx, fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`DELETE FROM user_roles WHERE user_id = %s AND role_id = %s`,
		s.ph(1), s.ph(2)), userID, roleID)
	return err
}

// RolesForUser returns every role assigned to userID, each with its
// permissions populated.
func (s *Store) RolesForUser(ctx context.Context, userID string) ([]*pubrbac.Role, error) {
	rows, err := s.store.DB().QueryContext(ctx, fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT r.id, r.name, r.description, r.is_builtin, r.created_at, r.updated_at
		 FROM roles r
		 JOIN user_roles ur ON ur.role_id = r.id
		 WHERE ur.user_id = %s
		 ORDER BY r.is_builtin DESC, r.name`, s.ph(1)), userID)
	if err != nil {
		return nil, fmt.Errorf("roles for user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*pubrbac.Role
	for rows.Next() {
		var (
			r           pubrbac.Role
			isBuiltin   int
			createdAt   string
			updatedAt   string
			description sql.NullString
		)
		if err := rows.Scan(&r.ID, &r.Name, &description, &isBuiltin, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		r.Description = description.String
		r.IsBuiltin = isBuiltin != 0
		r.CreatedAt = parseTime(createdAt)
		r.UpdatedAt = parseTime(updatedAt)
		out = append(out, &r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, r := range out {
		perms, err := s.permissionsFor(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		r.Permissions = perms
	}
	return out, nil
}

// PermissionSetForUser resolves the user's complete grant set by
// walking every assigned role + unioning permissions. Returns an
// empty Set when the user has no role assignments.
func (s *Store) PermissionSetForUser(ctx context.Context, userID string) (*pubrbac.Set, error) {
	rows, err := s.store.DB().QueryContext(ctx, fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT rp.resource, rp.action
		 FROM role_permissions rp
		 JOIN user_roles ur ON ur.role_id = rp.role_id
		 WHERE ur.user_id = %s`, s.ph(1)), userID)
	if err != nil {
		return nil, fmt.Errorf("permission set for user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := pubrbac.NewSet(userID)
	for rows.Next() {
		var resource, action string
		if err := rows.Scan(&resource, &action); err != nil {
			return nil, err
		}
		out.Add(pubrbac.Resource(resource), pubrbac.Action(action))
	}
	return out, rows.Err()
}

func (s *Store) permissionsFor(ctx context.Context, roleID string) ([]pubrbac.Permission, error) {
	rows, err := s.store.DB().QueryContext(ctx, fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT resource, action FROM role_permissions WHERE role_id = %s ORDER BY resource, action`,
		s.ph(1)), roleID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []pubrbac.Permission
	for rows.Next() {
		var resource, action string
		if err := rows.Scan(&resource, &action); err != nil {
			return nil, err
		}
		out = append(out, pubrbac.Permission{
			Resource: pubrbac.Resource(resource),
			Action:   pubrbac.Action(action),
		})
	}
	return out, rows.Err()
}

func scanRole(row *sql.Row) (*pubrbac.Role, error) {
	var (
		r           pubrbac.Role
		isBuiltin   int
		createdAt   string
		updatedAt   string
		description sql.NullString
	)
	if err := row.Scan(&r.ID, &r.Name, &description, &isBuiltin, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("scan role: %w", err)
	}
	r.Description = description.String
	r.IsBuiltin = isBuiltin != 0
	r.CreatedAt = parseTime(createdAt)
	r.UpdatedAt = parseTime(updatedAt)
	return &r, nil
}

func (s *Store) ph(n int) string {
	if s.store.Driver() == store.DriverPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func isBuiltinName(name string) bool {
	switch name {
	case pubrbac.BuiltinAdmin, pubrbac.BuiltinEditor, pubrbac.BuiltinViewer, pubrbac.BuiltinAuditor:
		return true
	}
	return false
}
