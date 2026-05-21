// Package rbac is the v1.12+ public surface for the daemon's
// role-based access control model. The types here describe the
// resource/action grid + the role assignment shape — they intentionally
// do not commit to a particular storage layout. Embedders inspect or
// compose roles programmatically; the daemon UI authors them via the
// permission matrix at /settings/roles.
//
// Like every type in pkg/compliancekit, this surface is covered by
// SemVer 2.0 and the api.txt CI gate. Additive changes only inside the
// v1.x line per ADR-014.
package rbac

import "time"

// Resource names one of the gated resources in the daemon. The set is
// closed — adding a new resource is a SemVer-significant change
// because operators may have written custom-role rows referencing the
// existing names.
type Resource string

// Resource constants. The CHECK constraint in migration 0018 enforces
// the same list at storage time so a typo in a custom-role row fails
// fast at INSERT instead of silently never matching at gate time.
const (
	ResourceScans      Resource = "scans"
	ResourceFindings   Resource = "findings"
	ResourceSettings   Resource = "settings"
	ResourceUsers      Resource = "users"
	ResourceAPITokens  Resource = "api_tokens"
	ResourcePlugins    Resource = "plugins"
	ResourceAuditLog   Resource = "audit_log"
	ResourceRules      Resource = "rules"
	ResourceWaivers    Resource = "waivers"
	ResourceFrameworks Resource = "frameworks"
	ResourceComments   Resource = "comments"
)

// AllResources is the canonical iteration order for the permission
// matrix UI columns. New resources append; reordering is a behavior
// change for any UI snapshot test that pins column order.
var AllResources = []Resource{
	ResourceScans,
	ResourceFindings,
	ResourceSettings,
	ResourceUsers,
	ResourceAPITokens,
	ResourcePlugins,
	ResourceAuditLog,
	ResourceRules,
	ResourceWaivers,
	ResourceFrameworks,
	ResourceComments,
}

// Action names the verb-side of a permission tuple. Read covers
// every list / get / search endpoint; Write covers create + update;
// Delete is the only verb separated from Write because operators
// regularly want "edit-but-can't-delete" custom roles.
//
// Admin is the per-resource superpower bit — covers everything plus
// resource-specific privileged operations (e.g. rotating tokens,
// restoring backups, configuring a SAML connection).
type Action string

// Action constants.
const (
	ActionRead   Action = "read"
	ActionWrite  Action = "write"
	ActionDelete Action = "delete"
	ActionAdmin  Action = "admin"
)

// AllActions is the canonical iteration order for the permission
// matrix UI rows.
var AllActions = []Action{
	ActionRead,
	ActionWrite,
	ActionDelete,
	ActionAdmin,
}

// Permission is a single (Resource, Action) grant inside a Role.
// The empty struct is meaningless; callers always populate both.
type Permission struct {
	Resource Resource `json:"resource"`
	Action   Action   `json:"action"`
}

// Role is the operator-authored unit of authorization. Built-in
// roles (admin/editor/viewer/auditor) carry IsBuiltin = true and
// cannot be deleted; their Permissions list is fixed by the
// migration seed.
type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	IsBuiltin   bool         `json:"is_builtin"`
	Permissions []Permission `json:"permissions"`
	CreatedAt   time.Time    `json:"created_at,omitempty"`
	UpdatedAt   time.Time    `json:"updated_at,omitempty"`
}

// Built-in role names. Operators see these in the UI and may target
// them in IaC; they are stable across the v1.x line.
const (
	BuiltinAdmin   = "admin"
	BuiltinEditor  = "editor"
	BuiltinViewer  = "viewer"
	BuiltinAuditor = "auditor"
)

// Has reports whether r grants the (resource, action) tuple.
// The admin role short-circuits via wildcard — anyone holding it is
// authorized everywhere — but the encoding is explicit: r's
// Permissions list contains every tuple it grants.
func (r *Role) Has(res Resource, act Action) bool {
	for _, p := range r.Permissions {
		if p.Resource == res && p.Action == act {
			return true
		}
	}
	return false
}

// Assignment is one row in user_roles — a (user_id, role_id) edge in
// the assignment graph. Operators rarely consume this type directly;
// it's exposed so audit-log emitters and SCIM provisioning can render
// stable shapes.
type Assignment struct {
	UserID    string    `json:"user_id"`
	RoleID    string    `json:"role_id"`
	RoleName  string    `json:"role_name,omitempty"`
	GrantedAt time.Time `json:"granted_at"`
	GrantedBy string    `json:"granted_by,omitempty"`
}

// Set is the resolved permission set for a single user — every grant
// reachable via any of their assigned roles, deduped. Callers gate
// requests via Set.Has(...) instead of walking the underlying
// assignments at every check.
type Set struct {
	UserID string
	Grants map[Resource]map[Action]struct{}
}

// NewSet returns an empty Set bound to userID.
func NewSet(userID string) *Set {
	return &Set{UserID: userID, Grants: make(map[Resource]map[Action]struct{})}
}

// Add records a (resource, action) grant on s. Safe to call with the
// same tuple repeatedly — Grants is a set semantically.
func (s *Set) Add(res Resource, act Action) {
	row, ok := s.Grants[res]
	if !ok {
		row = make(map[Action]struct{})
		s.Grants[res] = row
	}
	row[act] = struct{}{}
}

// Has reports whether s carries the (resource, action) grant.
// Returns false on the zero-value Set (no panics).
func (s *Set) Has(res Resource, act Action) bool {
	if s == nil || s.Grants == nil {
		return false
	}
	row, ok := s.Grants[res]
	if !ok {
		return false
	}
	_, ok = row[act]
	return ok
}

// HasAny reports whether s carries ANY action on the given resource.
// Used by route gates that want to allow "anyone with visibility into
// the resource" through (e.g. the resource detail page).
func (s *Set) HasAny(res Resource) bool {
	if s == nil || s.Grants == nil {
		return false
	}
	row, ok := s.Grants[res]
	return ok && len(row) > 0
}
