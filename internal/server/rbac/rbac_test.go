package rbac

import (
	"context"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
	pubrbac "github.com/darpanzope/compliancekit/pkg/compliancekit/rbac"
)

// newTestStore opens an in-memory SQLite store + applies every
// migration up through 0018.
func newTestStore(t *testing.T) (*store.Store, *Store, func()) {
	t.Helper()
	st, err := store.OpenSQLite(context.Background(), "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	if err := st.MigrateUp(context.Background()); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	return st, New(st), func() { _ = st.Close() }
}

func TestBuiltinRolesSeeded(t *testing.T) {
	_, s, cleanup := newTestStore(t)
	defer cleanup()
	roles, err := s.ListRoles(context.Background())
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	want := map[string]bool{
		pubrbac.BuiltinAdmin: true, pubrbac.BuiltinEditor: true,
		pubrbac.BuiltinViewer: true, pubrbac.BuiltinAuditor: true,
	}
	for _, r := range roles {
		if !r.IsBuiltin {
			continue
		}
		if !want[r.Name] {
			t.Errorf("unexpected built-in role %q", r.Name)
		}
		delete(want, r.Name)
	}
	if len(want) != 0 {
		t.Errorf("missing built-in roles: %v", want)
	}
	// admin should have a grant on every (Resource, Action) tuple.
	admin, err := s.ByName(context.Background(), pubrbac.BuiltinAdmin)
	if err != nil {
		t.Fatalf("ByName admin: %v", err)
	}
	for _, res := range pubrbac.AllResources {
		for _, act := range pubrbac.AllActions {
			if !admin.Has(res, act) {
				t.Errorf("admin should grant %s:%s", res, act)
			}
		}
	}
	// viewer should never grant write/delete/admin.
	viewer, err := s.ByName(context.Background(), pubrbac.BuiltinViewer)
	if err != nil {
		t.Fatalf("ByName viewer: %v", err)
	}
	for _, p := range viewer.Permissions {
		if p.Action != pubrbac.ActionRead {
			t.Errorf("viewer carried non-read action %s:%s", p.Resource, p.Action)
		}
	}
}

func TestCustomRoleLifecycle(t *testing.T) {
	st, s, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()

	// Need a user to assign to.
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO users (id, email, display_name, is_admin, created_at) VALUES (?, ?, ?, 0, ?)`,
		"u-1", "alice@example.com", "Alice", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	r, err := s.CreateRole(ctx, "auditor-eu", "EU-region auditor", []pubrbac.Permission{
		{Resource: pubrbac.ResourceFindings, Action: pubrbac.ActionRead},
		{Resource: pubrbac.ResourceAuditLog, Action: pubrbac.ActionRead},
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if r.IsBuiltin {
		t.Errorf("custom role should not be marked builtin")
	}

	// Built-in name should be rejected.
	if _, err := s.CreateRole(ctx, pubrbac.BuiltinAdmin, "x", nil); err == nil {
		t.Errorf("CreateRole with builtin name should fail")
	}

	// Update perms.
	if err := s.UpdatePermissions(ctx, r.ID, []pubrbac.Permission{
		{Resource: pubrbac.ResourceFindings, Action: pubrbac.ActionRead},
	}); err != nil {
		t.Fatalf("UpdatePermissions: %v", err)
	}
	got, err := s.ByID(ctx, r.ID)
	if err != nil {
		t.Fatalf("ByID after Update: %v", err)
	}
	if len(got.Permissions) != 1 {
		t.Errorf("expected 1 perm after update, got %d", len(got.Permissions))
	}

	// Assign + verify.
	if err := s.AssignRole(ctx, "u-1", r.ID, ""); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	// idempotent re-assign.
	if err := s.AssignRole(ctx, "u-1", r.ID, ""); err != nil {
		t.Fatalf("AssignRole (idempotent): %v", err)
	}
	set, err := s.PermissionSetForUser(ctx, "u-1")
	if err != nil {
		t.Fatalf("PermissionSetForUser: %v", err)
	}
	if !set.Has(pubrbac.ResourceFindings, pubrbac.ActionRead) {
		t.Errorf("user should carry findings:read after assignment")
	}
	if set.Has(pubrbac.ResourceFindings, pubrbac.ActionWrite) {
		t.Errorf("user should NOT carry findings:write")
	}

	// Revoke.
	if err := s.RevokeRole(ctx, "u-1", r.ID); err != nil {
		t.Fatalf("RevokeRole: %v", err)
	}
	set, _ = s.PermissionSetForUser(ctx, "u-1")
	if set.HasAny(pubrbac.ResourceFindings) {
		t.Errorf("user grants should be empty after revoke")
	}

	// Built-in role cannot be deleted.
	admin, _ := s.ByName(ctx, pubrbac.BuiltinAdmin)
	if err := s.DeleteRole(ctx, admin.ID); err != ErrBuiltinRoleImmutable {
		t.Errorf("DeleteRole on built-in should return ErrBuiltinRoleImmutable, got %v", err)
	}
	// Custom role can be deleted.
	if err := s.DeleteRole(ctx, r.ID); err != nil {
		t.Fatalf("DeleteRole custom: %v", err)
	}
	if _, err := s.ByID(ctx, r.ID); err != ErrRoleNotFound {
		t.Errorf("expected ErrRoleNotFound after delete, got %v", err)
	}
}

func TestAdminBackfillFromIsAdmin(t *testing.T) {
	st, s, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	// users seeded with is_admin=1 at migration time should already
	// hold the admin role. Insert one mid-migration would be more
	// rigorous, but the migration itself is the contract; this test
	// verifies a freshly-inserted user with is_admin=1 does NOT auto-
	// grant (that path requires a registration flow to call
	// AssignRole — the migration only backfills *existing* rows).
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO users (id, email, display_name, is_admin, created_at) VALUES (?, ?, ?, 1, ?)`,
		"u-new-admin", "new-admin@example.com", "New", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	set, err := s.PermissionSetForUser(ctx, "u-new-admin")
	if err != nil {
		t.Fatalf("PermissionSetForUser: %v", err)
	}
	if set.HasAny(pubrbac.ResourceSettings) {
		t.Errorf("post-migration is_admin=1 user should not auto-acquire admin role; that's the registration flow's job")
	}
}
