package ui

// v1.12 phase 1 — /settings/roles permission matrix UI.
//
// Two pages:
//   GET  /settings/roles              list every role + per-role
//                                     assigned-user count, plus the
//                                     "create new role" form.
//   POST /settings/roles              create a custom role.
//   GET  /settings/roles/{id}         render the permission matrix
//                                     (Resource × Action checkbox grid)
//                                     + the assignment panel.
//   POST /settings/roles/{id}         update the matrix.
//   POST /settings/roles/{id}/delete  delete a custom role (built-in
//                                     are immutable; the route 403s).
//   POST /settings/roles/{id}/users   assign a user to the role.
//   POST /settings/roles/{id}/users/{uid}/remove  revoke the assignment.
//
// Admin-only. Each mutation appends an audit_log row before the
// redirect so the matrix change is replayable.

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	srvrbac "github.com/darpanzope/compliancekit/internal/server/rbac"
	pubrbac "github.com/darpanzope/compliancekit/pkg/compliancekit/rbac"
)

// rolesRepo lazily-constructs the rbac.Store handle.
func (u *UI) rolesRepo() *srvrbac.Store {
	if u.roles == nil {
		u.roles = srvrbac.New(u.store)
	}
	return u.roles
}

// mountRolesRoutes wires the v1.12 phase 1 surface. adminOnly enforces
// the IsAdmin gate (matrix edits stay admin-only until phase 2 wires
// the role-based gate that includes "users:admin").
func (u *UI) mountRolesRoutes(r chi.Router) {
	r.Get("/settings/roles", u.adminOnly(u.rolesList))
	r.Post("/settings/roles", u.adminOnly(u.roleCreate))
	r.Get("/settings/roles/{id}", u.adminOnly(u.roleDetail))
	r.Post("/settings/roles/{id}", u.adminOnly(u.roleUpdate))
	r.Post("/settings/roles/{id}/delete", u.adminOnly(u.roleDelete))
	r.Post("/settings/roles/{id}/users", u.adminOnly(u.roleAssignUser))
	r.Post("/settings/roles/{id}/users/{uid}/remove", u.adminOnly(u.roleRevokeUser))
}

type rolesListView struct {
	View
	Roles []roleRow
	Error string
}

type roleRow struct {
	ID          string
	Name        string
	Description string
	IsBuiltin   bool
	PermCount   int
	UserCount   int
}

// rolesList renders the index page.
func (u *UI) rolesList(w http.ResponseWriter, r *http.Request) {
	roles, err := u.rolesRepo().ListRoles(r.Context())
	if err != nil {
		u.fail(w, "list roles: "+err.Error())
		return
	}
	counts, err := u.roleAssignmentCounts(r.Context())
	if err != nil {
		u.fail(w, "count assignments: "+err.Error())
		return
	}
	rows := make([]roleRow, 0, len(roles))
	for _, role := range roles {
		rows = append(rows, roleRow{
			ID:          role.ID,
			Name:        role.Name,
			Description: role.Description,
			IsBuiltin:   role.IsBuiltin,
			PermCount:   len(role.Permissions),
			UserCount:   counts[role.ID],
		})
	}
	view := rolesListView{
		View:  u.viewFor(r, "Roles & permissions", "settings", View{Flash: r.URL.Query().Get("flash")}),
		Roles: rows,
		Error: r.URL.Query().Get("error"),
	}
	u.render(w, "roles_list.html", view)
}

// roleAssignmentCounts returns map[role_id] = user_count.
func (u *UI) roleAssignmentCounts(ctx context.Context) (map[string]int, error) {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT role_id, COUNT(*) FROM user_roles GROUP BY role_id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make(map[string]int)
	for rows.Next() {
		var roleID string
		var n int
		if err := rows.Scan(&roleID, &n); err != nil {
			return nil, err
		}
		out[roleID] = n
	}
	return out, rows.Err()
}

// roleCreate handles the "new role" form post.
func (u *UI) roleCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	description := strings.TrimSpace(r.FormValue("description"))
	if name == "" {
		http.Redirect(w, r, "/settings/roles?error=missing-name", http.StatusSeeOther)
		return
	}
	role, err := u.rolesRepo().CreateRole(r.Context(), name, description, nil)
	if err != nil {
		http.Redirect(w, r, "/settings/roles?error="+errSlug(err), http.StatusSeeOther)
		return
	}
	u.AuditLog(r.Context(), "role.create", "role", role.ID, map[string]any{"name": name})
	http.Redirect(w, r, "/settings/roles/"+role.ID+"?flash=created", http.StatusSeeOther)
}

type roleDetailView struct {
	View
	Role        *pubrbac.Role
	Members     []roleMember
	AllUsers    []pickerOption
	Resources   []pubrbac.Resource
	Actions     []pubrbac.Action
	GrantLookup map[string]bool // "resource:action" → granted
	Error       string
}

type roleMember struct {
	ID    string
	Email string
	Name  string
}

// roleDetail renders the matrix + assignment panel.
func (u *UI) roleDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	role, err := u.rolesRepo().ByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	grants := make(map[string]bool, len(role.Permissions))
	for _, p := range role.Permissions {
		grants[string(p.Resource)+":"+string(p.Action)] = true
	}
	members, err := u.roleMembers(r.Context(), id)
	if err != nil {
		u.fail(w, "list members: "+err.Error())
		return
	}
	memberIDs := make(map[string]bool, len(members))
	for _, m := range members {
		memberIDs[m.ID] = true
	}
	allUsers := u.pickerOptions(r.Context())
	picker := make([]pickerOption, 0, len(allUsers))
	for _, opt := range allUsers {
		if memberIDs[opt.ID] {
			continue
		}
		picker = append(picker, opt)
	}
	view := roleDetailView{
		View:        u.viewFor(r, "Role — "+role.Name, "settings", View{Flash: r.URL.Query().Get("flash")}),
		Role:        role,
		Members:     members,
		AllUsers:    picker,
		Resources:   pubrbac.AllResources,
		Actions:     pubrbac.AllActions,
		GrantLookup: grants,
		Error:       r.URL.Query().Get("error"),
	}
	u.render(w, "roles_detail.html", view)
}

func (u *UI) roleMembers(ctx context.Context, roleID string) ([]roleMember, error) {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT u.id, u.email, COALESCE(u.display_name,'')
		 FROM user_roles ur JOIN users u ON u.id = ur.user_id
		 WHERE ur.role_id = `+ph(u.store, 1)+
			` ORDER BY COALESCE(NULLIF(u.display_name,''), u.email)`,
		roleID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []roleMember
	for rows.Next() {
		var m roleMember
		if err := rows.Scan(&m.ID, &m.Email, &m.Name); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// roleUpdate accepts the matrix POST. Form carries one checkbox per
// (resource, action) tuple named "perm[resource:action]" — every
// checked box becomes a Permission row.
func (u *UI) roleUpdate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	role, err := u.rolesRepo().ByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if role.IsBuiltin {
		http.Redirect(w, r, "/settings/roles/"+id+"?error=builtin-immutable", http.StatusSeeOther)
		return
	}
	var perms []pubrbac.Permission
	for _, res := range pubrbac.AllResources {
		for _, act := range pubrbac.AllActions {
			if r.FormValue("perm["+string(res)+":"+string(act)+"]") != "" {
				perms = append(perms, pubrbac.Permission{Resource: res, Action: act})
			}
		}
	}
	if err := u.rolesRepo().UpdatePermissions(r.Context(), id, perms); err != nil {
		http.Redirect(w, r, "/settings/roles/"+id+"?error="+errSlug(err), http.StatusSeeOther)
		return
	}
	u.AuditLog(r.Context(), "role.update", "role", id, map[string]any{"perm_count": len(perms)})
	http.Redirect(w, r, "/settings/roles/"+id+"?flash=saved", http.StatusSeeOther)
}

// roleDelete removes a custom role.
func (u *UI) roleDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := u.rolesRepo().DeleteRole(r.Context(), id); err != nil {
		http.Redirect(w, r, "/settings/roles?error="+errSlug(err), http.StatusSeeOther)
		return
	}
	u.AuditLog(r.Context(), "role.delete", "role", id, nil)
	http.Redirect(w, r, "/settings/roles?flash=deleted", http.StatusSeeOther)
}

// roleAssignUser binds a user to the role.
func (u *UI) roleAssignUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	userID := strings.TrimSpace(r.FormValue("user_id"))
	if userID == "" {
		http.Redirect(w, r, "/settings/roles/"+id+"?error=missing-user", http.StatusSeeOther)
		return
	}
	grantedBy := ""
	if sess := auth.FromContext(r.Context()); sess != nil {
		grantedBy = sess.UserID
	}
	if err := u.rolesRepo().AssignRole(r.Context(), userID, id, grantedBy); err != nil {
		http.Redirect(w, r, "/settings/roles/"+id+"?error="+errSlug(err), http.StatusSeeOther)
		return
	}
	u.AuditLog(r.Context(), "role.assign", "role", id, map[string]any{"user_id": userID})
	http.Redirect(w, r, "/settings/roles/"+id+"?flash=assigned", http.StatusSeeOther)
}

// roleRevokeUser drops the assignment.
func (u *UI) roleRevokeUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	uid := chi.URLParam(r, "uid")
	if err := u.rolesRepo().RevokeRole(r.Context(), uid, id); err != nil {
		http.Redirect(w, r, "/settings/roles/"+id+"?error="+errSlug(err), http.StatusSeeOther)
		return
	}
	u.AuditLog(r.Context(), "role.revoke", "role", id, map[string]any{"user_id": uid})
	http.Redirect(w, r, "/settings/roles/"+id+"?flash=revoked", http.StatusSeeOther)
}

// errSlug returns a stable URL-safe error code derived from the
// sentinel. Falls back to "internal".
func errSlug(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, srvrbac.ErrBuiltinRoleImmutable):
		return "builtin-immutable"
	case errors.Is(err, srvrbac.ErrRoleNotFound):
		return "not-found"
	}
	msg := err.Error()
	if strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "duplicate key") {
		return "name-taken"
	}
	return "internal"
}
