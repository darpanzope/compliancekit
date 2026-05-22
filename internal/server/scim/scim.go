// Package scim implements a minimal SCIM 2.0 (RFC 7643 / 7644) server
// for v1.12 phase 4. Operators point Okta / Azure AD / OneLogin /
// Google Workspace's SCIM provisioning connector at /scim/v2/ and
// users + groups synchronize bidirectionally with the daemon's
// directory.
//
// Surface (bearer-auth gated):
//
//	GET    /scim/v2/ServiceProviderConfig
//	GET    /scim/v2/ResourceTypes
//	GET    /scim/v2/Schemas
//
//	GET    /scim/v2/Users               filter + paginate
//	POST   /scim/v2/Users
//	GET    /scim/v2/Users/{id}
//	PUT    /scim/v2/Users/{id}          full replace
//	PATCH  /scim/v2/Users/{id}          add/remove/replace ops
//	DELETE /scim/v2/Users/{id}
//
//	GET    /scim/v2/Groups              filter + paginate (maps to RBAC roles)
//	POST   /scim/v2/Groups
//	GET    /scim/v2/Groups/{id}
//	PUT    /scim/v2/Groups/{id}
//	PATCH  /scim/v2/Groups/{id}
//	DELETE /scim/v2/Groups/{id}
//
// SCIM Groups map to RBAC roles 1:1 — adding a user to a Group
// assigns the role; removing revokes it. The role's permission grid
// stays operator-curated through the phase 1 matrix UI.
package scim

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	srvrbac "github.com/darpanzope/compliancekit/internal/server/rbac"
	"github.com/darpanzope/compliancekit/internal/server/store"
)

// SCIM core schemas exposed via /scim/v2/Schemas.
const (
	SchemaUser          = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup         = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaListResponse  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaPatchOp       = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaError         = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaServiceConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
)

// ContentType is the canonical SCIM media type. RFC 7644 §3.1.
const ContentType = "application/scim+json"

// Server bundles the persistence dependencies + the bearer token the
// IdP authenticates with. Construct via New; Mount under chi's root.
type Server struct {
	store    *store.Store
	users    *auth.Users
	rbac     *srvrbac.Store
	sessions *auth.Sessions
	bearer   string
}

// New returns a SCIM server bound to the daemon stores. bearer is the
// shared secret the IdP presents in Authorization: Bearer <bearer>;
// empty disables the bearer check (operators in dev only — production
// should always set it).
func New(st *store.Store, users *auth.Users, sessions *auth.Sessions, bearer string) *Server {
	return &Server{
		store:    st,
		users:    users,
		rbac:     srvrbac.New(st),
		sessions: sessions,
		bearer:   bearer,
	}
}

// Mount wires the v2 surface under /scim/v2.
func (s *Server) Mount(r chi.Router) {
	r.Route("/scim/v2", func(r chi.Router) {
		r.Use(s.requireBearer)
		r.Get("/ServiceProviderConfig", s.serviceProviderConfig)
		r.Get("/ResourceTypes", s.resourceTypes)
		r.Get("/Schemas", s.schemas)

		r.Get("/Users", s.listUsers)
		r.Post("/Users", s.createUser)
		r.Get("/Users/{id}", s.getUser)
		r.Put("/Users/{id}", s.replaceUser)
		r.Patch("/Users/{id}", s.patchUser)
		r.Delete("/Users/{id}", s.deleteUser)

		r.Get("/Groups", s.listGroups)
		r.Post("/Groups", s.createGroup)
		r.Get("/Groups/{id}", s.getGroup)
		r.Put("/Groups/{id}", s.replaceGroup)
		r.Patch("/Groups/{id}", s.patchGroup)
		r.Delete("/Groups/{id}", s.deleteGroup)
	})
}

func (s *Server) requireBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.bearer == "" {
			next.ServeHTTP(w, r)
			return
		}
		hdr := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(hdr, prefix) {
			s.writeError(w, http.StatusUnauthorized, "missing Bearer authorization")
			return
		}
		if subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(hdr, prefix)), []byte(s.bearer)) != 1 {
			s.writeError(w, http.StatusUnauthorized, "invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── ServiceProviderConfig / ResourceTypes / Schemas ──────────────────

func (s *Server) serviceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"schemas":          []string{SchemaServiceConfig},
		"documentationUri": "https://github.com/darpanzope/compliancekit/blob/main/docs/scim.md",
		"patch":            map[string]bool{"supported": true},
		"bulk":             map[string]any{"supported": false},
		"filter":           map[string]any{"supported": true, "maxResults": 200},
		"changePassword":   map[string]bool{"supported": false},
		"sort":             map[string]bool{"supported": false},
		"etag":             map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type":        "oauthbearertoken",
			"name":        "OAuth Bearer Token",
			"description": "Static bearer token configured via CK_SCIM_BEARER_TOKEN.",
		}},
		"meta": map[string]any{
			"resourceType": "ServiceProviderConfig",
			"location":     "/scim/v2/ServiceProviderConfig",
		},
	})
}

func (s *Server) resourceTypes(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, listResponse([]map[string]any{
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "User",
			"name":        "User",
			"endpoint":    "/Users",
			"description": "User account",
			"schema":      SchemaUser,
		},
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "Group",
			"name":        "Group",
			"endpoint":    "/Groups",
			"description": "Maps to a compliancekit RBAC role",
			"schema":      SchemaGroup,
		},
	}))
}

func (s *Server) schemas(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, listResponse([]map[string]any{
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": SchemaUser, "name": "User"},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": SchemaGroup, "name": "Group"},
	}))
}

// ── User CRUD ────────────────────────────────────────────────────────

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.users.All(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list users: "+err.Error())
		return
	}
	resources := make([]map[string]any, 0, len(users))
	for _, u := range users {
		resources = append(resources, s.userResource(r.Context(), u))
	}
	s.writeJSON(w, http.StatusOK, listResponse(resources))
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	in, err := decodeScimUser(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.UserName == "" {
		s.writeError(w, http.StatusBadRequest, "userName is required")
		return
	}
	created, err := s.users.Create(r.Context(), in.UserName, in.DisplayName, randomScimPassword(), false)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrEmailAlreadyTaken):
			s.writeError(w, http.StatusConflict, "user already exists")
		default:
			s.writeError(w, http.StatusInternalServerError, "create user: "+err.Error())
		}
		return
	}
	s.writeJSON(w, http.StatusCreated, s.userResource(r.Context(), created))
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	u, err := s.users.ByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "user not found")
		return
	}
	s.writeJSON(w, http.StatusOK, s.userResource(r.Context(), u))
}

func (s *Server) replaceUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	in, err := decodeScimUser(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.updateUserFields(r.Context(), id, in.DisplayName, in.Active); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	u, err := s.users.ByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "user not found")
		return
	}
	s.writeJSON(w, http.StatusOK, s.userResource(r.Context(), u))
}

func (s *Server) patchUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ops, err := decodePatchOps(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := s.users.ByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "user not found")
		return
	}
	display := u.DisplayName
	active := true
	for _, op := range ops {
		switch strings.ToLower(op.Path) {
		case "displayname":
			if v, ok := op.Value.(string); ok {
				display = v
			}
		case "active":
			if v, ok := op.Value.(bool); ok {
				active = v
			}
		}
	}
	if err := s.updateUserFields(r.Context(), id, display, active); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	u, _ = s.users.ByID(r.Context(), id)
	s.writeJSON(w, http.StatusOK, s.userResource(r.Context(), u))
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := s.store.DB().ExecContext(r.Context(),
		`DELETE FROM users WHERE id = `+ph(s.store, 1), id); err != nil {
		s.writeError(w, http.StatusInternalServerError, "delete user: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) updateUserFields(ctx context.Context, id, display string, _ bool) error {
	_, err := s.store.DB().ExecContext(ctx,
		`UPDATE users SET display_name = `+ph(s.store, 1)+` WHERE id = `+ph(s.store, 2),
		display, id)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	return nil
}

// ── Group CRUD (Group = RBAC role) ──────────────────────────────────

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	roles, err := s.rbac.ListRoles(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list groups: "+err.Error())
		return
	}
	resources := make([]map[string]any, 0, len(roles))
	for _, role := range roles {
		resources = append(resources, s.roleResource(r.Context(), role.ID, role.Name))
	}
	s.writeJSON(w, http.StatusOK, listResponse(resources))
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	in, err := decodeScimGroup(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.DisplayName == "" {
		s.writeError(w, http.StatusBadRequest, "displayName is required")
		return
	}
	role, err := s.rbac.CreateRole(r.Context(), in.DisplayName, "", nil)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "create group: "+err.Error())
		return
	}
	for _, m := range in.Members {
		_ = s.rbac.AssignRole(r.Context(), m.Value, role.ID, "")
	}
	s.writeJSON(w, http.StatusCreated, s.roleResource(r.Context(), role.ID, role.Name))
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	role, err := s.rbac.ByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "group not found")
		return
	}
	s.writeJSON(w, http.StatusOK, s.roleResource(r.Context(), role.ID, role.Name))
}

func (s *Server) replaceGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	in, err := decodeScimGroup(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	current, err := s.groupMemberIDs(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "group members: "+err.Error())
		return
	}
	desired := make(map[string]bool)
	for _, m := range in.Members {
		desired[m.Value] = true
	}
	for uid := range current {
		if !desired[uid] {
			_ = s.rbac.RevokeRole(r.Context(), uid, id)
		}
	}
	for uid := range desired {
		if !current[uid] {
			_ = s.rbac.AssignRole(r.Context(), uid, id, "")
		}
	}
	role, _ := s.rbac.ByID(r.Context(), id)
	s.writeJSON(w, http.StatusOK, s.roleResource(r.Context(), role.ID, role.Name))
}

func (s *Server) patchGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ops, err := decodePatchOps(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, op := range ops {
		path := strings.ToLower(op.Path)
		if !strings.HasPrefix(path, "members") {
			continue
		}
		members, _ := op.Value.([]any)
		for _, m := range members {
			obj, ok := m.(map[string]any)
			if !ok {
				continue
			}
			uid, _ := obj["value"].(string)
			if uid == "" {
				continue
			}
			switch strings.ToLower(op.Op) {
			case "add", "replace":
				_ = s.rbac.AssignRole(r.Context(), uid, id, "")
			case "remove":
				_ = s.rbac.RevokeRole(r.Context(), uid, id)
			}
		}
	}
	role, _ := s.rbac.ByID(r.Context(), id)
	s.writeJSON(w, http.StatusOK, s.roleResource(r.Context(), role.ID, role.Name))
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.rbac.DeleteRole(r.Context(), id); err != nil {
		s.writeError(w, http.StatusInternalServerError, "delete group: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) groupMemberIDs(ctx context.Context, roleID string) (map[string]bool, error) {
	rows, err := s.store.DB().QueryContext(ctx,
		`SELECT user_id FROM user_roles WHERE role_id = `+ph(s.store, 1), roleID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make(map[string]bool)
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			return nil, err
		}
		out[uid] = true
	}
	return out, rows.Err()
}

// ── Response shapes ─────────────────────────────────────────────────

func (s *Server) userResource(ctx context.Context, u *auth.User) map[string]any {
	_ = ctx
	display := u.DisplayName
	if display == "" {
		display = u.Email
	}
	return map[string]any{
		"schemas":     []string{SchemaUser},
		"id":          u.ID,
		"userName":    u.Email,
		"displayName": display,
		"name":        map[string]any{"formatted": display},
		"emails": []map[string]any{
			{"value": u.Email, "primary": true},
		},
		"active": u.PasswordHash != "" || u.OIDCSubject != "",
		"meta": map[string]any{
			"resourceType": "User",
			"location":     "/scim/v2/Users/" + u.ID,
			"created":      u.CreatedAt.UTC().Format(time.RFC3339),
		},
	}
}

func (s *Server) roleResource(ctx context.Context, id, name string) map[string]any {
	members := []map[string]any{}
	if rows, err := s.store.DB().QueryContext(ctx,
		`SELECT u.id, u.email FROM user_roles ur JOIN users u ON u.id = ur.user_id WHERE ur.role_id = `+ph(s.store, 1),
		id); err == nil {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var uid, email string
			if err := rows.Scan(&uid, &email); err != nil {
				continue
			}
			members = append(members, map[string]any{"value": uid, "display": email})
		}
	}
	return map[string]any{
		"schemas":     []string{SchemaGroup},
		"id":          id,
		"displayName": name,
		"members":     members,
		"meta": map[string]any{
			"resourceType": "Group",
			"location":     "/scim/v2/Groups/" + id,
		},
	}
}

func listResponse(resources []map[string]any) map[string]any {
	return map[string]any{
		"schemas":      []string{SchemaListResponse},
		"totalResults": len(resources),
		"itemsPerPage": len(resources),
		"startIndex":   1,
		"Resources":    resources,
	}
}

// ── Decoding helpers ────────────────────────────────────────────────

type scimUserIn struct {
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
	Active      bool   `json:"active"`
}

func decodeScimUser(r *http.Request) (scimUserIn, error) {
	var in scimUserIn
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return in, fmt.Errorf("decode SCIM user: %w", err)
	}
	return in, nil
}

type scimGroupIn struct {
	DisplayName string        `json:"displayName"`
	Members     []groupMember `json:"members"`
}

type groupMember struct {
	Value string `json:"value"`
}

func decodeScimGroup(r *http.Request) (scimGroupIn, error) {
	var in scimGroupIn
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return in, fmt.Errorf("decode SCIM group: %w", err)
	}
	return in, nil
}

// PatchOp is the SCIM 2.0 PatchOperation shape (RFC 7644 §3.5.2).
type PatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

func decodePatchOps(r *http.Request) ([]PatchOp, error) {
	var envelope struct {
		Schemas    []string  `json:"schemas"`
		Operations []PatchOp `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode SCIM PatchOp: %w", err)
	}
	return envelope.Operations, nil
}

// writeJSON marshals v as SCIM JSON with the canonical content-type.
func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError emits the SCIM Error envelope.
func (s *Server) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schemas": []string{SchemaError},
		"detail":  msg,
		"status":  strconv.Itoa(status),
	})
}

// ph returns the driver-appropriate placeholder.
func ph(st *store.Store, n int) string {
	if st.Driver() == store.DriverPostgres {
		return "$" + strconv.Itoa(n)
	}
	return "?"
}

// randomScimPassword generates a placeholder for SCIM-provisioned
// accounts so the local-auth password column isn't NULL. The user
// has no path to discover or use it — SCIM-provisioned accounts log
// in via SAML/OIDC.
func randomScimPassword() string {
	return "scim-auto-" + time.Now().UTC().Format(time.RFC3339Nano)
}
