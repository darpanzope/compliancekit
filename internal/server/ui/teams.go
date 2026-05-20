package ui

// v1.8 phase 8 — /settings/teams CRUD.
//
// Operators add named teams under /settings/teams; team membership +
// per-resource follower opt-in feed the inbox/notification fan-out
// from phase 9. Edit/delete is admin-or-creator only; non-admins see
// a read-only list.

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/collab"
)

// teamsRepo lazily-constructs the handle.
func (u *UI) teamsRepo() *collab.Teams {
	if u.teams == nil {
		u.teams = collab.NewTeams(u.store)
	}
	return u.teams
}

// followers lazily-constructs the followers handle.
func (u *UI) followers() *collab.Followers {
	if u.followersRepo == nil {
		u.followersRepo = collab.NewFollowers(u.store)
	}
	return u.followersRepo
}

// teamsViewRow is the per-team payload for the list template.
type teamsViewRow struct {
	ID          string
	Slug        string
	Name        string
	Description string
	MemberCount int
}

// teamDetailView is the per-team detail page payload.
type teamDetailView struct {
	View
	Team    collab.Team
	Members []collab.TeamMember
	Users   []pickerOption
	CanEdit bool
}

// mountTeamsRoutes wires the v1.8 phase 8 surface.
func (u *UI) mountTeamsRoutes(r chi.Router) {
	r.Get("/settings/teams", u.teamsList)
	r.Post("/settings/teams", u.teamsCreate)
	r.Get("/settings/teams/{id}", u.teamDetail)
	r.Post("/settings/teams/{id}", u.teamUpdate)
	r.Post("/settings/teams/{id}/delete", u.teamDelete)
	r.Post("/settings/teams/{id}/members", u.teamAddMember)
	r.Post("/settings/teams/{id}/members/{uid}/remove", u.teamRemoveMember)
	r.Post("/resources/{id}/follow", u.resourceFollow)
	r.Post("/resources/{id}/unfollow", u.resourceUnfollow)
}

// teamsList renders the page.
func (u *UI) teamsList(w http.ResponseWriter, r *http.Request) {
	teams, err := u.teamsRepo().All(r.Context())
	if err != nil {
		u.fail(w, "load teams: "+err.Error())
		return
	}
	rows := make([]teamsViewRow, 0, len(teams))
	for _, t := range teams {
		rows = append(rows, teamsViewRow{
			ID: t.ID, Slug: t.Slug, Name: t.Name,
			Description: t.Description, MemberCount: t.MemberCount,
		})
	}
	view := struct {
		View
		Teams   []teamsViewRow
		CanEdit bool
	}{
		View:    u.viewFor(r, "Teams", "settings", View{}),
		Teams:   rows,
		CanEdit: u.isAdmin(r.Context()),
	}
	u.render(w, "teams.html", view)
}

// teamsCreate handles POST /settings/teams.
func (u *UI) teamsCreate(w http.ResponseWriter, r *http.Request) {
	if !u.isAdmin(r.Context()) {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	slug := strings.TrimSpace(r.FormValue("slug"))
	name := strings.TrimSpace(r.FormValue("name"))
	desc := strings.TrimSpace(r.FormValue("description"))
	sess := auth.FromContext(r.Context())
	createdBy := ""
	if sess != nil {
		createdBy = sess.UserID
	}
	team, err := u.teamsRepo().Create(r.Context(), slug, name, desc, createdBy)
	if err != nil {
		http.Error(w, "create team: "+err.Error(), http.StatusBadRequest)
		return
	}
	u.AuditLog(r.Context(), "team.create", "team", team.ID, map[string]any{
		"slug": team.Slug, "name": team.Name,
	})
	http.Redirect(w, r, "/settings/teams/"+team.ID, http.StatusSeeOther)
}

// teamDetail renders one team.
func (u *UI) teamDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	team, err := u.teamsRepo().ByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	members, err := u.teamsRepo().Members(r.Context(), id)
	if err != nil {
		u.fail(w, "load members: "+err.Error())
		return
	}
	view := teamDetailView{
		View:    u.viewFor(r, team.Name, "settings", View{}),
		Team:    team,
		Members: members,
		Users:   u.pickerOptions(r.Context()),
		CanEdit: u.isAdmin(r.Context()),
	}
	u.render(w, "team_detail.html", view)
}

// teamUpdate handles POST /settings/teams/{id} (name + description).
func (u *UI) teamUpdate(w http.ResponseWriter, r *http.Request) {
	if !u.isAdmin(r.Context()) {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	desc := strings.TrimSpace(r.FormValue("description"))
	if err := u.teamsRepo().Update(r.Context(), id, name, desc); err != nil {
		http.Error(w, "update: "+err.Error(), http.StatusBadRequest)
		return
	}
	u.AuditLog(r.Context(), "team.update", "team", id, map[string]any{"name": name})
	http.Redirect(w, r, "/settings/teams/"+id, http.StatusSeeOther)
}

// teamDelete removes the team.
func (u *UI) teamDelete(w http.ResponseWriter, r *http.Request) {
	if !u.isAdmin(r.Context()) {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	if err := u.teamsRepo().Delete(r.Context(), id); err != nil {
		http.Error(w, "delete: "+err.Error(), http.StatusInternalServerError)
		return
	}
	u.AuditLog(r.Context(), "team.delete", "team", id, nil)
	http.Redirect(w, r, "/settings/teams", http.StatusSeeOther)
}

// teamAddMember adds a user with role.
func (u *UI) teamAddMember(w http.ResponseWriter, r *http.Request) {
	if !u.isAdmin(r.Context()) {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	userID := r.FormValue("user_id")
	role := r.FormValue("role")
	if err := u.teamsRepo().AddMember(r.Context(), id, userID, role); err != nil {
		http.Error(w, "add member: "+err.Error(), http.StatusBadRequest)
		return
	}
	u.AuditLog(r.Context(), "team.add_member", "team", id, map[string]any{
		"user_id": userID, "role": role,
	})
	http.Redirect(w, r, "/settings/teams/"+id, http.StatusSeeOther)
}

// teamRemoveMember drops a (team, user) row.
func (u *UI) teamRemoveMember(w http.ResponseWriter, r *http.Request) {
	if !u.isAdmin(r.Context()) {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	uid := chi.URLParam(r, "uid")
	if err := u.teamsRepo().RemoveMember(r.Context(), id, uid); err != nil {
		http.Error(w, "remove: "+err.Error(), http.StatusInternalServerError)
		return
	}
	u.AuditLog(r.Context(), "team.remove_member", "team", id, map[string]any{"user_id": uid})
	http.Redirect(w, r, "/settings/teams/"+id, http.StatusSeeOther)
}

// resourceFollow opts the session-user in to follow the resource.
func (u *UI) resourceFollow(w http.ResponseWriter, r *http.Request) {
	resID := chi.URLParam(r, "id")
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	if err := u.followers().Add(r.Context(), resID, sess.UserID); err != nil {
		http.Error(w, "follow: "+err.Error(), http.StatusInternalServerError)
		return
	}
	u.AuditLog(r.Context(), "resource.follow", "resource", resID, nil)
	u.renderFollowerWidget(w, r, resID)
}

// resourceUnfollow opts out.
func (u *UI) resourceUnfollow(w http.ResponseWriter, r *http.Request) {
	resID := chi.URLParam(r, "id")
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	if err := u.followers().Remove(r.Context(), resID, sess.UserID); err != nil {
		http.Error(w, "unfollow: "+err.Error(), http.StatusInternalServerError)
		return
	}
	u.AuditLog(r.Context(), "resource.unfollow", "resource", resID, nil)
	u.renderFollowerWidget(w, r, resID)
}

// renderFollowerWidget refreshes the follow/unfollow button.
func (u *UI) renderFollowerWidget(w http.ResponseWriter, r *http.Request, resourceID string) {
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	following, err := u.followers().Following(r.Context(), resourceID, sess.UserID)
	if err != nil {
		http.Error(w, "lookup: "+err.Error(), http.StatusInternalServerError)
		return
	}
	count, _ := u.followers().CountByResource(r.Context(), resourceID)
	u.renderPartial(w, "follower_widget", struct {
		ResourceID string
		Following  bool
		Count      int
		CountStr   string
		CSRFToken  string
	}{
		ResourceID: resourceID,
		Following:  following,
		Count:      count,
		CountStr:   strconv.Itoa(count),
		CSRFToken:  sess.CSRFToken,
	})
	_ = errors.New // silence linter on unused alias when only one use
}
