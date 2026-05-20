package ui

// v1.8 phase 1 — Per-finding markdown comments.
//
// Findings stop being a wall of read-only text and become a
// conversation. This file owns the UI side of the v1.8 comments
// feature: GET the thread for a finding (HTML partial that goes
// into the side-panel's Comments tab), POST a new comment, PUT
// to edit, DELETE to remove. All four routes are gated by the
// existing RequireAuth + RequireCSRF middleware chain mounted in
// ui.go.
//
// Identity model: comments thread by Finding.Fingerprint() — so the
// operator's conversation persists across scans. The finding-id in
// the URL is just the side-panel's current row; the handler resolves
// it to a fingerprint via loadFindingByID before touching the
// comments package.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/collab"
	"github.com/darpanzope/compliancekit/internal/server/comments"
)

// commentRow is the per-comment payload the comments_panel template
// iterates. Mirrors comments.Comment with template-friendly strings.
type commentRow struct {
	ID         string
	AuthorName string
	BodyHTML   string
	BodyRaw    string
	CreatedIn  string
	Edited     bool
	EditedIn   string
	Mine       bool
	Source     string
}

// commentsPanel is the partial payload — used by both the initial
// detail-tab render and the post-add re-render.
type commentsPanel struct {
	FindingID   string
	Fingerprint string
	Comments    []commentRow
	Total       int
	Flash       string
	CSRFToken   string
}

// mountCommentsRoutes wires the v1.8 phase 1 surface onto r.
// Mounted from ui.go inside the RequireAuth + RequireCSRF group.
func (u *UI) mountCommentsRoutes(r chi.Router) {
	r.Get("/findings/{id}/comments", u.commentsList)
	r.Post("/findings/{id}/comments", u.commentsAdd)
	r.Put("/findings/comments/{cid}", u.commentsEdit)
	r.Delete("/findings/comments/{cid}", u.commentsDelete)
}

// commentsList renders the comments tab for a finding. Returned as an
// HTMX partial; the finding_detail.html template lazy-loads it on tab
// activation.
func (u *UI) commentsList(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row, err := u.loadFindingByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	panel, err := u.buildCommentsPanel(r, row.ID, row.Fingerprint, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u.renderPartial(w, "comments_panel", panel)
}

// commentsAdd accepts a multipart/form-encoded body field, persists
// the comment, and returns the refreshed comments_panel partial so
// htmx can swap it directly back into the tab pane.
func (u *UI) commentsAdd(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row, err := u.loadFindingByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	body := r.FormValue("body")
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	flash := ""
	cid, err := u.comments.Add(r.Context(), row.Fingerprint, sess.UserID, body, comments.AddOptions{})
	if err != nil {
		if errors.Is(err, comments.ErrEmptyBody) {
			flash = "Comment body cannot be empty."
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		u.AuditLog(r.Context(), "comment.add", "finding", row.ID, map[string]any{
			"fingerprint": row.Fingerprint,
		})
		_, _ = u.activities().Record(r.Context(), row.Fingerprint, collab.ActivityCommentAdded, collab.RecordOptions{
			ActorID: sess.UserID, ActorSource: collab.ActorUI,
			Metadata: map[string]any{"comment_id": cid},
		})
		// v1.8 phase 4 — fan @mentions out as inbox notifications.
		// The mention extractor pulls handles from the markdown source;
		// the resolver matches against email or local-part.
		u.deliverMentions(r.Context(), row, sess.UserID, body)
	}
	panel, err := u.buildCommentsPanel(r, row.ID, row.Fingerprint, flash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u.renderPartial(w, "comments_panel", panel)
}

// commentsEdit rewrites an existing comment's body. Only the author
// (or an admin) may edit; non-authors get a 403.
func (u *UI) commentsEdit(w http.ResponseWriter, r *http.Request) {
	cid := chi.URLParam(r, "cid")
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	c, err := u.comments.ByID(r.Context(), cid)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !u.canMutateComment(r.Context(), c.AuthorID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	body := r.FormValue("body")
	flash := ""
	if err := u.comments.Edit(r.Context(), cid, body); err != nil {
		if errors.Is(err, comments.ErrEmptyBody) {
			flash = "Comment body cannot be empty."
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		u.AuditLog(r.Context(), "comment.edit", "finding", "", map[string]any{
			"comment_id": cid, "fingerprint": c.FindingFingerprint,
		})
		_, _ = u.activities().Record(r.Context(), c.FindingFingerprint, collab.ActivityCommentEdited, collab.RecordOptions{
			ActorID: sess.UserID, ActorSource: collab.ActorUI,
			Metadata: map[string]any{"comment_id": cid},
		})
	}
	// Resolve a finding-id for the partial render so the form's
	// hx-post target stays correct after the swap.
	findingID := r.URL.Query().Get("finding_id")
	panel, err := u.buildCommentsPanel(r, findingID, c.FindingFingerprint, flash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u.renderPartial(w, "comments_panel", panel)
}

// commentsDelete removes a comment. Same authorship rules as edit.
func (u *UI) commentsDelete(w http.ResponseWriter, r *http.Request) {
	cid := chi.URLParam(r, "cid")
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	c, err := u.comments.ByID(r.Context(), cid)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !u.canMutateComment(r.Context(), c.AuthorID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := u.comments.Delete(r.Context(), cid); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u.AuditLog(r.Context(), "comment.delete", "finding", "", map[string]any{
		"comment_id": cid, "fingerprint": c.FindingFingerprint,
	})
	_, _ = u.activities().Record(r.Context(), c.FindingFingerprint, collab.ActivityCommentEdited, collab.RecordOptions{
		ActorID: sess.UserID, ActorSource: collab.ActorUI,
		Metadata: map[string]any{"comment_id": cid, "deleted": true},
	})
	findingID := r.URL.Query().Get("finding_id")
	panel, err := u.buildCommentsPanel(r, findingID, c.FindingFingerprint, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u.renderPartial(w, "comments_panel", panel)
}

// canMutateComment returns true if the current session is the
// author, or an admin. The author check uses the auth subject id
// from the session.
func (u *UI) canMutateComment(ctx context.Context, authorID string) bool {
	sess := auth.FromContext(ctx)
	if sess == nil {
		return false
	}
	if authorID != "" && sess.UserID == authorID {
		return true
	}
	return u.isAdmin(ctx)
}

// buildCommentsPanel loads the thread + projects each row to the
// template-friendly commentRow shape.
func (u *UI) buildCommentsPanel(r *http.Request, findingID, fingerprint, flash string) (commentsPanel, error) {
	cs, err := u.comments.ListByFingerprint(r.Context(), fingerprint)
	if err != nil {
		return commentsPanel{}, err
	}
	sess := auth.FromContext(r.Context())
	now := time.Now()
	rows := make([]commentRow, 0, len(cs))
	for _, c := range cs {
		row := commentRow{
			ID:         c.ID,
			AuthorName: authorDisplayLabel(c),
			BodyHTML:   c.BodyHTML,
			BodyRaw:    c.Body,
			CreatedIn:  humanizeAgoFrom(c.CreatedAt, now),
			Source:     c.Source,
		}
		if c.EditedAt != nil {
			row.Edited = true
			row.EditedIn = humanizeAgoFrom(*c.EditedAt, now)
		}
		if sess != nil && c.AuthorID != "" && c.AuthorID == sess.UserID {
			row.Mine = true
		}
		rows = append(rows, row)
	}
	csrf := ""
	if sess != nil {
		csrf = sess.CSRFToken
	}
	return commentsPanel{
		FindingID:   findingID,
		Fingerprint: fingerprint,
		Comments:    rows,
		Total:       len(rows),
		Flash:       flash,
		CSRFToken:   csrf,
	}, nil
}

// deliverMentions resolves @handles in the comment body, posts an
// inbox row to each mentioned user, and records a follower opt-in
// signal so future events on the same resource keep notifying. Best-
// effort — DB failures here are swallowed; the inbox is a notification
// layer, not a system of record.
func (u *UI) deliverMentions(ctx context.Context, row findingRow, authorID, body string) {
	handles := comments.ExtractMentions(body)
	if len(handles) == 0 {
		return
	}
	users, err := u.users.All(ctx)
	if err != nil {
		return
	}
	href := "/findings?focus=" + row.ID
	title := "You were mentioned in a finding comment"
	bodyText := row.CheckID + " — " + row.ResourceName
	for _, handle := range handles {
		uid := matchUserHandle(users, handle)
		if uid == "" || uid == authorID {
			continue
		}
		u.NotifyInbox(ctx, uid, "info", title, bodyText, href)
	}
}

// matchUserHandle resolves a mention handle to a userID using the
// same matching rules as the autocomplete endpoint (case-insensitive
// substring on email + display_name).
func matchUserHandle(users []*auth.User, handle string) string {
	needle := strings.ToLower(handle)
	for _, u := range users {
		local := u.Email
		if at := strings.IndexByte(u.Email, '@'); at > 0 {
			local = u.Email[:at]
		}
		if strings.EqualFold(local, handle) || strings.EqualFold(u.DisplayName, handle) {
			return u.ID
		}
	}
	// Fall back to substring on email if no exact match found.
	for _, u := range users {
		if strings.Contains(strings.ToLower(u.Email), needle) {
			return u.ID
		}
	}
	return ""
}

// authorDisplayLabel mirrors compliancekit.User.Label() for the
// daemon-side row shape.
func authorDisplayLabel(c comments.Comment) string {
	if c.AuthorDisplayName != "" {
		return c.AuthorDisplayName
	}
	if c.AuthorEmail != "" {
		for i := 0; i < len(c.AuthorEmail); i++ {
			if c.AuthorEmail[i] == '@' {
				return c.AuthorEmail[:i]
			}
		}
		return c.AuthorEmail
	}
	return "deleted user"
}
