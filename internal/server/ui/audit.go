package ui

// v1.4 Phase 11 — Audit log + in-UI notifications inbox.
//
// Routes:
//
//	GET  /audit                  paginated audit_log view
//	GET  /inbox                  per-user notifications list
//	POST /inbox/{id}/read        mark single notification as read
//	POST /inbox/read-all         mark every unread as read
//
// AuditLog(...) is a package-internal helper any handler can call to
// record a config change. The events flow through the existing
// audit_log table (v1.3 phase 1 schema) — no Go-side audit framework
// to learn, just one helper call.
//
// Inbox alerts live in their own table (migration 0004). NotifyInbox
// fans out broadcast alerts (user_id NULL) or per-user alerts.

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/darpanzope/compliancekit/internal/server/auth"
)

// auditEntry is the per-row payload of the /audit page.
type auditEntry struct {
	ID         string
	CreatedAt  string
	CreatedIn  string
	ActorEmail string
	ActorIP    string
	Action     string
	EntityType string
	EntityID   string
	Metadata   string
}

type auditView struct {
	View
	Items   []auditEntry
	Page    int
	HasNext bool
}

// inboxItem is the per-row payload of /inbox.
type inboxItem struct {
	ID        string
	CreatedAt string
	CreatedIn string
	Severity  string
	Title     string
	Body      string
	Href      string
	Read      bool
}

type inboxView struct {
	View
	Items       []inboxItem
	UnreadCount int
	Flash       string
}

// mountAuditRoutes registers the Phase 11 endpoints.
func (u *UI) mountAuditRoutes(r chi.Router) {
	r.Get("/audit", u.auditList)
	r.Get("/inbox", u.inboxList)
	r.Post("/inbox/{id}/read", u.inboxMarkRead)
	r.Post("/inbox/read-all", u.inboxMarkAllRead)
}

// AuditLog records one entry in the audit_log table. Any UI handler
// that mutates state should call this with the (action, entity_type,
// entity_id, metadata) shape. Failures are logged + swallowed — the
// underlying operation already succeeded; we don't want a missing
// audit row to bubble a 500 to the user.
func (u *UI) AuditLog(ctx context.Context, action, entityType, entityID string, metadata map[string]any) {
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339)
	var userArg any
	if sess := auth.FromContext(ctx); sess != nil && sess.UserID != "" {
		userArg = sess.UserID
	}
	mdJSON, _ := json.Marshal(metadata)
	if len(mdJSON) == 0 {
		mdJSON = []byte("{}")
	}
	// actor_ip stays empty for now — Phase 11 ships the audit shape;
	// future audit-hook middleware will populate it via RealIP.
	// actor_user_id is NULL when no session is present (system-driven
	// events) so the FK to users(id) is satisfied either way.
	q := `INSERT INTO audit_log (id, created_at, actor_user_id, actor_ip,
	                              action, entity_type, entity_id, metadata_json)
	      VALUES (` + phList(u.store, 8) + `)`
	_, _ = u.store.DB().ExecContext(ctx, q,
		id, now, userArg, "", action, entityType, entityID, string(mdJSON))
}

// NotifyInbox writes one inbox alert. userID may be empty to broadcast
// to every user; severity defaults to "info" when blank.
func (u *UI) NotifyInbox(ctx context.Context, userID, severity, title, body, href string) {
	if severity == "" {
		severity = "info"
	}
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339)
	var userArg any
	if userID == "" {
		userArg = nil
	} else {
		userArg = userID
	}
	q := `INSERT INTO inbox (id, user_id, created_at, severity, title, body, href)
	      VALUES (` + phList(u.store, 7) + `)`
	_, _ = u.store.DB().ExecContext(ctx, q,
		id, userArg, now, severity, title, body, href)
}

func (u *UI) auditList(w http.ResponseWriter, r *http.Request) {
	pageN, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if pageN < 1 {
		pageN = 1
	}
	per := 50
	offset := (pageN - 1) * per
	rows, err := u.store.DB().QueryContext(r.Context(),
		`SELECT a.id, a.created_at, COALESCE(u.email,''), COALESCE(a.actor_ip,''),
		        a.action, COALESCE(a.entity_type,''), COALESCE(a.entity_id,''),
		        COALESCE(a.metadata_json,'{}')
		 FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id
		 ORDER BY a.created_at DESC LIMIT `+strconv.Itoa(per+1)+` OFFSET `+strconv.Itoa(offset))
	if err != nil {
		u.fail(w, "list audit: "+err.Error())
		return
	}
	defer func() { _ = rows.Close() }()
	items := []auditEntry{}
	for rows.Next() {
		var e auditEntry
		if err := rows.Scan(&e.ID, &e.CreatedAt, &e.ActorEmail, &e.ActorIP,
			&e.Action, &e.EntityType, &e.EntityID, &e.Metadata); err != nil {
			u.fail(w, "audit row: "+err.Error())
			return
		}
		e.CreatedIn = humanizeAgo(e.CreatedAt)
		items = append(items, e)
	}
	hasNext := len(items) > per
	if hasNext {
		items = items[:per]
	}
	view := auditView{
		View:    u.viewFor(r, "Audit log · Settings", "settings", View{}),
		Items:   items,
		Page:    pageN,
		HasNext: hasNext,
	}
	u.render(w, "audit.html", view)
}

func (u *UI) inboxList(w http.ResponseWriter, r *http.Request) {
	userID := ""
	if sess := auth.FromContext(r.Context()); sess != nil {
		userID = sess.UserID
	}
	items, unread, err := u.loadInbox(r.Context(), userID)
	if err != nil {
		u.fail(w, "load inbox: "+err.Error())
		return
	}
	view := inboxView{
		View:        u.viewFor(r, "Inbox", "inbox", View{}),
		Items:       items,
		UnreadCount: unread,
		Flash:       r.URL.Query().Get("flash"),
	}
	u.render(w, "inbox.html", view)
}

func (u *UI) inboxMarkRead(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = u.store.DB().ExecContext(r.Context(),
		`UPDATE inbox SET read_at = `+ph(u.store, 1)+` WHERE id = `+ph(u.store, 2)+` AND read_at IS NULL`,
		now, id)
	http.Redirect(w, r, "/inbox", http.StatusSeeOther)
}

func (u *UI) inboxMarkAllRead(w http.ResponseWriter, r *http.Request) {
	userID := ""
	if sess := auth.FromContext(r.Context()); sess != nil {
		userID = sess.UserID
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if userID == "" {
		_, _ = u.store.DB().ExecContext(r.Context(),
			`UPDATE inbox SET read_at = `+ph(u.store, 1)+` WHERE read_at IS NULL AND user_id IS NULL`, now)
	} else {
		_, _ = u.store.DB().ExecContext(r.Context(),
			`UPDATE inbox SET read_at = `+ph(u.store, 1)+
				` WHERE read_at IS NULL AND (user_id = `+ph(u.store, 2)+` OR user_id IS NULL)`,
			now, userID)
	}
	http.Redirect(w, r, "/inbox?flash=read-all", http.StatusSeeOther)
}

// loadInbox returns the inbox items visible to userID (their own +
// broadcasts) plus the unread count. Newest first.
func (u *UI) loadInbox(ctx context.Context, userID string) ([]inboxItem, int, error) {
	q := `SELECT id, created_at, severity, title, body, COALESCE(href,''), read_at
	      FROM inbox`
	args := []any{}
	if userID != "" {
		q += ` WHERE user_id = ` + ph(u.store, 1) + ` OR user_id IS NULL`
		args = append(args, userID)
	} else {
		q += ` WHERE user_id IS NULL`
	}
	q += ` ORDER BY created_at DESC LIMIT 100`

	rows, err := u.store.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	items := []inboxItem{}
	unread := 0
	for rows.Next() {
		var it inboxItem
		var readAt *string
		if err := rows.Scan(&it.ID, &it.CreatedAt, &it.Severity, &it.Title, &it.Body, &it.Href, &readAt); err != nil {
			return items, 0, err
		}
		it.CreatedIn = humanizeAgo(it.CreatedAt)
		it.Read = readAt != nil && *readAt != ""
		if !it.Read {
			unread++
		}
		items = append(items, it)
	}
	return items, unread, rows.Err()
}

// CountUnreadInbox is exposed so the topbar can render the unread
// badge. Returns 0 on any error so a flaky inbox doesn't take down
// the whole UI.
func (u *UI) CountUnreadInbox(ctx context.Context, userID string) int {
	var n int
	q := `SELECT COUNT(*) FROM inbox WHERE read_at IS NULL`
	if userID != "" {
		q += ` AND (user_id = ` + ph(u.store, 1) + ` OR user_id IS NULL)`
		_ = u.store.DB().QueryRowContext(ctx, q, userID).Scan(&n)
		return n
	}
	q += ` AND user_id IS NULL`
	_ = u.store.DB().QueryRowContext(ctx, q).Scan(&n)
	return n
}
