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
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
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
	r.Get("/audit/export.ndjson", u.auditExportNDJSON)
	r.Get("/audit/export.csv", u.auditExportCSV)
	r.Get("/inbox", u.inboxList)
	r.Post("/inbox/{id}/read", u.inboxMarkRead)
	r.Post("/inbox/read-all", u.inboxMarkAllRead)
}

// AuditLog records one entry in the audit_log table. Any UI handler
// that mutates state should call this with the (action, entity_type,
// entity_id, metadata) shape. Failures are logged + swallowed — the
// underlying operation already succeeded; we don't want a missing
// audit row to bubble a 500 to the user.
//
// v1.12 phase 10: each inserted row is hash-chained. prev_hash is the
// previous row's row_hash (or the all-zero hash for the first row);
// row_hash = SHA-256(prev_hash || canonical-json(this row)).
// compliancekit serve audit verify walks the chain to detect
// tampering.
func (u *UI) AuditLog(ctx context.Context, action, entityType, entityID string, metadata map[string]any) {
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	userID := ""
	if sess := auth.FromContext(ctx); sess != nil && sess.UserID != "" {
		userID = sess.UserID
	}
	mdJSON, _ := json.Marshal(metadata)
	if len(mdJSON) == 0 {
		mdJSON = []byte("{}")
	}
	prev := u.latestRowHash(ctx)
	rowHash := computeRowHash(prev, auditRowCanonical{
		ID:         id,
		CreatedAt:  now,
		ActorUser:  userID,
		Action:     action,
		EntityType: entityType,
		EntityID:   entityID,
		Metadata:   string(mdJSON),
	})
	var userArg any
	if userID != "" {
		userArg = userID
	}
	q := `INSERT INTO audit_log (id, created_at, actor_user_id, actor_ip,
	                              action, entity_type, entity_id, metadata_json,
	                              prev_hash, row_hash)
	      VALUES (` + phList(u.store, 10) + `)`
	_, _ = u.store.DB().ExecContext(ctx, q,
		id, now, userArg, "", action, entityType, entityID, string(mdJSON),
		prev, rowHash)
}

// auditRowCanonical is the canonical projection of an audit_log row
// used as the hash input. Field order is fixed by the json.Marshal
// alphabetic-key behavior of the struct field tags. Adding a new
// field is a SemVer-significant change for the verify command.
type auditRowCanonical struct {
	ID         string `json:"id"`
	CreatedAt  string `json:"created_at"`
	ActorUser  string `json:"actor_user_id"`
	Action     string `json:"action"`
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	Metadata   string `json:"metadata_json"`
}

// computeRowHash returns the hex-encoded SHA-256 over prev || canonical-json(row).
func computeRowHash(prev string, row auditRowCanonical) string {
	body, _ := json.Marshal(row)
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// latestRowHash returns the most-recent row_hash. The all-zero
// SHA-256 ("000…0", 64 zeros) is returned when no chained rows exist
// — the genesis prev_hash.
func (u *UI) latestRowHash(ctx context.Context) string {
	const genesis = "0000000000000000000000000000000000000000000000000000000000000000"
	var hash sql.NullString
	_ = u.store.DB().QueryRowContext(ctx,
		`SELECT row_hash FROM audit_log WHERE row_hash IS NOT NULL
		 ORDER BY created_at DESC, id DESC LIMIT 1`).Scan(&hash)
	if !hash.Valid || hash.String == "" {
		return genesis
	}
	return hash.String
}

// AuditVerifyResult is the report shape VerifyAuditChain returns.
type AuditVerifyResult struct {
	Total     int
	Chained   int
	Unchained int // pre-v1.12 rows with NULL row_hash
	Broken    []string
}

// VerifyAuditChain walks audit_log oldest-first and recomputes each
// row's hash. Returns the rowIDs of any rows where prev_hash or
// row_hash doesn't match the recomputed value. Unchained legacy rows
// (NULL row_hash) are counted but not validated.
func (u *UI) VerifyAuditChain(ctx context.Context) (AuditVerifyResult, error) {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT id, created_at, COALESCE(actor_user_id,''), action,
		        COALESCE(entity_type,''), COALESCE(entity_id,''),
		        COALESCE(metadata_json,'{}'),
		        COALESCE(prev_hash,''), COALESCE(row_hash,'')
		 FROM audit_log
		 ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return AuditVerifyResult{}, err
	}
	defer func() { _ = rows.Close() }()
	res := AuditVerifyResult{}
	const genesis = "0000000000000000000000000000000000000000000000000000000000000000"
	expectedPrev := genesis
	for rows.Next() {
		var (
			c                 auditRowCanonical
			prevHash, rowHash string
		)
		if err := rows.Scan(&c.ID, &c.CreatedAt, &c.ActorUser, &c.Action,
			&c.EntityType, &c.EntityID, &c.Metadata, &prevHash, &rowHash); err != nil {
			return res, err
		}
		res.Total++
		if rowHash == "" {
			res.Unchained++
			continue
		}
		res.Chained++
		if prevHash != expectedPrev {
			res.Broken = append(res.Broken, c.ID)
		}
		expected := computeRowHash(prevHash, c)
		if expected != rowHash {
			res.Broken = append(res.Broken, c.ID)
		}
		expectedPrev = rowHash
	}
	return res, rows.Err()
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

// auditFilters captures the query-string knobs the v1.12 phase 6
// audit search surface exposes. All fields optional.
type auditFilters struct {
	Q          string // full-text fragment: matches action, entity_id, entity_type, metadata_json substring
	ActorEmail string
	Action     string
	Entity     string // matches entity_type
	Since      string // RFC3339; rows with created_at >= since
	Until      string // RFC3339; rows with created_at < until
}

// parseAuditFilters reads the filters out of r's query string.
func parseAuditFilters(r *http.Request) auditFilters {
	q := r.URL.Query()
	return auditFilters{
		Q:          q.Get("q"),
		ActorEmail: q.Get("actor"),
		Action:     q.Get("action"),
		Entity:     q.Get("entity"),
		Since:      q.Get("since"),
		Until:      q.Get("until"),
	}
}

// auditWhere builds the WHERE clause + bind args from f. Returns the
// SQL fragment (sans leading WHERE) and the argument slice. Empty
// fragment when no filters apply.
func (u *UI) auditWhere(f auditFilters, nextPh func() string) (clause string, args []any) {
	var conds []string
	if f.Q != "" {
		p := nextPh()
		conds = append(conds, "(a.action LIKE "+p+" OR a.entity_id LIKE "+p+" OR a.entity_type LIKE "+p+" OR a.metadata_json LIKE "+p+")")
		args = append(args, "%"+f.Q+"%")
	}
	if f.ActorEmail != "" {
		p := nextPh()
		conds = append(conds, "u.email LIKE "+p)
		args = append(args, "%"+f.ActorEmail+"%")
	}
	if f.Action != "" {
		p := nextPh()
		conds = append(conds, "a.action = "+p)
		args = append(args, f.Action)
	}
	if f.Entity != "" {
		p := nextPh()
		conds = append(conds, "a.entity_type = "+p)
		args = append(args, f.Entity)
	}
	if f.Since != "" {
		p := nextPh()
		conds = append(conds, "a.created_at >= "+p)
		args = append(args, f.Since)
	}
	if f.Until != "" {
		p := nextPh()
		conds = append(conds, "a.created_at < "+p)
		args = append(args, f.Until)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// phCounter returns a fresh-per-call placeholder helper for the
// current driver, used by auditWhere.
func (u *UI) phCounter() func() string {
	n := 0
	return func() string {
		n++
		return ph(u.store, n)
	}
}

func (u *UI) auditList(w http.ResponseWriter, r *http.Request) {
	pageN, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if pageN < 1 {
		pageN = 1
	}
	per := 50
	offset := (pageN - 1) * per
	filters := parseAuditFilters(r)
	where, args := u.auditWhere(filters, u.phCounter())
	q := `SELECT a.id, a.created_at, COALESCE(u.email,''), COALESCE(a.actor_ip,''),
	             a.action, COALESCE(a.entity_type,''), COALESCE(a.entity_id,''),
	             COALESCE(a.metadata_json,'{}')
	      FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id` +
		where +
		` ORDER BY a.created_at DESC LIMIT ` + strconv.Itoa(per+1) + ` OFFSET ` + strconv.Itoa(offset)
	rows, err := u.store.DB().QueryContext(r.Context(), q, args...)
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
	view := struct {
		View
		Items   []auditEntry
		Page    int
		HasNext bool
		Filters auditFilters
	}{
		View:    u.viewFor(r, "Audit log · Settings", "settings", View{}),
		Items:   items,
		Page:    pageN,
		HasNext: hasNext,
		Filters: filters,
	}
	u.render(w, "audit.html", view)
}

// auditExportNDJSON streams every matching audit_log row as one JSON
// object per line. Admin-only — the audit_log can contain sensitive
// metadata + non-admins shouldn't be able to pull the full history.
func (u *UI) auditExportNDJSON(w http.ResponseWriter, r *http.Request) {
	if !u.isAdmin(r.Context()) {
		http.Error(w, "admin required", http.StatusForbidden)
		return
	}
	filters := parseAuditFilters(r)
	where, args := u.auditWhere(filters, u.phCounter())
	rows, err := u.store.DB().QueryContext(r.Context(),
		`SELECT a.id, a.created_at, COALESCE(u.email,''), COALESCE(a.actor_ip,''),
		        a.action, COALESCE(a.entity_type,''), COALESCE(a.entity_id,''),
		        COALESCE(a.metadata_json,'{}')
		 FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id`+where+
			` ORDER BY a.created_at DESC LIMIT 100000`, args...)
	if err != nil {
		http.Error(w, "list audit: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = rows.Close() }()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="audit.ndjson"`)
	enc := json.NewEncoder(w)
	for rows.Next() {
		var e auditEntry
		if err := rows.Scan(&e.ID, &e.CreatedAt, &e.ActorEmail, &e.ActorIP,
			&e.Action, &e.EntityType, &e.EntityID, &e.Metadata); err != nil {
			return
		}
		_ = enc.Encode(map[string]any{
			"id":          e.ID,
			"created_at":  e.CreatedAt,
			"actor_email": e.ActorEmail,
			"actor_ip":    e.ActorIP,
			"action":      e.Action,
			"entity_type": e.EntityType,
			"entity_id":   e.EntityID,
			"metadata":    json.RawMessage(e.Metadata),
		})
	}
}

// auditExportCSV streams every matching row as a CSV. Same admin gate
// + same upper bound.
func (u *UI) auditExportCSV(w http.ResponseWriter, r *http.Request) {
	if !u.isAdmin(r.Context()) {
		http.Error(w, "admin required", http.StatusForbidden)
		return
	}
	filters := parseAuditFilters(r)
	where, args := u.auditWhere(filters, u.phCounter())
	rows, err := u.store.DB().QueryContext(r.Context(),
		`SELECT a.id, a.created_at, COALESCE(u.email,''), COALESCE(a.actor_ip,''),
		        a.action, COALESCE(a.entity_type,''), COALESCE(a.entity_id,''),
		        COALESCE(a.metadata_json,'{}')
		 FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id`+where+
			` ORDER BY a.created_at DESC LIMIT 100000`, args...)
	if err != nil {
		http.Error(w, "list audit: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = rows.Close() }()
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="audit.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "created_at", "actor_email", "actor_ip", "action", "entity_type", "entity_id", "metadata_json"})
	for rows.Next() {
		var e auditEntry
		if err := rows.Scan(&e.ID, &e.CreatedAt, &e.ActorEmail, &e.ActorIP,
			&e.Action, &e.EntityType, &e.EntityID, &e.Metadata); err != nil {
			return
		}
		_ = cw.Write([]string{e.ID, e.CreatedAt, e.ActorEmail, e.ActorIP, e.Action, e.EntityType, e.EntityID, e.Metadata})
	}
	cw.Flush()
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
