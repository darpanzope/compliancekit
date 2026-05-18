package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/darpanzope/compliancekit/internal/server/auth"
)

// triggerScanRequest is the body POST /api/v1/scans accepts. Empty
// values mean "scan everything currently enabled" — phase 8's worker
// derives the providers + frameworks from compliancekit.yaml + the
// providers + checks_state tables.
type triggerScanRequest struct {
	Providers  []string `json:"providers,omitempty"`
	Frameworks []string `json:"frameworks,omitempty"`
	Profile    string   `json:"profile,omitempty"`
	Source     string   `json:"source,omitempty"` // "daemon" (default), "webhook", "schedule"
}

// triggerScanResponse echoes the created scan row's primary key +
// status so clients can poll GET /api/v1/scans/{id} for progress.
type triggerScanResponse struct {
	ScanID    string `json:"scan_id"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

// triggerScan enqueues a scan job by inserting a row into scans with
// status='queued'. Phase 8's worker pool polls for queued rows and
// runs them. The actor (session user or token holder) lands in the
// triggered_by_user_id / triggered_by_token_id columns for audit.
func (a *API) triggerScan(w http.ResponseWriter, r *http.Request) {
	req, err := decodeBody[triggerScanRequest](r)
	if err != nil {
		respondError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	source := req.Source
	if source == "" {
		source = "daemon"
	}
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339)
	providersJSON, _ := json.Marshal(req.Providers)
	frameworksJSON, _ := json.Marshal(req.Frameworks)

	actorUserID, actorTokenID := actorFromCtx(r)

	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`INSERT INTO scans (id, created_at, source, status, providers_scanned, frameworks_scanned,
		                    triggered_by_user_id, triggered_by_token_id)
		 VALUES (%s, %s, %s, %s, %s, %s, %s, %s)`,
		a.ph(1), a.ph(2), a.ph(3), a.ph(4), a.ph(5), a.ph(6), a.ph(7), a.ph(8))
	_, err = a.store.DB().ExecContext(r.Context(), q,
		id, now, source, "queued", string(providersJSON), string(frameworksJSON),
		nullableString(actorUserID), nullableString(actorTokenID))
	if err != nil {
		respondError(w, http.StatusInternalServerError, "insert scan: "+err.Error())
		return
	}
	a.auditLog(r, "scan.trigger", "scan", id, map[string]any{
		"providers": req.Providers, "frameworks": req.Frameworks, "profile": req.Profile,
	})
	respondJSON(w, r, http.StatusAccepted, triggerScanResponse{
		ScanID: id, Status: "queued", CreatedAt: now,
	})
}

// createWaiverRequest is the body POST /api/v1/waivers accepts.
type createWaiverRequest struct {
	CheckID    string `json:"check_id"`
	ResourceID string `json:"resource_id"`
	Reason     string `json:"reason"`
	Approver   string `json:"approver"`
	ExpiresAt  string `json:"expires_at,omitempty"` // RFC-3339; empty = no expiry
}

func (a *API) createWaiver(w http.ResponseWriter, r *http.Request) {
	req, err := decodeBody[createWaiverRequest](r)
	if err != nil {
		respondError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.CheckID == "" || req.ResourceID == "" || req.Reason == "" || req.Approver == "" {
		respondError(w, http.StatusBadRequest, "check_id, resource_id, reason, approver are all required")
		return
	}
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339)
	actorUserID, _ := actorFromCtx(r)

	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`INSERT INTO waivers (id, check_id, resource_id, reason, approver, created_by_user_id, created_at, expires_at)
		 VALUES (%s, %s, %s, %s, %s, %s, %s, %s)`,
		a.ph(1), a.ph(2), a.ph(3), a.ph(4), a.ph(5), a.ph(6), a.ph(7), a.ph(8))
	_, err = a.store.DB().ExecContext(r.Context(), q,
		id, req.CheckID, req.ResourceID, req.Reason, req.Approver,
		nullableString(actorUserID), now, nullableString(req.ExpiresAt))
	if err != nil {
		respondError(w, http.StatusInternalServerError, "insert waiver: "+err.Error())
		return
	}
	a.auditLog(r, "waiver.add", "waiver", id, map[string]any{
		"check_id": req.CheckID, "resource_id": req.ResourceID, "approver": req.Approver,
	})
	respondJSON(w, r, http.StatusCreated, waiverRow{
		ID: id, CheckID: req.CheckID, ResourceID: req.ResourceID,
		Reason: req.Reason, Approver: req.Approver, CreatedAt: now, ExpiresAt: req.ExpiresAt,
	})
}

// updateWaiverRequest accepts a partial update — only non-zero fields
// get written. expires_at can be set to a literal empty string to
// clear an existing expiry.
type updateWaiverRequest struct {
	Reason    *string `json:"reason,omitempty"`
	Approver  *string `json:"approver,omitempty"`
	ExpiresAt *string `json:"expires_at,omitempty"`
}

func (a *API) updateWaiver(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	req, err := decodeBody[updateWaiverRequest](r)
	if err != nil {
		respondError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	sets := []string{}
	args := []any{}
	i := 1
	if req.Reason != nil {
		sets = append(sets, "reason = "+a.ph(i))
		args = append(args, *req.Reason)
		i++
	}
	if req.Approver != nil {
		sets = append(sets, "approver = "+a.ph(i))
		args = append(args, *req.Approver)
		i++
	}
	if req.ExpiresAt != nil {
		sets = append(sets, "expires_at = "+a.ph(i))
		if *req.ExpiresAt == "" {
			args = append(args, nil)
		} else {
			args = append(args, *req.ExpiresAt)
		}
		i++
	}
	if len(sets) == 0 {
		respondError(w, http.StatusBadRequest, "no fields to update")
		return
	}
	args = append(args, id)
	q := fmt.Sprintf( //nolint:gosec // placeholders only; field names from constants
		`UPDATE waivers SET %s WHERE id = %s AND revoked_at IS NULL`,
		joinComma(sets), a.ph(i))
	res, err := a.store.DB().ExecContext(r.Context(), q, args...)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "update waiver: "+err.Error())
		return
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		respondError(w, http.StatusNotFound, "waiver not found or already revoked")
		return
	}
	a.auditLog(r, "waiver.update", "waiver", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) revokeWaiver(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`UPDATE waivers SET revoked_at = %s WHERE id = %s AND revoked_at IS NULL`,
		a.ph(1), a.ph(2))
	res, err := a.store.DB().ExecContext(r.Context(), q, time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "revoke waiver: "+err.Error())
		return
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		respondError(w, http.StatusNotFound, "waiver not found or already revoked")
		return
	}
	a.auditLog(r, "waiver.revoke", "waiver", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

// updateProviderRequest accepts an enabled flag + optional JSON
// config blob. Used by PUT /api/v1/providers/{id}.
type updateProviderRequest struct {
	Enabled    *bool           `json:"enabled,omitempty"`
	ConfigJSON json.RawMessage `json:"config_json,omitempty"`
}

func (a *API) updateProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	req, err := decodeBody[updateProviderRequest](r)
	if err != nil {
		respondError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.Enabled == nil && len(req.ConfigJSON) == 0 {
		respondError(w, http.StatusBadRequest, "no fields to update")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)

	// Upsert: provider rows may not exist until the operator
	// configures them via this endpoint. Use INSERT ... ON CONFLICT.
	var enabledVal int
	if req.Enabled != nil && *req.Enabled {
		enabledVal = 1
	}
	configVal := "{}"
	if len(req.ConfigJSON) > 0 {
		configVal = string(req.ConfigJSON)
	}
	var q string
	switch a.store.Driver() {
	case "postgres":
		q = fmt.Sprintf( //nolint:gosec // placeholders only; no user input
			`INSERT INTO providers (id, enabled, config_json, created_at, updated_at)
			 VALUES (%s, %s, %s, %s, %s)
			 ON CONFLICT (id) DO UPDATE SET
			   enabled = EXCLUDED.enabled, config_json = EXCLUDED.config_json, updated_at = EXCLUDED.updated_at`,
			a.ph(1), a.ph(2), a.ph(3), a.ph(4), a.ph(5))
	default:
		q = fmt.Sprintf( //nolint:gosec // placeholders only; no user input
			`INSERT INTO providers (id, enabled, config_json, created_at, updated_at)
			 VALUES (%s, %s, %s, %s, %s)
			 ON CONFLICT(id) DO UPDATE SET
			   enabled = excluded.enabled, config_json = excluded.config_json, updated_at = excluded.updated_at`,
			a.ph(1), a.ph(2), a.ph(3), a.ph(4), a.ph(5))
	}
	_, err = a.store.DB().ExecContext(r.Context(), q, id, enabledVal, configVal, now, now)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "upsert provider: "+err.Error())
		return
	}
	a.auditLog(r, "provider.update", "provider", id, map[string]any{
		"enabled": req.Enabled,
	})
	w.WriteHeader(http.StatusNoContent)
}

// toggleCheck flips the per-check enabled/disabled override. The
// request body is optional; when provided, accepts {"enabled": bool,
// "reason": string} for explicit state, otherwise the row's value is
// flipped (toggle semantics).
type toggleCheckRequest struct {
	Enabled *bool  `json:"enabled,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func (a *API) toggleCheck(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	req, err := decodeBody[toggleCheckRequest](r)
	if err != nil && !errors.Is(err, errEmptyBody) {
		respondError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}

	// Read current state (default enabled if no row).
	current := true
	row := a.store.DB().QueryRowContext(r.Context(),
		"SELECT enabled FROM checks_state WHERE check_id = "+a.ph(1), id)
	var enabledVal int
	scanErr := row.Scan(&enabledVal)
	if scanErr == nil {
		current = enabledVal != 0
	} else if !errors.Is(scanErr, sql.ErrNoRows) {
		respondError(w, http.StatusInternalServerError, "read checks_state: "+scanErr.Error())
		return
	}

	target := !current
	if req.Enabled != nil {
		target = *req.Enabled
	}

	actorUserID, _ := actorFromCtx(r)
	now := time.Now().UTC().Format(time.RFC3339)

	var q string
	var args []any
	switch a.store.Driver() {
	case "postgres":
		q = fmt.Sprintf( //nolint:gosec // placeholders only; no user input
			`INSERT INTO checks_state (check_id, enabled, disabled_reason, disabled_by_user_id, disabled_at, updated_at)
			 VALUES (%s, %s, %s, %s, %s, %s)
			 ON CONFLICT (check_id) DO UPDATE SET
			   enabled = EXCLUDED.enabled, disabled_reason = EXCLUDED.disabled_reason,
			   disabled_by_user_id = EXCLUDED.disabled_by_user_id, disabled_at = EXCLUDED.disabled_at,
			   updated_at = EXCLUDED.updated_at`,
			a.ph(1), a.ph(2), a.ph(3), a.ph(4), a.ph(5), a.ph(6))
	default:
		q = fmt.Sprintf( //nolint:gosec // placeholders only; no user input
			`INSERT INTO checks_state (check_id, enabled, disabled_reason, disabled_by_user_id, disabled_at, updated_at)
			 VALUES (%s, %s, %s, %s, %s, %s)
			 ON CONFLICT(check_id) DO UPDATE SET
			   enabled = excluded.enabled, disabled_reason = excluded.disabled_reason,
			   disabled_by_user_id = excluded.disabled_by_user_id, disabled_at = excluded.disabled_at,
			   updated_at = excluded.updated_at`,
			a.ph(1), a.ph(2), a.ph(3), a.ph(4), a.ph(5), a.ph(6))
	}
	targetVal := 1
	if !target {
		targetVal = 0
	}
	var disabledReason any
	var disabledAt any
	var disabledByUser any
	if !target {
		disabledReason = req.Reason
		disabledAt = now
		disabledByUser = nullableString(actorUserID)
	}
	args = []any{id, targetVal, disabledReason, disabledByUser, disabledAt, now}
	if _, err := a.store.DB().ExecContext(r.Context(), q, args...); err != nil {
		respondError(w, http.StatusInternalServerError, "upsert checks_state: "+err.Error())
		return
	}
	a.auditLog(r, "check.toggle", "check", id, map[string]any{"enabled": target, "reason": req.Reason})
	respondJSON(w, r, http.StatusOK, map[string]any{"check_id": id, "enabled": target})
}

// errEmptyBody is sentinel for "no body present" — decodeBody returns
// it so callers like toggleCheck can treat empty bodies as a valid
// no-payload request (semantic toggle).
var errEmptyBody = errors.New("empty body")

// decodeBody is a generic JSON-decoder. Returns errEmptyBody when the
// request has no payload (Content-Length 0 or io.EOF on Decode).
func decodeBody[T any](r *http.Request) (T, error) {
	var v T
	if r.ContentLength == 0 {
		return v, errEmptyBody
	}
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		return v, err
	}
	return v, nil
}

// actorFromCtx pulls the acting user_id + token_id from the request
// context. Token-auth populates both; session-auth populates only the
// user. Both can be empty in test paths that bypass middleware.
func actorFromCtx(r *http.Request) (userID, tokenID string) {
	if tok := auth.TokenFromContext(r.Context()); tok != nil {
		return tok.UserID, tok.ID
	}
	if sess := auth.FromContext(r.Context()); sess != nil {
		return sess.UserID, ""
	}
	return "", ""
}

// auditLog appends a row to audit_log. Best-effort — a failed audit
// write should never break the action that triggered it; the row
// will surface in /metrics for ops monitoring.
func (a *API) auditLog(r *http.Request, action, entityType, entityID string, metadata map[string]any) {
	actorUserID, actorTokenID := actorFromCtx(r)
	metaJSON, _ := json.Marshal(metadata)
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`INSERT INTO audit_log (id, created_at, actor_user_id, actor_token_id, actor_ip, action, entity_type, entity_id, metadata_json)
		 VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		a.ph(1), a.ph(2), a.ph(3), a.ph(4), a.ph(5), a.ph(6), a.ph(7), a.ph(8), a.ph(9))
	_, _ = a.store.DB().ExecContext(r.Context(), q,
		uuid.NewString(), time.Now().UTC().Format(time.RFC3339),
		nullableString(actorUserID), nullableString(actorTokenID),
		clientIPFromReq(r), action, entityType, entityID, string(metaJSON))
}

// nullableString returns nil for the empty string, the value itself
// otherwise. Lets INSERT statements distinguish "not set" from "set
// to empty" in NULL-able columns.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// joinComma is a tiny strings.Join shim that avoids one more import
// in this file. Used only for the UPDATE SET column list (small N).
func joinComma(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	out := xs[0]
	for _, x := range xs[1:] {
		out += ", " + x
	}
	return out
}

// clientIPFromReq strips the port off RemoteAddr. RealIP middleware
// has already set RemoteAddr to the X-Forwarded-For value when
// present.
func clientIPFromReq(r *http.Request) string {
	host := r.RemoteAddr
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}
