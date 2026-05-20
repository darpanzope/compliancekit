package ui

// v1.5 Phase 3 — Linear-style side-panel finding detail.
//
// Clicking a row in /findings opens a fixed side panel with the full
// check + resource + framework metadata. ESC or click-outside closes.
// No page reload — the row HTMX-loads /findings/{id}/detail and swaps
// the result into a target div. The same shape backs a future Phase
// 4 (remediation studio) by extending the same partial.

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// findingDetail is the side-panel payload.
type findingDetail struct {
	View
	Row          findingRow
	CheckTitle   string
	CheckDesc    string
	CheckRemed   string
	CheckRefs    []string
	WaiverCount  int
	WaiverActive bool
}

// mountFindingDetailRoutes registers the Phase 3 endpoint.
func (u *UI) mountFindingDetailRoutes(r chi.Router) {
	r.Get("/findings/{id}/detail", u.findingDetailPartial)
}

// findingDetailPartial returns the side-panel HTML (no daemon
// chrome) for one finding id. Targeted by an hx-get on each row.
func (u *UI) findingDetailPartial(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row, err := u.loadFindingByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Augment with check registry metadata (description / remediation /
	// references) — the registry has it but the findings table doesn't
	// duplicate it.
	checkTitle, checkDesc, checkRemed, checkRefs := lookupCheckMeta(row.CheckID)
	waiverCount, anyActive := u.countWaiversForResource(r.Context(), row.CheckID, row.ResourceID)

	detail := findingDetail{
		View:         u.viewFor(r, "", "findings", View{}),
		Row:          row,
		CheckTitle:   checkTitle,
		CheckDesc:    checkDesc,
		CheckRemed:   checkRemed,
		CheckRefs:    checkRefs,
		WaiverCount:  waiverCount,
		WaiverActive: anyActive,
	}

	// Render just the partial — no daemon chrome, htmx target is the
	// detail panel container.
	u.renderPartial(w, "finding_detail", detail)
}

// loadFindingByID is the single-row variant of queryFindings.
func (u *UI) loadFindingByID(ctx context.Context, id string) (findingRow, error) {
	var r findingRow
	var fwJSON string
	err := u.store.DB().QueryRowContext(ctx,
		`SELECT id, scan_id, check_id, severity, status, provider,
		        resource_id, resource_name, resource_type, COALESCE(message,''),
		        COALESCE(framework_ids,'[]'),
		        first_seen_at, last_seen_at, fingerprint
		 FROM findings WHERE id = `+ph(u.store, 1),
		id).Scan(&r.ID, &r.ScanID, &r.CheckID, &r.Severity, &r.Status, &r.Provider,
		&r.ResourceID, &r.ResourceName, &r.ResourceType, &r.Message,
		&fwJSON, &r.FirstSeen, &r.LastSeen, &r.Fingerprint)
	if err != nil {
		return r, err
	}
	_ = json.Unmarshal([]byte(fwJSON), &r.Frameworks)
	now := time.Now()
	if t, e := time.Parse(time.RFC3339, r.FirstSeen); e == nil {
		r.FirstSeenIn = humanizeAgoFrom(t, now)
	}
	if t, e := time.Parse(time.RFC3339, r.LastSeen); e == nil {
		r.LastSeenIn = humanizeAgoFrom(t, now)
	}
	if u.comments != nil {
		if n, err := u.comments.CountByFingerprint(ctx, r.Fingerprint); err == nil {
			r.CommentCount = n
		}
	}
	return r, nil
}

// countWaiversForResource returns the total number of waivers
// matching (check_id, resource_id) and whether any are currently
// active (not expired, not revoked). Drives the "Waivers" panel
// section in the detail view.
func (u *UI) countWaiversForResource(ctx context.Context, checkID, resourceID string) (total int, anyActive bool) {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT COALESCE(expires_at,''), COALESCE(revoked_at,'')
		 FROM waivers WHERE check_id = `+ph(u.store, 1)+
			` AND (resource_id = `+ph(u.store, 2)+` OR resource_id = '*')`,
		checkID, resourceID)
	if err != nil {
		return 0, false
	}
	defer func() { _ = rows.Close() }()
	now := time.Now()
	for rows.Next() {
		var expires, revoked string
		if err := rows.Scan(&expires, &revoked); err != nil {
			continue
		}
		total++
		if revoked != "" {
			continue
		}
		if expires != "" {
			if t, e := time.Parse(time.RFC3339, expires); e == nil && t.Before(now) {
				continue
			}
		}
		anyActive = true
	}
	return total, anyActive
}

// lookupCheckMeta walks compliancekit.RegisteredChecks for the id.
// Returns ("", "", "", nil) when the check is unknown — happens when
// a finding was ingested from a CLI scan that ran a custom check the
// daemon's binary doesn't know about.
func lookupCheckMeta(id string) (title, desc, remediation string, refs []string) {
	for _, c := range compliancekit.RegisteredChecks() {
		if c.ID == id {
			return c.Title, c.Description, c.Remediation, c.References
		}
	}
	return "", "", "", nil
}
