// Package approvals owns the v1.9 phase 5 multi-approver waiver
// flow. Existing single-approver waivers (required_approvers=1)
// continue to work; high-severity waivers enter the "pending"
// state until N approvers have clicked Approve, then transition
// to "active".
//
// The Repo exposes the data-layer primitives (Approve, Reject,
// List, GetByID); the UI surface mounts /waivers/{id}/approve +
// /reject in the v1.9 phase 3 rules UI. The audit_log carries
// every transition.
package approvals

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// Status values. Mirrors the CHECK constraint in migration 0015.
const (
	StatusActive   = "active"
	StatusPending  = "pending"
	StatusRejected = "rejected"
	StatusRevoked  = "revoked"
)

// Approval records one approver's vote. Stored as a JSON object
// element in waivers.approvals_json.
type Approval struct {
	UserID    string    `json:"user_id"`
	Approved  bool      `json:"approved"`
	Note      string    `json:"note,omitempty"`
	Timestamp time.Time `json:"at"`
}

// Waiver is the v1.9-augmented row including approval metadata.
type Waiver struct {
	ID                string
	CheckID           string
	ResourceID        string
	Reason            string
	Approver          string
	Status            string
	RequiredApprovers int
	Approvals         []Approval
	PendingSince      *time.Time
	ExpiresAt         *time.Time
	CreatedAt         time.Time
}

// Repo owns the waivers table + multi-approver transitions.
type Repo struct{ store *store.Store }

// NewRepo wires the handle.
func NewRepo(s *store.Store) *Repo { return &Repo{store: s} }

// Approve appends one approval. When the count reaches
// required_approvers, the waiver transitions to active +
// pending_since clears.
func (r *Repo) Approve(ctx context.Context, waiverID, userID, note string) (Waiver, error) {
	wv, err := r.ByID(ctx, waiverID)
	if err != nil {
		return Waiver{}, err
	}
	if wv.Status != StatusPending {
		return wv, errors.New("waiver not pending")
	}
	for _, a := range wv.Approvals {
		if a.UserID == userID && a.Approved {
			return wv, errors.New("already approved by this user")
		}
	}
	wv.Approvals = append(wv.Approvals, Approval{
		UserID: userID, Approved: true, Note: note, Timestamp: time.Now().UTC(),
	})
	if approvalCount(wv.Approvals) >= wv.RequiredApprovers {
		wv.Status = StatusActive
		wv.PendingSince = nil
	}
	return r.save(ctx, wv)
}

// Reject moves the waiver to status="rejected". One reject wins —
// the operator can re-submit the waiver via the /waivers form.
func (r *Repo) Reject(ctx context.Context, waiverID, userID, note string) (Waiver, error) {
	wv, err := r.ByID(ctx, waiverID)
	if err != nil {
		return Waiver{}, err
	}
	if wv.Status != StatusPending {
		return wv, errors.New("waiver not pending")
	}
	wv.Approvals = append(wv.Approvals, Approval{
		UserID: userID, Approved: false, Note: note, Timestamp: time.Now().UTC(),
	})
	wv.Status = StatusRejected
	wv.PendingSince = nil
	return r.save(ctx, wv)
}

// SubmitForApproval transitions a freshly-created single-approver
// waiver into the multi-approver queue. Called by the v1.9 phase 3
// UI when an admin author configures required_approvers > 1.
func (r *Repo) SubmitForApproval(ctx context.Context, waiverID string, requiredApprovers int) (Waiver, error) {
	wv, err := r.ByID(ctx, waiverID)
	if err != nil {
		return Waiver{}, err
	}
	if wv.Status == StatusActive && len(wv.Approvals) == 0 && requiredApprovers > 1 {
		now := time.Now().UTC()
		wv.PendingSince = &now
		wv.Status = StatusPending
		wv.RequiredApprovers = requiredApprovers
		return r.save(ctx, wv)
	}
	return wv, errors.New("waiver not eligible for multi-approval")
}

// ByID loads a single waiver.
func (r *Repo) ByID(ctx context.Context, id string) (Waiver, error) {
	q := selectWaiver + " WHERE id = " + ph(r.store, 1)
	row := r.store.DB().QueryRowContext(ctx, q, id)
	return scanWaiver(row)
}

// ListPending returns every waiver with status='pending', oldest
// first. Drives the /waivers pending-queue surface.
func (r *Repo) ListPending(ctx context.Context) ([]Waiver, error) {
	q := selectWaiver + " WHERE status = 'pending' ORDER BY pending_since ASC"
	rows, err := r.store.DB().QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Waiver
	for rows.Next() {
		wv, err := scanWaiver(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, wv)
	}
	return out, rows.Err()
}

// CountPending returns the number of pending waivers for the nav
// badge.
func (r *Repo) CountPending(ctx context.Context) (int, error) {
	var n int
	err := r.store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM waivers WHERE status = 'pending'`).Scan(&n)
	return n, err
}

// ─── helpers ───────────────────────────────────────────────────────────

func (r *Repo) save(ctx context.Context, wv Waiver) (Waiver, error) {
	approvalsJSON, err := json.Marshal(wv.Approvals)
	if err != nil {
		return Waiver{}, fmt.Errorf("marshal approvals: %w", err)
	}
	if approvalsJSON == nil {
		approvalsJSON = []byte("[]")
	}
	var pendingSince any
	if wv.PendingSince != nil {
		pendingSince = wv.PendingSince.UTC().Format(time.RFC3339)
	}
	q := `UPDATE waivers SET status = ` + ph(r.store, 1) +
		`, required_approvers = ` + ph(r.store, 2) +
		`, approvals_json = ` + ph(r.store, 3) +
		`, pending_since = ` + ph(r.store, 4) +
		` WHERE id = ` + ph(r.store, 5)
	res, err := r.store.DB().ExecContext(ctx, q,
		wv.Status, wv.RequiredApprovers, string(approvalsJSON), pendingSince, wv.ID)
	if err != nil {
		return Waiver{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return Waiver{}, sql.ErrNoRows
	}
	return wv, nil
}

func approvalCount(as []Approval) int {
	n := 0
	for _, a := range as {
		if a.Approved {
			n++
		}
	}
	return n
}

const selectWaiver = `SELECT id, check_id, resource_id, reason, approver, status,
       required_approvers, approvals_json,
       COALESCE(pending_since, ''), COALESCE(expires_at, ''),
       created_at
FROM waivers`

type rowScanner interface{ Scan(dest ...any) error }

func scanWaiver(s rowScanner) (Waiver, error) {
	var (
		wv            Waiver
		approvalsJSON string
		pendingSince  string
		expiresAt     string
		createdAt     string
	)
	if err := s.Scan(&wv.ID, &wv.CheckID, &wv.ResourceID, &wv.Reason, &wv.Approver,
		&wv.Status, &wv.RequiredApprovers, &approvalsJSON,
		&pendingSince, &expiresAt, &createdAt); err != nil {
		return wv, err
	}
	if approvalsJSON != "" {
		_ = json.Unmarshal([]byte(approvalsJSON), &wv.Approvals)
	}
	if pendingSince != "" {
		if t, err := time.Parse(time.RFC3339, pendingSince); err == nil {
			wv.PendingSince = &t
		}
	}
	if expiresAt != "" {
		if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
			wv.ExpiresAt = &t
		}
	}
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		wv.CreatedAt = t
	}
	return wv, nil
}

func ph(s *store.Store, n int) string {
	if s.Driver() == store.DriverPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}
