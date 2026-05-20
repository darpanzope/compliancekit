// Package collab owns the v1.8 collaboration data layer that
// doesn't fit into the comments package: per-finding assignees,
// per-resource owners, and resource follower opt-ins.
//
// The split between this package and comments is deliberate:
// comments has its own goldmark + bluemonday pipeline + table.
// collab is the much-thinner CRUD layer over three small tables.
// Future phases (activity stream, mentions) layer on top.
package collab

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// nowFn lets tests pin timestamps. Production uses time.Now().UTC().
var nowFn = func() time.Time { return time.Now().UTC() }

// SetClock overrides the clock; returns the previous value so the
// caller can restore it. Used by tests.
func SetClock(fn func() time.Time) func() time.Time {
	prev := nowFn
	nowFn = fn
	return prev
}

// Assignments owns the finding_assignment table — latest-wins per
// fingerprint with history in finding_activity (Phase 3).
type Assignments struct{ store *store.Store }

// NewAssignments wires an Assignments handle.
func NewAssignments(s *store.Store) *Assignments { return &Assignments{store: s} }

// Assignment is the table-row shape including a JOIN against users
// for human-readable rendering.
type Assignment struct {
	Fingerprint   string
	AssigneeID    string
	AssigneeEmail string
	AssigneeName  string
	AssignedByID  string
	AssignedAt    time.Time
}

// Set upserts the (fingerprint, assignee) pair. assignedBy may be
// empty (system-driven assignment). Returns the new/updated row.
func (a *Assignments) Set(ctx context.Context, fingerprint, assigneeID, assignedByID string) (Assignment, error) {
	if fingerprint == "" || assigneeID == "" {
		return Assignment{}, errors.New("fingerprint and assigneeID required")
	}
	now := nowFn().UTC().Format(time.RFC3339)
	q := upsertAssignmentSQL(a.store)
	if _, err := a.store.DB().ExecContext(ctx, q, fingerprint, assigneeID, nullable(assignedByID), now); err != nil {
		return Assignment{}, err
	}
	return a.Get(ctx, fingerprint)
}

// Unset clears the assignment for the fingerprint. No-op if already
// unassigned. Returns sql.ErrNoRows if nothing was deleted (caller
// can ignore for an idempotent path).
func (a *Assignments) Unset(ctx context.Context, fingerprint string) error {
	q := "DELETE FROM finding_assignment WHERE finding_fingerprint = " + ph(a.store, 1)
	res, err := a.store.DB().ExecContext(ctx, q, fingerprint)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Get loads the current assignment for the fingerprint.
// Returns sql.ErrNoRows when no row exists.
func (a *Assignments) Get(ctx context.Context, fingerprint string) (Assignment, error) {
	q := selectAssignment + " WHERE fa.finding_fingerprint = " + ph(a.store, 1)
	row := a.store.DB().QueryRowContext(ctx, q, fingerprint)
	return scanAssignment(row)
}

// CountByUser returns how many findings are currently assigned to
// the user. Drives the v1.8 nav badge ("3 findings assigned").
func (a *Assignments) CountByUser(ctx context.Context, userID string) (int, error) {
	var n int
	q := "SELECT COUNT(*) FROM finding_assignment WHERE assignee_user_id = " + ph(a.store, 1)
	if err := a.store.DB().QueryRowContext(ctx, q, userID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// ListByUser returns the fingerprints assigned to the given user,
// most-recently-assigned first. Used by the "my findings" filter.
func (a *Assignments) ListByUser(ctx context.Context, userID string) ([]string, error) {
	q := "SELECT finding_fingerprint FROM finding_assignment WHERE assignee_user_id = " +
		ph(a.store, 1) + " ORDER BY assigned_at DESC"
	rows, err := a.store.DB().QueryContext(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		out = append(out, fp)
	}
	return out, rows.Err()
}

// ─── helpers ───────────────────────────────────────────────────────────

func upsertAssignmentSQL(s *store.Store) string {
	if s.Driver() == store.DriverPostgres {
		return `INSERT INTO finding_assignment (finding_fingerprint, assignee_user_id, assigned_by_user_id, assigned_at)
		        VALUES ($1, $2, $3, $4)
		        ON CONFLICT (finding_fingerprint) DO UPDATE SET
		          assignee_user_id    = EXCLUDED.assignee_user_id,
		          assigned_by_user_id = EXCLUDED.assigned_by_user_id,
		          assigned_at         = EXCLUDED.assigned_at`
	}
	return `INSERT INTO finding_assignment (finding_fingerprint, assignee_user_id, assigned_by_user_id, assigned_at)
	        VALUES (?, ?, ?, ?)
	        ON CONFLICT (finding_fingerprint) DO UPDATE SET
	          assignee_user_id    = excluded.assignee_user_id,
	          assigned_by_user_id = excluded.assigned_by_user_id,
	          assigned_at         = excluded.assigned_at`
}

const selectAssignment = `SELECT fa.finding_fingerprint,
       fa.assignee_user_id,
       COALESCE(u.email,''),
       COALESCE(u.display_name,''),
       COALESCE(fa.assigned_by_user_id,''),
       fa.assigned_at
FROM finding_assignment fa
LEFT JOIN users u ON u.id = fa.assignee_user_id`

type rowScanner interface{ Scan(dest ...any) error }

func scanAssignment(s rowScanner) (Assignment, error) {
	var (
		a       Assignment
		stampAt string
	)
	if err := s.Scan(&a.Fingerprint, &a.AssigneeID, &a.AssigneeEmail,
		&a.AssigneeName, &a.AssignedByID, &stampAt); err != nil {
		return a, err
	}
	if t, err := time.Parse(time.RFC3339, stampAt); err == nil {
		a.AssignedAt = t
	}
	return a, nil
}

func ph(s *store.Store, n int) string {
	if s.Driver() == store.DriverPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
