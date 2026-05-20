package collab

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// External issue system identifiers — the canonical CHECK list in
// migration 0011.
const (
	SystemJira   = "jira"
	SystemLinear = "linear"
)

// ExternalIssueStatus values. Mirrors the Jira/Linear coarse state
// machine — daemon never tries to model the operator's custom
// workflow, just open vs done.
const (
	ExternalIssueOpen   = "open"
	ExternalIssueClosed = "closed"
)

// ExternalIssue is one row in external_issue_mapping.
type ExternalIssue struct {
	ID          string
	Fingerprint string
	System      string // jira | linear
	ExternalID  string
	ExternalURL string
	Status      string
	CreatedByID string
	CreatedAt   time.Time
	ClosedAt    *time.Time
}

// ExternalIssues is the persistence handle.
type ExternalIssues struct{ store *store.Store }

// NewExternalIssues wires the handle.
func NewExternalIssues(s *store.Store) *ExternalIssues { return &ExternalIssues{store: s} }

// LinkOptions is the optional metadata bag passed to Link.
type LinkOptions struct {
	ExternalURL string
	CreatedByID string
	Status      string
}

// Link inserts a (fingerprint, system, external_id) row. Idempotent
// via the UNIQUE constraint: re-linking the same triple is a no-op
// but returns the existing row.
func (e *ExternalIssues) Link(ctx context.Context, fingerprint, system, externalID string, opts LinkOptions) (ExternalIssue, error) {
	if fingerprint == "" || system == "" || externalID == "" {
		return ExternalIssue{}, errors.New("collab: Link needs fingerprint, system, external_id")
	}
	if system != SystemJira && system != SystemLinear {
		return ExternalIssue{}, errors.New("collab: unsupported system: " + system)
	}
	status := opts.Status
	if status == "" {
		status = ExternalIssueOpen
	}
	id, err := newExternalIssueID()
	if err != nil {
		return ExternalIssue{}, err
	}
	now := nowFn().UTC().Format(time.RFC3339)
	q := insertExternalIssueSQL(e.store)
	if _, err := e.store.DB().ExecContext(ctx, q, id, fingerprint, system, externalID,
		opts.ExternalURL, status, nullable(opts.CreatedByID), now); err != nil {
		return ExternalIssue{}, err
	}
	return e.Find(ctx, system, externalID, fingerprint)
}

// Find returns the row for the (system, external_id, fingerprint)
// triple. Returns sql.ErrNoRows if not present.
func (e *ExternalIssues) Find(ctx context.Context, system, externalID, fingerprint string) (ExternalIssue, error) {
	q := selectExternalIssue + " WHERE system = " + ph(e.store, 1) +
		" AND external_id = " + ph(e.store, 2) + " AND fingerprint = " + ph(e.store, 3)
	row := e.store.DB().QueryRowContext(ctx, q, system, externalID, fingerprint)
	return scanExternalIssue(row)
}

// ListByExternal returns every fingerprint linked to the same
// (system, external_id) pair. The webhook handlers use this to
// fan a status update across all linked findings.
func (e *ExternalIssues) ListByExternal(ctx context.Context, system, externalID string) ([]ExternalIssue, error) {
	q := selectExternalIssue + " WHERE system = " + ph(e.store, 1) +
		" AND external_id = " + ph(e.store, 2)
	rows, err := e.store.DB().QueryContext(ctx, q, system, externalID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ExternalIssue
	for rows.Next() {
		row, err := scanExternalIssue(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// MarkClosed flips status="closed" + stamps closed_at for the row.
// Returns sql.ErrNoRows if no row matched.
func (e *ExternalIssues) MarkClosed(ctx context.Context, id string) error {
	now := nowFn().UTC().Format(time.RFC3339)
	q := "UPDATE external_issue_mapping SET status = 'closed', closed_at = " +
		ph(e.store, 1) + " WHERE id = " + ph(e.store, 2)
	res, err := e.store.DB().ExecContext(ctx, q, now, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListByFingerprint returns every external link for the finding.
// Drives the side-panel "Linked issues" chips.
func (e *ExternalIssues) ListByFingerprint(ctx context.Context, fingerprint string) ([]ExternalIssue, error) {
	q := selectExternalIssue + " WHERE fingerprint = " + ph(e.store, 1) +
		" ORDER BY created_at ASC"
	rows, err := e.store.DB().QueryContext(ctx, q, fingerprint)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ExternalIssue
	for rows.Next() {
		row, err := scanExternalIssue(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// ─── helpers ───────────────────────────────────────────────────────────

const selectExternalIssue = `SELECT id, fingerprint, system, external_id, external_url,
       status, COALESCE(created_by_user_id, ''), created_at, COALESCE(closed_at, '')
FROM external_issue_mapping`

func insertExternalIssueSQL(s *store.Store) string {
	if s.Driver() == store.DriverPostgres {
		return `INSERT INTO external_issue_mapping (id, fingerprint, system, external_id, external_url, status, created_by_user_id, created_at)
		        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		        ON CONFLICT (system, external_id, fingerprint) DO NOTHING`
	}
	return `INSERT INTO external_issue_mapping (id, fingerprint, system, external_id, external_url, status, created_by_user_id, created_at)
	        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	        ON CONFLICT (system, external_id, fingerprint) DO NOTHING`
}

func scanExternalIssue(s rowScanner) (ExternalIssue, error) {
	var (
		out      ExternalIssue
		stampAt  string
		closedAt string
	)
	if err := s.Scan(&out.ID, &out.Fingerprint, &out.System, &out.ExternalID,
		&out.ExternalURL, &out.Status, &out.CreatedByID, &stampAt, &closedAt); err != nil {
		return out, err
	}
	if t, err := time.Parse(time.RFC3339, stampAt); err == nil {
		out.CreatedAt = t
	}
	if closedAt != "" {
		if t, err := time.Parse(time.RFC3339, closedAt); err == nil {
			out.ClosedAt = &t
		}
	}
	return out, nil
}

func newExternalIssueID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "ei_" + hex.EncodeToString(b[:]), nil
}
