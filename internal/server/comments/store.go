package comments

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// nowFn is the clock source for created/updated timestamps. Tests
// override this for deterministic ordering assertions.
var nowFn = func() time.Time { return time.Now().UTC() }

// SetClock overrides the clock used by the package; returns the
// previous value so callers can restore it. Used by tests.
func SetClock(fn func() time.Time) func() time.Time {
	prev := nowFn
	nowFn = fn
	return prev
}

// Source values flow into the comments.source column. The allowed
// set matches the CHECK constraint in migration 0008.
const (
	SourceUI       = "ui"
	SourceSlack    = "slack"
	SourceTeams    = "teams"
	SourceGitHubPR = "github-pr"
	SourceJira     = "jira"
	SourceLinear   = "linear"
)

// Comment is the per-row shape held by the daemon and exposed to
// the UI templates. AuthorEmail / AuthorDisplayName resolve out of
// the users table via JOIN at read time; comments table itself only
// stores the foreign key.
type Comment struct {
	ID                 string
	FindingFingerprint string
	AuthorID           string
	AuthorEmail        string
	AuthorDisplayName  string
	Body               string
	BodyHTML           string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	EditedAt           *time.Time
	Source             string
	ExternalID         string
}

// Repo is the persistence layer over the v1.8 comments table.
type Repo struct {
	store    *store.Store
	renderer *Renderer
}

// NewRepo wires a Repo against the given store. The default
// Renderer is used for markdown→HTML conversion.
func NewRepo(s *store.Store) *Repo {
	return &Repo{store: s, renderer: Default()}
}

// WithRenderer overrides the markdown renderer. Useful for tests
// that want to assert specific HTML output or skip rendering.
func (r *Repo) WithRenderer(rr *Renderer) *Repo { r.renderer = rr; return r }

// ErrEmptyBody is returned by Add and Edit when the markdown source
// is empty after trimming. The UI surfaces this as a flash.
var ErrEmptyBody = errors.New("comment body is empty")

// AddOptions is the optional non-UI metadata bag for Add. The UI
// path leaves this zero-valued; sink ingest paths populate Source
// + ExternalID so two-way sync can dedup re-delivery.
type AddOptions struct {
	Source     string
	ExternalID string
	CreatedAt  *time.Time
}

// Add inserts a comment authored by `authorID` against the
// finding identified by `fingerprint`. Returns the new row's ID.
//
// `body` is the markdown source as the operator typed it. The
// renderer produces body_html in the same write so list rendering
// stays cheap. ErrEmptyBody is returned if `body` trims to "".
func (r *Repo) Add(ctx context.Context, fingerprint, authorID, body string, opts AddOptions) (string, error) {
	body = strings.TrimSpace(body)
	if body == "" {
		return "", ErrEmptyBody
	}
	bodyHTML, err := r.renderer.Render(body)
	if err != nil {
		return "", fmt.Errorf("render markdown: %w", err)
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	now := nowFn().Format(time.RFC3339)
	if opts.CreatedAt != nil {
		now = opts.CreatedAt.UTC().Format(time.RFC3339)
	}
	source := opts.Source
	if source == "" {
		source = SourceUI
	}
	var externalID any
	if opts.ExternalID != "" {
		externalID = opts.ExternalID
	}
	q := "INSERT INTO comments (id, finding_fingerprint, author_user_id, body, body_html, created_at, updated_at, source, external_id) VALUES (" +
		ph(r.store, 1) + "," + ph(r.store, 2) + "," + ph(r.store, 3) + "," + ph(r.store, 4) + "," + ph(r.store, 5) + "," + ph(r.store, 6) + "," + ph(r.store, 7) + "," + ph(r.store, 8) + "," + ph(r.store, 9) + ")"
	if _, err := r.store.DB().ExecContext(ctx, q, id, fingerprint, nullable(authorID), body, bodyHTML, now, now, source, externalID); err != nil {
		return "", err
	}
	return id, nil
}

// Edit rewrites the comment body. EditedAt is stamped on first
// edit; subsequent edits keep the original EditedAt? No — every
// edit updates EditedAt so "edited Nm ago" tracks the latest write.
// Returns ErrEmptyBody for empty trimmed bodies.
func (r *Repo) Edit(ctx context.Context, id, body string) error {
	body = strings.TrimSpace(body)
	if body == "" {
		return ErrEmptyBody
	}
	bodyHTML, err := r.renderer.Render(body)
	if err != nil {
		return fmt.Errorf("render markdown: %w", err)
	}
	now := nowFn().Format(time.RFC3339)
	q := "UPDATE comments SET body = " + ph(r.store, 1) + ", body_html = " + ph(r.store, 2) +
		", updated_at = " + ph(r.store, 3) + ", edited_at = " + ph(r.store, 4) +
		" WHERE id = " + ph(r.store, 5)
	res, err := r.store.DB().ExecContext(ctx, q, body, bodyHTML, now, now, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Delete removes a comment. Returns sql.ErrNoRows if no row matched.
func (r *Repo) Delete(ctx context.Context, id string) error {
	q := "DELETE FROM comments WHERE id = " + ph(r.store, 1)
	res, err := r.store.DB().ExecContext(ctx, q, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ByID loads a single comment by primary key.
func (r *Repo) ByID(ctx context.Context, id string) (Comment, error) {
	q := selectComments + " WHERE c.id = " + ph(r.store, 1)
	row := r.store.DB().QueryRowContext(ctx, q, id)
	return scanComment(row)
}

// ListByFingerprint returns the ordered conversation attached to
// the given fingerprint, oldest-first. The UI renders bottom-to-top
// or top-to-bottom from the same slice.
func (r *Repo) ListByFingerprint(ctx context.Context, fingerprint string) ([]Comment, error) {
	q := selectComments + " WHERE c.finding_fingerprint = " + ph(r.store, 1) + " ORDER BY c.created_at ASC, c.id ASC"
	rows, err := r.store.DB().QueryContext(ctx, q, fingerprint)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Comment
	for rows.Next() {
		c, err := scanComment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CountByFingerprint returns how many comments are attached to the
// fingerprint. Drives the badge on the finding row.
func (r *Repo) CountByFingerprint(ctx context.Context, fingerprint string) (int, error) {
	var n int
	q := "SELECT COUNT(*) FROM comments WHERE finding_fingerprint = " + ph(r.store, 1)
	if err := r.store.DB().QueryRowContext(ctx, q, fingerprint).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// ByExternalID resolves a comment via its sink-native identifier.
// Used by inbound two-way sync paths to detect re-delivery.
func (r *Repo) ByExternalID(ctx context.Context, source, externalID string) (Comment, error) {
	q := selectComments + " WHERE c.source = " + ph(r.store, 1) + " AND c.external_id = " + ph(r.store, 2)
	row := r.store.DB().QueryRowContext(ctx, q, source, externalID)
	return scanComment(row)
}

// ─── helpers ───────────────────────────────────────────────────────────

const selectComments = `SELECT c.id, c.finding_fingerprint,
       COALESCE(c.author_user_id, ''),
       COALESCE(u.email, ''),
       COALESCE(u.display_name, ''),
       c.body, c.body_html, c.created_at, c.updated_at,
       COALESCE(c.edited_at, ''),
       c.source, COALESCE(c.external_id, '')
FROM comments c
LEFT JOIN users u ON u.id = c.author_user_id`

// rowScanner abstracts *sql.Row + *sql.Rows for scanComment.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanComment(s rowScanner) (Comment, error) {
	var (
		c        Comment
		editedAt string
	)
	if err := s.Scan(&c.ID, &c.FindingFingerprint, &c.AuthorID, &c.AuthorEmail,
		&c.AuthorDisplayName, &c.Body, &c.BodyHTML, &createdScan{&c.CreatedAt},
		&createdScan{&c.UpdatedAt}, &editedAt, &c.Source, &c.ExternalID); err != nil {
		return c, err
	}
	if editedAt != "" {
		if t, err := time.Parse(time.RFC3339, editedAt); err == nil {
			c.EditedAt = &t
		}
	}
	return c, nil
}

// createdScan is a *time.Time-friendly sql.Scanner that parses
// the RFC3339-encoded TEXT we store across SQLite + Postgres.
type createdScan struct{ dst *time.Time }

func (c *createdScan) Scan(src any) error {
	switch v := src.(type) {
	case string:
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return err
		}
		*c.dst = t
		return nil
	case []byte:
		t, err := time.Parse(time.RFC3339, string(v))
		if err != nil {
			return err
		}
		*c.dst = t
		return nil
	case time.Time:
		*c.dst = v
		return nil
	case nil:
		return nil
	}
	return fmt.Errorf("comments: unsupported time scan src %T", src)
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "cmnt_" + hex.EncodeToString(b[:]), nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func ph(s *store.Store, n int) string {
	if s.Driver() == store.DriverPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}
