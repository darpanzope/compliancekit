package collab

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// Activity kinds — the canonical set the finding_activity.kind CHECK
// constraint allows. Re-exported as strings so emitters don't have to
// reach into the migration file to remember the spelling.
const (
	ActivityStateChanged    = "state_changed"
	ActivityCommentAdded    = "comment_added"
	ActivityCommentEdited   = "comment_edited"
	ActivityWaiverApplied   = "waiver_applied"
	ActivityWaiverRevoked   = "waiver_revoked"
	ActivityScanRan         = "scan_ran"
	ActivityWebhookEvent    = "webhook_event"
	ActivityAssigned        = "assigned"
	ActivityUnassigned      = "unassigned"
	ActivityOwnerChanged    = "owner_changed"
	ActivityFollowerAdded   = "follower_added"
	ActivityFollowerRemoved = "follower_removed"
)

// ActorSource values are the canonical set finding_activity.actor_source
// allows (ui / engine / slack / teams / github-pr / jira / linear / webhook).
const (
	ActorUI       = "ui"
	ActorEngine   = "engine"
	ActorSlack    = "slack"
	ActorTeams    = "teams"
	ActorGitHubPR = "github-pr"
	ActorJira     = "jira"
	ActorLinear   = "linear"
	ActorWebhook  = "webhook"
)

// Activity is one chronological event in a finding's life.
type Activity struct {
	ID          string
	Fingerprint string
	CreatedAt   time.Time
	Kind        string
	ActorID     string
	ActorEmail  string
	ActorName   string
	ActorSource string
	Metadata    map[string]any
}

// Activities is the persistence handle for the finding_activity
// table. Emitters call Record from the spot in the codebase where
// the event was generated; consumers (the timeline UI) call List.
type Activities struct{ store *store.Store }

// NewActivities wires an Activities handle.
func NewActivities(s *store.Store) *Activities { return &Activities{store: s} }

// RecordOptions is the optional metadata bag passed to Record. Most
// callers only set Metadata; tests set CreatedAt for deterministic
// ordering.
type RecordOptions struct {
	ActorID     string
	ActorSource string
	Metadata    map[string]any
	CreatedAt   *time.Time
}

// Record persists one activity row. Empty Kind / Fingerprint fail
// loud — the activity table is the auditor's read-only contract and
// a malformed row would silently distort the timeline.
func (a *Activities) Record(ctx context.Context, fingerprint, kind string, opts RecordOptions) (string, error) {
	if fingerprint == "" || kind == "" {
		return "", fmt.Errorf("collab: Record needs fingerprint and kind")
	}
	id, err := newActivityID()
	if err != nil {
		return "", err
	}
	now := nowFn().UTC().Format(time.RFC3339)
	if opts.CreatedAt != nil {
		now = opts.CreatedAt.UTC().Format(time.RFC3339)
	}
	source := opts.ActorSource
	if source == "" {
		source = ActorUI
	}
	metaJSON := "{}"
	if len(opts.Metadata) > 0 {
		b, err := json.Marshal(opts.Metadata)
		if err == nil {
			metaJSON = string(b)
		}
	}
	q := "INSERT INTO finding_activity (id, finding_fingerprint, created_at, kind, actor_user_id, actor_source, metadata_json) VALUES (" +
		ph(a.store, 1) + "," + ph(a.store, 2) + "," + ph(a.store, 3) + "," + ph(a.store, 4) + "," + ph(a.store, 5) + "," + ph(a.store, 6) + "," + ph(a.store, 7) + ")"
	if _, err := a.store.DB().ExecContext(ctx, q, id, fingerprint, now, kind, nullable(opts.ActorID), source, metaJSON); err != nil {
		return "", err
	}
	return id, nil
}

// List returns the activity log for a fingerprint, oldest-first.
// The detail-panel timeline tab renders bottom-to-top from the same
// slice (CSS column-reverse).
func (a *Activities) List(ctx context.Context, fingerprint string) ([]Activity, error) {
	q := selectActivity + " WHERE fa.finding_fingerprint = " + ph(a.store, 1) +
		" ORDER BY fa.created_at ASC, fa.id ASC"
	rows, err := a.store.DB().QueryContext(ctx, q, fingerprint)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Activity
	for rows.Next() {
		row, err := scanActivity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// Count returns the number of activity rows for the fingerprint.
func (a *Activities) Count(ctx context.Context, fingerprint string) (int, error) {
	var n int
	q := "SELECT COUNT(*) FROM finding_activity WHERE finding_fingerprint = " + ph(a.store, 1)
	if err := a.store.DB().QueryRowContext(ctx, q, fingerprint).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// ─── helpers ───────────────────────────────────────────────────────────

const selectActivity = `SELECT fa.id, fa.finding_fingerprint, fa.created_at, fa.kind,
       COALESCE(fa.actor_user_id, ''),
       COALESCE(u.email, ''),
       COALESCE(u.display_name, ''),
       fa.actor_source, fa.metadata_json
FROM finding_activity fa
LEFT JOIN users u ON u.id = fa.actor_user_id`

func scanActivity(s rowScanner) (Activity, error) {
	var (
		out      Activity
		stampAt  string
		metaJSON string
	)
	if err := s.Scan(&out.ID, &out.Fingerprint, &stampAt, &out.Kind,
		&out.ActorID, &out.ActorEmail, &out.ActorName,
		&out.ActorSource, &metaJSON); err != nil {
		return out, err
	}
	if t, err := time.Parse(time.RFC3339, stampAt); err == nil {
		out.CreatedAt = t
	}
	out.Metadata = map[string]any{}
	if metaJSON != "" {
		_ = json.Unmarshal([]byte(metaJSON), &out.Metadata)
	}
	return out, nil
}

func newActivityID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "act_" + hex.EncodeToString(b[:]), nil
}
