package collab

import (
	"context"
	"errors"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// Followers owns the resource_follower join table. The v0.17 sinks
// + the v1.9 inbox 2.0 producer consult this when fanning out
// notifications.
type Followers struct{ store *store.Store }

// NewFollowers wires a Followers handle.
func NewFollowers(s *store.Store) *Followers { return &Followers{store: s} }

// Add opts the user in. Idempotent — re-adding is a no-op.
func (f *Followers) Add(ctx context.Context, resourceID, userID string) error {
	if resourceID == "" || userID == "" {
		return errors.New("resourceID and userID required")
	}
	now := nowFn().UTC().Format(time.RFC3339)
	q := insertFollowerSQL(f.store)
	_, err := f.store.DB().ExecContext(ctx, q, resourceID, userID, now)
	return err
}

// Remove opts the user out.
func (f *Followers) Remove(ctx context.Context, resourceID, userID string) error {
	q := "DELETE FROM resource_follower WHERE resource_id = " + ph(f.store, 1) +
		" AND user_id = " + ph(f.store, 2)
	_, err := f.store.DB().ExecContext(ctx, q, resourceID, userID)
	return err
}

// Following reports whether the user is opted in.
func (f *Followers) Following(ctx context.Context, resourceID, userID string) (bool, error) {
	var n int
	q := "SELECT COUNT(*) FROM resource_follower WHERE resource_id = " +
		ph(f.store, 1) + " AND user_id = " + ph(f.store, 2)
	if err := f.store.DB().QueryRowContext(ctx, q, resourceID, userID).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// ListByResource returns the userIDs following the given resource.
// Sinks fan-out to these when a finding event fires for the resource.
func (f *Followers) ListByResource(ctx context.Context, resourceID string) ([]string, error) {
	q := "SELECT user_id FROM resource_follower WHERE resource_id = " +
		ph(f.store, 1) + " ORDER BY created_at ASC"
	rows, err := f.store.DB().QueryContext(ctx, q, resourceID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			return nil, err
		}
		out = append(out, uid)
	}
	return out, rows.Err()
}

// CountByResource returns the follower count for the resource.
func (f *Followers) CountByResource(ctx context.Context, resourceID string) (int, error) {
	var n int
	q := "SELECT COUNT(*) FROM resource_follower WHERE resource_id = " + ph(f.store, 1)
	if err := f.store.DB().QueryRowContext(ctx, q, resourceID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func insertFollowerSQL(s *store.Store) string {
	if s.Driver() == store.DriverPostgres {
		return `INSERT INTO resource_follower (resource_id, user_id, created_at)
		        VALUES ($1, $2, $3)
		        ON CONFLICT DO NOTHING`
	}
	return `INSERT INTO resource_follower (resource_id, user_id, created_at)
	        VALUES (?, ?, ?)
	        ON CONFLICT DO NOTHING`
}
