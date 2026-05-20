package collab

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// Owners owns the resource_owner table — one row per resource,
// upserted by Set. The resource_id FK CASCADES on resource delete.
type Owners struct{ store *store.Store }

// NewOwners wires an Owners handle.
func NewOwners(s *store.Store) *Owners { return &Owners{store: s} }

// ResourceOwner is the JOIN-augmented row exposed to the UI.
type ResourceOwner struct {
	ResourceID   string
	OwnerID      string
	OwnerEmail   string
	OwnerName    string
	AssignedByID string
	AssignedAt   time.Time
}

// Set upserts the (resource, owner) pair. assignedBy may be empty.
func (o *Owners) Set(ctx context.Context, resourceID, ownerID, assignedByID string) (ResourceOwner, error) {
	if resourceID == "" || ownerID == "" {
		return ResourceOwner{}, errors.New("resourceID and ownerID required")
	}
	now := nowFn().UTC().Format(time.RFC3339)
	q := upsertOwnerSQL(o.store)
	if _, err := o.store.DB().ExecContext(ctx, q, resourceID, ownerID, nullable(assignedByID), now); err != nil {
		return ResourceOwner{}, err
	}
	return o.Get(ctx, resourceID)
}

// Unset clears the owner for the resource.
func (o *Owners) Unset(ctx context.Context, resourceID string) error {
	q := "DELETE FROM resource_owner WHERE resource_id = " + ph(o.store, 1)
	res, err := o.store.DB().ExecContext(ctx, q, resourceID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Get returns the current owner record for the resource.
func (o *Owners) Get(ctx context.Context, resourceID string) (ResourceOwner, error) {
	q := selectOwner + " WHERE ro.resource_id = " + ph(o.store, 1)
	row := o.store.DB().QueryRowContext(ctx, q, resourceID)
	return scanOwner(row)
}

// CountByUser returns the number of resources owned by the user.
func (o *Owners) CountByUser(ctx context.Context, userID string) (int, error) {
	var n int
	q := "SELECT COUNT(*) FROM resource_owner WHERE owner_user_id = " + ph(o.store, 1)
	if err := o.store.DB().QueryRowContext(ctx, q, userID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// ─── helpers ───────────────────────────────────────────────────────────

func upsertOwnerSQL(s *store.Store) string {
	if s.Driver() == store.DriverPostgres {
		return `INSERT INTO resource_owner (resource_id, owner_user_id, assigned_by_user_id, assigned_at)
		        VALUES ($1, $2, $3, $4)
		        ON CONFLICT (resource_id) DO UPDATE SET
		          owner_user_id       = EXCLUDED.owner_user_id,
		          assigned_by_user_id = EXCLUDED.assigned_by_user_id,
		          assigned_at         = EXCLUDED.assigned_at`
	}
	return `INSERT INTO resource_owner (resource_id, owner_user_id, assigned_by_user_id, assigned_at)
	        VALUES (?, ?, ?, ?)
	        ON CONFLICT (resource_id) DO UPDATE SET
	          owner_user_id       = excluded.owner_user_id,
	          assigned_by_user_id = excluded.assigned_by_user_id,
	          assigned_at         = excluded.assigned_at`
}

const selectOwner = `SELECT ro.resource_id,
       ro.owner_user_id,
       COALESCE(u.email,''),
       COALESCE(u.display_name,''),
       COALESCE(ro.assigned_by_user_id,''),
       ro.assigned_at
FROM resource_owner ro
LEFT JOIN users u ON u.id = ro.owner_user_id`

func scanOwner(s rowScanner) (ResourceOwner, error) {
	var (
		o       ResourceOwner
		stampAt string
	)
	if err := s.Scan(&o.ResourceID, &o.OwnerID, &o.OwnerEmail, &o.OwnerName,
		&o.AssignedByID, &stampAt); err != nil {
		return o, err
	}
	if t, err := time.Parse(time.RFC3339, stampAt); err == nil {
		o.AssignedAt = t
	}
	return o, nil
}
