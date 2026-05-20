package collab

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.OpenSQLite(context.Background(),
		"file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	if err := s.MigrateUp(context.Background()); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seedUser(t *testing.T, s *store.Store, id, email string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	q := "INSERT INTO users (id, email, display_name, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, 0, ?)"
	if _, err := s.DB().ExecContext(context.Background(), q, id, email, email, "x", now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func seedResource(t *testing.T, s *store.Store, id string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	q := "INSERT INTO resources (id, name, type, provider, first_seen_at, last_seen_at, attrs) VALUES (?, ?, ?, ?, ?, ?, ?)"
	if _, err := s.DB().ExecContext(context.Background(), q, id, id, "aws.ec2.instance", "aws", now, now, "{}"); err != nil {
		t.Fatalf("seed resource: %v", err)
	}
}

// TestAssignments_SetGetUnset round-trips a single fingerprint
// through the latest-wins shape + verifies the join populates the
// assignee email / display name.
func TestAssignments_SetGetUnset(t *testing.T) {
	s := openTestStore(t)
	seedUser(t, s, "u-alice", "alice@example.com")
	seedUser(t, s, "u-bob", "bob@example.com")
	a := NewAssignments(s)
	ctx := context.Background()
	fp := "fp-1"

	if _, err := a.Set(ctx, fp, "u-alice", "u-bob"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := a.Get(ctx, fp)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AssigneeID != "u-alice" || got.AssigneeEmail != "alice@example.com" {
		t.Errorf("first Get = %+v", got)
	}

	// Second Set rewrites the row.
	if _, err := a.Set(ctx, fp, "u-bob", "u-alice"); err != nil {
		t.Fatalf("Set 2: %v", err)
	}
	got, _ = a.Get(ctx, fp)
	if got.AssigneeID != "u-bob" {
		t.Errorf("second Get = %s, want u-bob", got.AssigneeID)
	}

	if n, _ := a.CountByUser(ctx, "u-bob"); n != 1 {
		t.Errorf("CountByUser(bob) = %d, want 1", n)
	}

	if err := a.Unset(ctx, fp); err != nil {
		t.Fatalf("Unset: %v", err)
	}
	if _, err := a.Get(ctx, fp); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("post-Unset Get = %v, want ErrNoRows", err)
	}
}

// TestOwners_SetGet verifies the upsert + join paths.
func TestOwners_SetGet(t *testing.T) {
	s := openTestStore(t)
	seedUser(t, s, "u-owner", "owner@example.com")
	seedResource(t, s, "aws.ec2.instance.web-1")
	o := NewOwners(s)
	ctx := context.Background()
	if _, err := o.Set(ctx, "aws.ec2.instance.web-1", "u-owner", ""); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := o.Get(ctx, "aws.ec2.instance.web-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.OwnerID != "u-owner" || got.OwnerEmail != "owner@example.com" {
		t.Errorf("Get = %+v", got)
	}
}

// TestActivities_RoundTrip records a mix of events + reads them
// back in chronological order; metadata round-trips through JSON.
func TestActivities_RoundTrip(t *testing.T) {
	s := openTestStore(t)
	seedUser(t, s, "u-actor", "actor@example.com")
	a := NewActivities(s)
	ctx := context.Background()
	fp := "fp-act"

	t0 := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	for i, kind := range []string{ActivityAssigned, ActivityCommentAdded, ActivityStateChanged} {
		stamp := t0.Add(time.Duration(i) * time.Second)
		if _, err := a.Record(ctx, fp, kind, RecordOptions{
			ActorID:   "u-actor",
			Metadata:  map[string]any{"idx": i},
			CreatedAt: &stamp,
		}); err != nil {
			t.Fatalf("Record(%s): %v", kind, err)
		}
	}
	got, err := a.List(ctx, fp)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if got[0].Kind != ActivityAssigned || got[2].Kind != ActivityStateChanged {
		t.Errorf("order broken: %v / %v", got[0].Kind, got[2].Kind)
	}
	if got[0].ActorEmail != "actor@example.com" {
		t.Errorf("actor email = %q", got[0].ActorEmail)
	}
	if got[1].Metadata["idx"] == nil {
		t.Errorf("metadata lost: %+v", got[1].Metadata)
	}
	n, _ := a.Count(ctx, fp)
	if n != 3 {
		t.Errorf("Count = %d, want 3", n)
	}
}

// TestExternalIssues_LinkClose round-trips the Jira/Linear mapping
// + verifies the close path marks every linked fingerprint.
func TestExternalIssues_LinkClose(t *testing.T) {
	s := openTestStore(t)
	seedUser(t, s, "u-creator", "creator@example.com")
	e := NewExternalIssues(s)
	ctx := context.Background()

	row1, err := e.Link(ctx, "fp-1", SystemJira, "PROJ-1", LinkOptions{
		ExternalURL: "https://acme.atlassian.net/browse/PROJ-1",
		CreatedByID: "u-creator",
	})
	if err != nil {
		t.Fatalf("Link 1: %v", err)
	}
	if _, err := e.Link(ctx, "fp-2", SystemJira, "PROJ-1", LinkOptions{}); err != nil {
		t.Fatalf("Link 2: %v", err)
	}

	all, err := e.ListByExternal(ctx, SystemJira, "PROJ-1")
	if err != nil {
		t.Fatalf("ListByExternal: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("listed %d, want 2", len(all))
	}

	if err := e.MarkClosed(ctx, row1.ID); err != nil {
		t.Fatalf("MarkClosed: %v", err)
	}
	got, err := e.Find(ctx, SystemJira, "PROJ-1", "fp-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.Status != ExternalIssueClosed {
		t.Errorf("status = %q, want closed", got.Status)
	}
	if got.ClosedAt == nil {
		t.Error("ClosedAt nil after close")
	}
}

// TestFollowers_AddIdempotent verifies the ON CONFLICT DO NOTHING
// path on the composite key.
func TestFollowers_AddIdempotent(t *testing.T) {
	s := openTestStore(t)
	seedUser(t, s, "u-fol", "follower@example.com")
	seedResource(t, s, "aws.ec2.instance.web-2")
	f := NewFollowers(s)
	ctx := context.Background()
	if err := f.Add(ctx, "aws.ec2.instance.web-2", "u-fol"); err != nil {
		t.Fatalf("Add 1: %v", err)
	}
	if err := f.Add(ctx, "aws.ec2.instance.web-2", "u-fol"); err != nil {
		t.Fatalf("Add 2 (idempotent): %v", err)
	}
	got, err := f.ListByResource(ctx, "aws.ec2.instance.web-2")
	if err != nil {
		t.Fatalf("ListByResource: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d, want 1", len(got))
	}
}
