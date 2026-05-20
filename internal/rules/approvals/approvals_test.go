package approvals

import (
	"context"
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

func seedWaiver(t *testing.T, s *store.Store, id string, required int) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	status := "pending"
	pendingSince := now
	if required == 1 {
		status = "active"
		pendingSince = ""
	}
	q := `INSERT INTO waivers (id, check_id, resource_id, reason, approver, created_at, status, required_approvers, pending_since)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	var ps any
	if pendingSince != "" {
		ps = pendingSince
	}
	_, err := s.DB().ExecContext(context.Background(), q,
		id, "ck.test", "res.1", "needs more than 16 chars here please", "ops",
		now, status, required, ps)
	if err != nil {
		t.Fatalf("seed waiver: %v", err)
	}
}

// TestApprove transitions pending → active after threshold reached.
func TestApprove(t *testing.T) {
	s := openTestStore(t)
	repo := NewRepo(s)
	seedWaiver(t, s, "wv1", 2)

	// First approval — still pending.
	wv, err := repo.Approve(context.Background(), "wv1", "u-alice", "fine")
	if err != nil {
		t.Fatalf("Approve 1: %v", err)
	}
	if wv.Status != StatusPending {
		t.Errorf("after 1/2: status = %q, want pending", wv.Status)
	}

	// Second approval — flips to active.
	wv, err = repo.Approve(context.Background(), "wv1", "u-bob", "agreed")
	if err != nil {
		t.Fatalf("Approve 2: %v", err)
	}
	if wv.Status != StatusActive {
		t.Errorf("after 2/2: status = %q, want active", wv.Status)
	}
	if wv.PendingSince != nil {
		t.Errorf("PendingSince should clear: %v", wv.PendingSince)
	}
}

// TestApprove_DuplicateUser rejects same-user double-approval.
func TestApprove_DuplicateUser(t *testing.T) {
	s := openTestStore(t)
	repo := NewRepo(s)
	seedWaiver(t, s, "wv2", 2)
	if _, err := repo.Approve(context.Background(), "wv2", "u-alice", ""); err != nil {
		t.Fatalf("first Approve: %v", err)
	}
	if _, err := repo.Approve(context.Background(), "wv2", "u-alice", ""); err == nil {
		t.Error("second approval by same user should fail")
	}
}

// TestReject transitions pending → rejected.
func TestReject(t *testing.T) {
	s := openTestStore(t)
	repo := NewRepo(s)
	seedWaiver(t, s, "wv3", 3)
	wv, err := repo.Reject(context.Background(), "wv3", "u-carol", "no, too risky")
	if err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if wv.Status != StatusRejected {
		t.Errorf("status = %q, want rejected", wv.Status)
	}
}

// TestRejectNonPending refuses when waiver isn't pending.
func TestRejectNonPending(t *testing.T) {
	s := openTestStore(t)
	repo := NewRepo(s)
	seedWaiver(t, s, "wv4", 1) // active
	if _, err := repo.Reject(context.Background(), "wv4", "u-x", ""); err == nil {
		t.Error("Reject of active waiver should fail")
	}
	_ = errors.New
}

// TestListPending returns pending waivers oldest first.
func TestListPending(t *testing.T) {
	s := openTestStore(t)
	repo := NewRepo(s)
	seedWaiver(t, s, "wv5", 2)
	seedWaiver(t, s, "wv6", 2)
	got, err := repo.ListPending(context.Background())
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d, want 2", len(got))
	}
	n, _ := repo.CountPending(context.Background())
	if n != 2 {
		t.Errorf("CountPending = %d, want 2", n)
	}
}
