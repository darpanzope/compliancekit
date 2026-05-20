package comments

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// openTestStore boots a fresh in-memory SQLite store + applies the
// full migration set. Each test gets its own database via t.Name().
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

// seedUser inserts a minimal user row + returns its id.
func seedUser(t *testing.T, s *store.Store, email, name string) string {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	q := "INSERT INTO users (id, email, display_name, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, 0, ?)"
	id := "u_" + name
	if _, err := s.DB().ExecContext(context.Background(), q, id, email, name, "x", now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// TestRepo_AddListEdit covers the happy-path round trip + verifies
// authoring metadata + the goldmark→bluemonday pipeline runs.
func TestRepo_AddListEdit(t *testing.T) {
	s := openTestStore(t)
	authorID := seedUser(t, s, "alice@example.com", "Alice")
	repo := NewRepo(s)
	ctx := context.Background()
	fp := "fp-1"

	t1 := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Second)
	id1, err := repo.Add(ctx, fp, authorID, "Hello **world**", AddOptions{CreatedAt: &t1})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	id2, err := repo.Add(ctx, fp, authorID, "second comment", AddOptions{CreatedAt: &t2})
	if err != nil {
		t.Fatalf("Add 2: %v", err)
	}

	list, err := repo.ListByFingerprint(ctx, fp)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d, want 2", len(list))
	}
	if list[0].ID != id1 || list[1].ID != id2 {
		t.Errorf("ordering broken: %v", []string{list[0].ID, list[1].ID})
	}
	if list[0].AuthorEmail != "alice@example.com" {
		t.Errorf("AuthorEmail = %q, want alice@example.com", list[0].AuthorEmail)
	}
	if !contains(list[0].BodyHTML, "<strong>world</strong>") {
		t.Errorf("rendered body lost <strong>: %s", list[0].BodyHTML)
	}

	// Edit
	time.Sleep(2 * time.Millisecond) // ensure updated_at distinct from created_at
	if err := repo.Edit(ctx, id1, "Edited markdown"); err != nil {
		t.Fatalf("Edit: %v", err)
	}
	got, err := repo.ByID(ctx, id1)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.Body != "Edited markdown" {
		t.Errorf("body = %q, want Edited markdown", got.Body)
	}
	if got.EditedAt == nil {
		t.Error("EditedAt nil after edit")
	}

	// Count
	n, err := repo.CountByFingerprint(ctx, fp)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 2 {
		t.Errorf("count = %d, want 2", n)
	}
}

// TestRepo_EmptyBodyRejected confirms whitespace-only bodies bounce.
func TestRepo_EmptyBodyRejected(t *testing.T) {
	s := openTestStore(t)
	authorID := seedUser(t, s, "bob@example.com", "Bob")
	repo := NewRepo(s)
	if _, err := repo.Add(context.Background(), "fp", authorID, "   \t\n  ", AddOptions{}); !errors.Is(err, ErrEmptyBody) {
		t.Errorf("Add empty = %v, want ErrEmptyBody", err)
	}
}

// TestRepo_DeleteIsHard verifies hard-delete (no soft-delete column
// at v1.8) — operator action requires admin/author gate at the
// handler layer; repo is unguarded.
func TestRepo_DeleteIsHard(t *testing.T) {
	s := openTestStore(t)
	authorID := seedUser(t, s, "carol@example.com", "Carol")
	repo := NewRepo(s)
	ctx := context.Background()
	id, err := repo.Add(ctx, "fp-del", authorID, "delete me", AddOptions{})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := repo.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := repo.ByID(ctx, id); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("post-delete ByID = %v, want ErrNoRows", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
