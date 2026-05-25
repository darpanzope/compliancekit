package leader

import (
	"context"
	"testing"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

func TestSQLiteAlwaysLeader(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(ctx, "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	defer func() { _ = st.Close() }()
	if err := st.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}

	e := New(st)
	if e.IsLeader() {
		t.Errorf("elector should not be leader before Start")
	}
	<-e.Start(ctx)
	if !e.IsLeader() {
		t.Errorf("SQLite elector should report leader=true post-Start")
	}
	e.Stop()
	// After Stop, SQLite path keeps leader=true (no contention
	// possible) — the field remains until process exit.
	if !e.IsLeader() {
		t.Errorf("SQLite elector should retain leader=true post-Stop")
	}
}

func TestLockKeyDisjointFromMigrationKey(t *testing.T) {
	// Hardcoded test: the migration lock in store/postgres.go uses
	// 0x636B5F6D69677261 ("ck_migra"); leader uses 0x636B5F6C656164
	// ("ck_lead"). They must differ — co-locating would deadlock
	// the daemon between migration + leader-election on first boot.
	const migrationKey int64 = 0x636B5F6D69677261
	if LockKey == migrationKey {
		t.Errorf("leader.LockKey collides with migration lock key %x", migrationKey)
	}
}
