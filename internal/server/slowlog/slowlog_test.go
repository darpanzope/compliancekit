package slowlog

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRecorder_FastQueryNoSlowCount(t *testing.T) {
	r := New(50*time.Millisecond, 0, nil)
	r.Record(context.Background(), "SELECT 1", 5*time.Millisecond, 1)
	groups, _, slow := r.Stats()
	if slow != 0 {
		t.Errorf("slow count = %d, want 0", slow)
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %d", len(groups))
	}
	if groups[0].Calls != 1 {
		t.Errorf("Calls = %d", groups[0].Calls)
	}
}

func TestRecorder_SlowQueryIncrements(t *testing.T) {
	r := New(10*time.Millisecond, 0, nil)
	r.Record(context.Background(), "SELECT * FROM findings", 50*time.Millisecond, 100)
	r.Record(context.Background(), "SELECT * FROM findings", 80*time.Millisecond, 200)
	r.Record(context.Background(), "SELECT * FROM scans", 5*time.Millisecond, 5)
	groups, _, slow := r.Stats()
	if slow != 2 {
		t.Errorf("slow count = %d, want 2", slow)
	}
	if len(groups) != 2 {
		t.Errorf("distinct query groups = %d, want 2", len(groups))
	}
	// Findings query should be first after the totalMS sort.
	if groups[0].SQL != "SELECT * FROM findings" {
		t.Errorf("top group = %q", groups[0].SQL)
	}
	if groups[0].MaxMS != 80 {
		t.Errorf("MaxMS = %d, want 80", groups[0].MaxMS)
	}
}

func TestQueryID_StableAcrossWhitespace(t *testing.T) {
	a := queryID("SELECT  *  FROM\nfindings")
	b := queryID("select * from findings")
	if a != b {
		t.Errorf("queryID not stable across whitespace + case: %q vs %q", a, b)
	}
}

func TestRedact_StringsRedacted(t *testing.T) {
	in := `SELECT * FROM findings WHERE check_id = 'aws.iam.mfa' AND severity = 'critical'`
	out := redact(in)
	if out != `SELECT * FROM findings WHERE check_id = '?' AND severity = '?'` {
		t.Errorf("redact = %q", out)
	}
}

func TestTracker_OverBudget(t *testing.T) {
	r := New(0, 100*time.Millisecond, nil)
	tr := r.NewTracker()
	tr.Add(40 * time.Millisecond)
	if tr.OverBudget() {
		t.Error("40ms should be under 100ms budget")
	}
	tr.Add(80 * time.Millisecond)
	if !tr.OverBudget() {
		t.Error("120ms should be over 100ms budget")
	}
}

func TestTimeQuery_AccountsForElapsed(t *testing.T) {
	r := New(1*time.Millisecond, 0, nil)
	tr := r.NewTracker()
	ctx := WithTracker(context.Background(), tr)

	want := errors.New("boom")
	got := TimeQuery(ctx, r, "SELECT 1", func() (int, error) {
		time.Sleep(5 * time.Millisecond)
		return 1, want
	})
	if !errors.Is(got, want) {
		t.Errorf("error = %v, want %v", got, want)
	}
	if tr.Total() == 0 {
		t.Error("tracker total should be >0")
	}
	_, _, slow := r.Stats()
	if slow == 0 {
		t.Error("slow count should be ≥1 (5ms > 1ms threshold)")
	}
}

func TestTimeQuery_NilRecorderPasses(t *testing.T) {
	if err := TimeQuery(context.Background(), nil, "SELECT 1", func() (int, error) {
		return 1, nil
	}); err != nil {
		t.Errorf("nil recorder should pass through: %v", err)
	}
}
