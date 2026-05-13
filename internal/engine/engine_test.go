package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
)

// fakeCollector is a Collector test double that returns canned resources.
type fakeCollector struct {
	name      string
	resources []core.Resource
	err       error
}

func (f *fakeCollector) Name() string { return f.name }
func (f *fakeCollector) Collect(_ context.Context) ([]core.Resource, error) {
	return f.resources, f.err
}

func TestEngine_Run_HappyPath(t *testing.T) {
	reg := core.NewRegistry()
	reg.Register("test-pass", func(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
		var out []core.Finding
		for _, r := range g.ByType("test.resource") {
			out = append(out, core.Finding{
				CheckID:  "test-pass",
				Status:   core.StatusPass,
				Resource: r.Ref(),
			})
		}
		return out, nil
	})

	coll := &fakeCollector{
		name: "fake",
		resources: []core.Resource{
			{ID: "test.resource.1", Type: "test.resource", Name: "alpha"},
			{ID: "test.resource.2", Type: "test.resource", Name: "beta"},
		},
	}

	eng := New([]core.Collector{coll}, reg)
	res, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := res.Graph.Count(); got != 2 {
		t.Errorf("graph Count() = %d, want 2", got)
	}
	if got := len(res.Findings); got != 2 {
		t.Errorf("len(findings) = %d, want 2", got)
	}
	for _, f := range res.Findings {
		if f.Timestamp.IsZero() {
			t.Error("finding Timestamp is zero; engine should populate it")
		}
	}
}

func TestEngine_Run_CheckErrorBecomesStatusError(t *testing.T) {
	reg := core.NewRegistry()
	reg.Register("test-fail", func(_ context.Context, _ *core.ResourceGraph) ([]core.Finding, error) {
		return nil, errors.New("ouch")
	})
	reg.Register("test-ok", func(_ context.Context, _ *core.ResourceGraph) ([]core.Finding, error) {
		return []core.Finding{{CheckID: "test-ok", Status: core.StatusPass}}, nil
	})

	eng := New(nil, reg)
	res, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := len(res.Findings); got != 2 {
		t.Errorf("findings = %d, want 2 (1 error + 1 pass)", got)
	}

	var sawError, sawPass bool
	for _, f := range res.Findings {
		switch {
		case f.CheckID == "test-fail" && f.Status == core.StatusError:
			sawError = true
		case f.CheckID == "test-ok" && f.Status == core.StatusPass:
			sawPass = true
		}
	}
	if !sawError {
		t.Error("expected test-fail to produce a StatusError finding")
	}
	if !sawPass {
		t.Error("expected test-ok to still produce its StatusPass finding")
	}
}

func TestEngine_Run_CollectorErrorAborts(t *testing.T) {
	reg := core.NewRegistry()
	coll := &fakeCollector{name: "broken", err: errors.New("network down")}

	eng := New([]core.Collector{coll}, reg)
	_, err := eng.Run(context.Background())
	if err == nil {
		t.Fatal("expected error when collector fails")
	}
	if !strings.Contains(err.Error(), "broken") {
		t.Errorf("error should name the broken collector: %v", err)
	}
}

func TestEngine_Run_ContextCancellation(t *testing.T) {
	reg := core.NewRegistry()
	reg.Register("would-run", func(_ context.Context, _ *core.ResourceGraph) ([]core.Finding, error) {
		t.Error("check ran despite canceled context")
		return nil, nil
	})
	coll := &fakeCollector{name: "would-run", resources: []core.Resource{{ID: "a", Type: "t"}}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	eng := New([]core.Collector{coll}, reg)
	_, err := eng.Run(ctx)
	if err == nil {
		t.Error("expected context error when context is canceled")
	}
}

func TestEngine_Run_FillsTimestampOnlyWhenMissing(t *testing.T) {
	// A check that explicitly sets Timestamp should have it preserved.
	custom := core.Finding{
		CheckID: "custom-time",
		Status:  core.StatusPass,
	}
	custom.Timestamp = custom.Timestamp.AddDate(2020, 0, 0) // a fixed past date

	reg := core.NewRegistry()
	reg.Register("custom-time", func(_ context.Context, _ *core.ResourceGraph) ([]core.Finding, error) {
		return []core.Finding{custom}, nil
	})

	eng := New(nil, reg)
	res, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	if !res.Findings[0].Timestamp.Equal(custom.Timestamp) {
		t.Errorf("engine overwrote a pre-set timestamp: got %v, want %v",
			res.Findings[0].Timestamp, custom.Timestamp)
	}
}
