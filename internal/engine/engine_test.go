package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// fakeCollector is a Collector test double that returns canned resources.
type fakeCollector struct {
	name      string
	resources []compliancekit.Resource
	err       error
}

func (f *fakeCollector) Name() string { return f.name }
func (f *fakeCollector) Collect(_ context.Context) ([]compliancekit.Resource, error) {
	return f.resources, f.err
}

func TestEngine_Run_HappyPath(t *testing.T) {
	reg := compliancekit.NewRegistry()
	reg.Register(compliancekit.Check{ID: "test-pass"}, func(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
		var out []compliancekit.Finding
		for _, r := range g.ByType("test.resource") {
			out = append(out, compliancekit.Finding{
				CheckID:  "test-pass",
				Status:   compliancekit.StatusPass,
				Resource: r.Ref(),
			})
		}
		return out, nil
	})

	coll := &fakeCollector{
		name: "fake",
		resources: []compliancekit.Resource{
			{ID: "test.resource.1", Type: "test.resource", Name: "alpha"},
			{ID: "test.resource.2", Type: "test.resource", Name: "beta"},
		},
	}

	eng := New([]compliancekit.Collector{coll}, reg)
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
	reg := compliancekit.NewRegistry()
	reg.Register(compliancekit.Check{ID: "test-fail"}, func(_ context.Context, _ *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
		return nil, errors.New("ouch")
	})
	reg.Register(compliancekit.Check{ID: "test-ok"}, func(_ context.Context, _ *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
		return []compliancekit.Finding{{CheckID: "test-ok", Status: compliancekit.StatusPass}}, nil
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
		case f.CheckID == "test-fail" && f.Status == compliancekit.StatusError:
			sawError = true
		case f.CheckID == "test-ok" && f.Status == compliancekit.StatusPass:
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
	reg := compliancekit.NewRegistry()
	coll := &fakeCollector{name: "broken", err: errors.New("network down")}

	eng := New([]compliancekit.Collector{coll}, reg)
	_, err := eng.Run(context.Background())
	if err == nil {
		t.Fatal("expected error when collector fails")
	}
	if !strings.Contains(err.Error(), "broken") {
		t.Errorf("error should name the broken collector: %v", err)
	}
}

func TestEngine_Run_ContextCancellation(t *testing.T) {
	reg := compliancekit.NewRegistry()
	reg.Register(compliancekit.Check{ID: "would-run"}, func(_ context.Context, _ *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
		t.Error("check ran despite canceled context")
		return nil, nil
	})
	coll := &fakeCollector{name: "would-run", resources: []compliancekit.Resource{{ID: "a", Type: "t"}}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	eng := New([]compliancekit.Collector{coll}, reg)
	_, err := eng.Run(ctx)
	if err == nil {
		t.Error("expected context error when context is canceled")
	}
}

func TestEngine_Run_FillsTimestampOnlyWhenMissing(t *testing.T) {
	// A check that explicitly sets Timestamp should have it preserved.
	custom := compliancekit.Finding{
		CheckID: "custom-time",
		Status:  compliancekit.StatusPass,
	}
	custom.Timestamp = custom.Timestamp.AddDate(2020, 0, 0) // a fixed past date

	reg := compliancekit.NewRegistry()
	reg.Register(compliancekit.Check{ID: "custom-time"}, func(_ context.Context, _ *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
		return []compliancekit.Finding{custom}, nil
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
