package k8s

import (
	"context"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.21 phase 11 — coverage for the 15 control-plane manual-verify
// checks in control_plane.go. Every cpvSpec emits exactly one
// StatusError finding per cluster context.

func TestControlPlaneManualVerify(t *testing.T) {
	g := gph(t, mkCluster("prod"))
	for _, spec := range cpvSpecs {
		t.Run(spec.id, func(t *testing.T) {
			fn, ok := core.Lookup(spec.id)
			if !ok {
				t.Fatalf("check %q not registered", spec.id)
			}
			findings, _ := fn(context.Background(), g)
			if len(findings) != 1 {
				t.Fatalf("want 1 finding per cluster, got %d", len(findings))
			}
			if findings[0].Status != core.StatusError {
				t.Errorf("status=%v want StatusError (manual-verify)", findings[0].Status)
			}
		})
	}
}

// TestControlPlaneSpecsCoverage asserts the cpvSpecs slice has the
// expected breadth so a future commit that removes specs accidentally
// fails fast rather than silently shrinking coverage.
func TestControlPlaneSpecsCoverage(t *testing.T) {
	if len(cpvSpecs) < 15 {
		t.Errorf("cpvSpecs=%d entries; phase 7 expects ≥15", len(cpvSpecs))
	}
	seen := map[string]bool{}
	for _, s := range cpvSpecs {
		if seen[s.id] {
			t.Errorf("duplicate cpv spec id: %s", s.id)
		}
		seen[s.id] = true
		if s.title == "" || s.severity == 0 || len(s.cis) == 0 || s.hint == "" {
			t.Errorf("incomplete cpv spec: %+v", s)
		}
	}
}
