package k8s

import (
	"context"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.21 phase 11 — coverage for the 15 DOKS/EKS/GKE manual-verify
// deepening checks in managed_extra.go. Every mkSpec emits exactly
// one StatusError finding per cluster context.

func TestManagedK8sManualVerify(t *testing.T) {
	g := gph(t, mkCluster("prod"))
	for _, spec := range managedExtraSpecs {
		t.Run(spec.id, func(t *testing.T) {
			fn, ok := compliancekit.Lookup(spec.id)
			if !ok {
				t.Fatalf("check %q not registered", spec.id)
			}
			findings, _ := fn(context.Background(), g)
			if len(findings) != 1 {
				t.Fatalf("want 1 finding per cluster, got %d", len(findings))
			}
			if findings[0].Status != compliancekit.StatusError {
				t.Errorf("status=%v want StatusError (manual-verify)", findings[0].Status)
			}
		})
	}
}

func TestManagedK8sSpecsCoverage(t *testing.T) {
	if len(managedExtraSpecs) < 15 {
		t.Errorf("managedExtraSpecs=%d entries; phase 8 expects ≥15 (5 per vendor)", len(managedExtraSpecs))
	}
	perVendor := map[string]int{}
	for _, s := range managedExtraSpecs {
		perVendor[s.vendor]++
		if s.title == "" || s.severity == 0 || s.vendor == "" || s.hint == "" {
			t.Errorf("incomplete managed spec: %+v", s)
		}
	}
	for _, v := range []string{"doks", "eks", "gke"} {
		if perVendor[v] == 0 {
			t.Errorf("no specs for vendor %q", v)
		}
	}
}
