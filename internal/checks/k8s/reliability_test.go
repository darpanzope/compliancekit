package k8s

import (
	"context"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.21 phase 11 — coverage for the 12 reliability + supply-chain
// additions in reliability.go.

func TestReliability(t *testing.T) {
	cases := []struct {
		name     string
		id       string
		podAttrs map[string]any
		wantPass bool
	}{
		// readinessProbe
		{"readiness probe present → pass", "k8s-pod-readiness-probe",
			map[string]any{"containers": []any{
				map[string]any{"name": "app", "kind": "container", "has_readiness_probe": true, "has_liveness_probe": true},
			}}, true},
		{"readiness probe absent → fail", "k8s-pod-readiness-probe",
			map[string]any{"containers": []any{
				map[string]any{"name": "app", "kind": "container", "has_readiness_probe": false, "has_liveness_probe": true},
			}}, false},
		// ephemeral-storage
		{"ephemeral storage limit present → pass", "k8s-pod-ephemeral-storage-limit",
			map[string]any{"containers": []any{
				map[string]any{"name": "app", "kind": "container", "has_ephemeral_storage_limit": true},
			}}, true},
		{"ephemeral storage limit absent → fail", "k8s-pod-ephemeral-storage-limit",
			map[string]any{"containers": []any{
				map[string]any{"name": "app", "kind": "container", "has_ephemeral_storage_limit": false},
			}}, false},
		// topologySpread
		{"topology spread present → pass", "k8s-pod-topology-spread-constraints",
			map[string]any{"topology_spread_constraints": 2}, true},
		{"topology spread absent → fail", "k8s-pod-topology-spread-constraints",
			map[string]any{"topology_spread_constraints": 0}, false},
		// image digest pinned
		{"images digest-pinned → pass", "k8s-pod-image-digest-pinned",
			map[string]any{"containers": []any{
				map[string]any{"name": "app", "kind": "container", "image_digest_pinned": true},
			}}, true},
		{"images not digest-pinned → fail", "k8s-pod-image-digest-pinned",
			map[string]any{"containers": []any{
				map[string]any{"name": "app", "kind": "container", "image_digest_pinned": false},
			}}, false},
		// termination grace
		{"terminationGracePeriod set → pass", "k8s-pod-termination-grace-period-explicit",
			map[string]any{"termination_grace_period": int64(60)}, true},
		{"terminationGracePeriod unset → fail", "k8s-pod-termination-grace-period-explicit",
			map[string]any{"termination_grace_period": int64(0)}, false},
		// owner ref
		{"owner ref present → pass", "k8s-pod-has-owner-ref",
			map[string]any{"owner_kind": "Deployment"}, true},
		{"owner ref absent → fail", "k8s-pod-has-owner-ref",
			map[string]any{"owner_kind": ""}, false},
		// host ports
		{"no host ports → pass", "k8s-pod-no-host-ports",
			map[string]any{"containers": []any{
				map[string]any{"name": "app", "kind": "container", "host_ports": []int{}},
			}}, true},
		{"host ports present → fail", "k8s-pod-no-host-ports",
			map[string]any{"containers": []any{
				map[string]any{"name": "app", "kind": "container", "host_ports": []int{8080}},
			}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pod := mkPod("p1", c.podAttrs)
			fn, ok := core.Lookup(c.id)
			if !ok {
				t.Fatalf("check %q not registered", c.id)
			}
			findings, _ := fn(context.Background(), gph(t, pod))
			got := findings[0].Status == core.StatusPass
			if got != c.wantPass {
				t.Errorf("status=%v want pass=%v (msg=%q)", findings[0].Status, c.wantPass, findings[0].Message)
			}
		})
	}
}
