package k8s

import (
	"context"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.21 phase 11 — coverage for the 12 pod-security additions in
// pods_extra.go. Reuses the mkPod helper from pods_test.go and the
// gph helper from testhelpers_test.go.

func TestPodSecurityExtra(t *testing.T) {
	cases := []struct {
		name     string
		id       string
		podAttrs map[string]any
		wantPass bool
	}{
		// shareProcessNamespace — unset passes (defaults to false)
		{"shareProcessNamespace unset → pass", "k8s-pod-share-process-namespace", nil, true},
		{"shareProcessNamespace=true → fail", "k8s-pod-share-process-namespace",
			map[string]any{"share_process_namespace": true}, false},
		// dnsPolicy
		{"dnsPolicy=ClusterFirst → pass", "k8s-pod-dns-policy-not-default",
			map[string]any{"dns_policy": "ClusterFirst"}, true},
		{"dnsPolicy=Default → fail", "k8s-pod-dns-policy-not-default",
			map[string]any{"dns_policy": "Default"}, false},
		// priorityClassName explicit
		{"priorityClassName set → pass", "k8s-pod-priority-class-explicit",
			map[string]any{"priority_class_name": "production"}, true},
		{"priorityClassName unset → fail", "k8s-pod-priority-class-explicit",
			map[string]any{"priority_class_name": ""}, false},
		// hostUsers (false explicit passes)
		{"hostUsers=false → pass", "k8s-pod-host-users-disabled",
			map[string]any{"host_users": false}, true},
		{"hostUsers=true → fail", "k8s-pod-host-users-disabled",
			map[string]any{"host_users": true}, false},
		// fsGroup
		{"fsGroup=1000 → pass", "k8s-pod-fs-group-set",
			map[string]any{"pod_security": map[string]any{"fs_group": int64(1000)}}, true},
		// runAsGroup
		{"runAsGroup=0 → fail", "k8s-pod-run-as-group-set",
			map[string]any{"pod_security": map[string]any{"run_as_group": int64(0)}}, false},
		{"runAsGroup=1000 → pass", "k8s-pod-run-as-group-set",
			map[string]any{"pod_security": map[string]any{"run_as_group": int64(1000)}}, true},
		// volume subpath
		{"no subPath mounts → pass", "k8s-pod-volume-subpath-restricted",
			map[string]any{"volume_subpath_mounts": []string{}}, true},
		{"subPath mounts present → fail", "k8s-pod-volume-subpath-restricted",
			map[string]any{"volume_subpath_mounts": []string{"app/data:config"}}, false},
		// default SA
		{"explicit SA → pass", "k8s-pod-default-service-account",
			map[string]any{"service_account": "app-sa"}, true},
		{"default SA → fail", "k8s-pod-default-service-account",
			map[string]any{"service_account": "default"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pod := mkPod("p1", c.podAttrs)
			fn, ok := compliancekit.Lookup(c.id)
			if !ok {
				t.Fatalf("check %q not registered", c.id)
			}
			findings, _ := fn(context.Background(), gph(t, pod))
			got := findings[0].Status == compliancekit.StatusPass
			if got != c.wantPass {
				t.Errorf("status=%v want pass=%v (id=%s msg=%q)", findings[0].Status, c.wantPass, c.id, findings[0].Message)
			}
		})
	}
}
