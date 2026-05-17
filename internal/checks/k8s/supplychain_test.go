package k8s

import (
	"context"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.21 phase 11 — coverage for the 10 supply-chain additions in
// supplychain.go + the registryFromImage helper.

func TestSupplyChain(t *testing.T) {
	cases := []struct {
		name     string
		id       string
		podAttrs map[string]any
		wantPass bool
	}{
		// mutable tag
		{"semver tag → pass", "k8s-pod-image-tag-not-mutable",
			map[string]any{"containers": []any{
				map[string]any{"name": "app", "kind": "container", "image_tag": "v1.2.3"},
			}}, true},
		{"latest tag → fail", "k8s-pod-image-tag-not-mutable",
			map[string]any{"containers": []any{
				map[string]any{"name": "app", "kind": "container", "image_tag": "latest"},
			}}, false},
		// empty tag
		{"explicit tag → pass", "k8s-pod-image-tag-not-empty",
			map[string]any{"containers": []any{
				map[string]any{"name": "app", "kind": "container", "image_tag": "1.0"},
			}}, true},
		{"empty tag → fail", "k8s-pod-image-tag-not-empty",
			map[string]any{"containers": []any{
				map[string]any{"name": "app", "kind": "container", "image_tag": ""},
			}}, false},
		// pull policy consistency
		{"digest + IfNotPresent → pass", "k8s-pod-image-pull-policy-consistent",
			map[string]any{"containers": []any{
				map[string]any{"name": "app", "kind": "container", "image_digest_pinned": true, "image_pull_policy": "IfNotPresent", "image_tag": "1.0"},
			}}, true},
		{"mutable + IfNotPresent → fail", "k8s-pod-image-pull-policy-consistent",
			map[string]any{"containers": []any{
				map[string]any{"name": "app", "kind": "container", "image_digest_pinned": false, "image_pull_policy": "IfNotPresent", "image_tag": "latest"},
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

// TestRegistryFromImage exercises the OCI distribution-spec parsing
// of image references — defaulting to docker.io, recognizing
// hostname-with-port + dot-bearing registries.
func TestRegistryFromImage(t *testing.T) {
	cases := []struct {
		image string
		want  string
	}{
		{"nginx", "docker.io"},
		{"library/nginx", "docker.io"},
		{"ghcr.io/org/repo:v1", "ghcr.io"},
		{"private:5000/img:latest", "private:5000"},
		{"localhost:8080/app", "localhost:8080"},
		{"registry.example.com/myorg/app@sha256:abc", "registry.example.com"},
	}
	for _, c := range cases {
		t.Run(c.image, func(t *testing.T) {
			if got := registryFromImage(c.image); got != c.want {
				t.Errorf("registryFromImage(%q) = %q, want %q", c.image, got, c.want)
			}
		})
	}
}
