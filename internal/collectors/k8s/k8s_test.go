package k8s

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// fakeScope returns a ContextScope wired to an empty fake clientset.
// Tests use it to exercise the orchestration without hitting a real
// cluster.
func fakeScope(t *testing.T, name, server string) *ContextScope {
	t.Helper()
	return &ContextScope{
		Name:   name,
		Server: server,
		Client: fake.NewSimpleClientset(),
	}
}

// writeKubeconfig writes a minimal but valid kubeconfig at path,
// returning the resulting path. The cert-data fields are not real
// certs; client-go only validates them when the clientset actually
// makes a request, which Phase 0 tests do not.
func writeKubeconfig(t *testing.T, path string, contexts []string, current string) {
	t.Helper()
	b := "apiVersion: v1\nkind: Config\n"
	if current != "" {
		b += "current-context: " + current + "\n"
	}
	b += "clusters:\n"
	for _, c := range contexts {
		b += "- name: " + c + "-cluster\n"
		b += "  cluster:\n"
		b += "    server: https://" + c + ".example.invalid:6443\n"
		b += "    insecure-skip-tls-verify: true\n"
	}
	b += "users:\n"
	for _, c := range contexts {
		b += "- name: " + c + "-user\n"
		b += "  user:\n"
		b += "    token: fake-token-" + c + "\n"
	}
	b += "contexts:\n"
	for _, c := range contexts {
		b += "- name: " + c + "\n"
		b += "  context:\n"
		b += "    cluster: " + c + "-cluster\n"
		b += "    user: " + c + "-user\n"
	}
	if err := os.WriteFile(path, []byte(b), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
}

func TestNew_LoadsCurrentContext(t *testing.T) {
	dir := t.TempDir()
	kc := filepath.Join(dir, "kubeconfig")
	writeKubeconfig(t, kc, []string{"prod", "dev"}, "prod")

	col, err := New(Options{KubeconfigPath: kc})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := col.Contexts()
	if len(got) != 1 || got[0] != "prod" {
		t.Fatalf("Contexts() = %v, want [prod]", got)
	}
}

func TestNew_ExplicitContexts(t *testing.T) {
	dir := t.TempDir()
	kc := filepath.Join(dir, "kubeconfig")
	writeKubeconfig(t, kc, []string{"prod", "dev"}, "prod")

	col, err := New(Options{KubeconfigPath: kc, Contexts: []string{"dev", "prod"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := col.Contexts()
	if len(got) != 2 || got[0] != "dev" || got[1] != "prod" {
		t.Fatalf("Contexts() = %v, want [dev prod]", got)
	}
}

func TestNew_UnknownContext(t *testing.T) {
	dir := t.TempDir()
	kc := filepath.Join(dir, "kubeconfig")
	writeKubeconfig(t, kc, []string{"prod"}, "prod")

	if _, err := New(Options{KubeconfigPath: kc, Contexts: []string{"nope"}}); err == nil {
		t.Fatalf("New: expected error for missing context")
	}
}

func TestNew_NoCurrentContext(t *testing.T) {
	dir := t.TempDir()
	kc := filepath.Join(dir, "kubeconfig")
	writeKubeconfig(t, kc, []string{"prod"}, "")

	if _, err := New(Options{KubeconfigPath: kc}); err == nil {
		t.Fatalf("New: expected error when current-context is empty and Contexts is empty")
	}
}

func TestContextScope_Region(t *testing.T) {
	s := &ContextScope{Name: "x", Server: "https://api.example.invalid:6443"}
	if got := s.Region(); got != "api.example.invalid:6443" {
		t.Errorf("Region() = %q, want host:port", got)
	}

	s2 := &ContextScope{Name: "y", Server: "not-a-url"}
	if got := s2.Region(); got != "not-a-url" {
		t.Errorf("Region() fallback = %q, want raw server", got)
	}

	s3 := &ContextScope{Name: "z"}
	if got := s3.Region(); got != "" {
		t.Errorf("Region() empty = %q, want \"\"", got)
	}
}

func TestCollect_EmitsClusterAnchor(t *testing.T) {
	// Build scopes manually with empty fake clientsets so the
	// workloads sub-collector returns 0 pods cleanly. Tests that
	// drive listPods against a backing object set live in
	// workloads_test.go.
	scopes := []*ContextScope{
		fakeScope(t, "prod", "https://prod.example.invalid:6443"),
		fakeScope(t, "dev", "https://dev.example.invalid:6443"),
	}
	col := NewWithScopes(scopes)

	resources, err := col.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Two anchors expected. Phase 1 adds workloads but with empty
	// fake clientsets there are zero pods to emit.
	if len(resources) != 2 {
		t.Fatalf("Collect: %d resources, want 2 anchors", len(resources))
	}
	for i, want := range []string{"prod", "dev"} {
		r := resources[i]
		if r.Type != ClusterType {
			t.Errorf("resources[%d].Type = %q, want %q", i, r.Type, ClusterType)
		}
		if r.Name != want {
			t.Errorf("resources[%d].Name = %q, want %q", i, r.Name, want)
		}
		if r.Attributes["context"] != want {
			t.Errorf("resources[%d] attr.context = %v, want %q", i, r.Attributes["context"], want)
		}
		if got := r.Attributes["region"]; got != want+".example.invalid:6443" {
			t.Errorf("resources[%d] attr.region = %v, want host:port", i, got)
		}
	}
}

func TestCollectError_Shape(t *testing.T) {
	col := &Collector{}
	scope := &ContextScope{Name: "prod", Server: "https://api.example.invalid"}
	r := col.collectError(scope, "rbac", os.ErrPermission)

	if r.Type != CollectErrorType {
		t.Errorf("Type = %q, want %q", r.Type, CollectErrorType)
	}
	if r.Attributes["service"] != "rbac" {
		t.Errorf("attr.service = %v, want rbac", r.Attributes["service"])
	}
	if r.Attributes["context"] != "prod" {
		t.Errorf("attr.context = %v, want prod", r.Attributes["context"])
	}
	if got := r.Attributes["error"]; got == nil || got == "" {
		t.Errorf("attr.error empty")
	}
}

// Compile-time guard: Collector satisfies compliancekit.Collector.
var _ compliancekit.Collector = (*Collector)(nil)
