package k8s

import (
	"testing"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

func mkServiceAccount(ns, name string, attrs map[string]any) core.Resource {
	base := map[string]any{
		"namespace":               ns,
		"automount_token":         "unset",
		"image_pull_secret_count": 0,
		"secret_count":            0,
	}
	for k, v := range attrs {
		base[k] = v
	}
	return core.Resource{
		ID:         "k8s.sa.prod." + ns + "." + name,
		Type:       k8scol.ServiceAccountType,
		Name:       name,
		Provider:   "kubernetes",
		Attributes: base,
	}
}

func TestSADefaultAutomount(t *testing.T) {
	g := newPodGraph(
		mkServiceAccount("ns1", "default", map[string]any{"automount_token": "false"}),
		mkServiceAccount("ns2", "default", map[string]any{"automount_token": "true"}),
		mkServiceAccount("ns3", "default", map[string]any{"automount_token": "unset"}),
		mkServiceAccount("ns4", "custom", map[string]any{"automount_token": "true"}),
	)
	findings, err := SADefaultAutomount(t.Context(), g)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	pass := 0
	fail := 0
	for _, f := range findings {
		if f.Resource.Name == "custom" {
			t.Errorf("custom SA should not be checked")
		}
		switch f.Status {
		case core.StatusPass:
			pass++
		case core.StatusFail:
			fail++
		}
	}
	if pass != 1 || fail != 2 {
		t.Errorf("pass=%d fail=%d (want 1/2)", pass, fail)
	}
}

func TestSADefaultUsed(t *testing.T) {
	g := newPodGraph(
		mkPod("uses-default", map[string]any{"service_account": ""}),
		mkPod("uses-explicit-default", map[string]any{"service_account": "default"}),
		mkPod("uses-custom", map[string]any{"service_account": "web-sa"}),
	)
	got := runCheck(t, SADefaultUsed, g)
	if got["uses-default"] != core.StatusFail || got["uses-explicit-default"] != core.StatusFail {
		t.Errorf("default uses: %v", got)
	}
	if got["uses-custom"] != core.StatusPass {
		t.Errorf("custom: %v", got["uses-custom"])
	}
}

func TestSAOrphan(t *testing.T) {
	g := newPodGraph(
		mkServiceAccount("default", "default", nil),
		mkServiceAccount("default", "used", nil),
		mkServiceAccount("default", "orphan", nil),
		mkPod("p1", map[string]any{"service_account": "used"}),
	)
	got := runCheck(t, SAOrphan, g)
	if got["used"] != core.StatusPass {
		t.Errorf("used: %v", got["used"])
	}
	if got["orphan"] != core.StatusFail {
		t.Errorf("orphan: %v", got["orphan"])
	}
	if _, ok := got["default"]; ok {
		t.Errorf("default SA should be exempt")
	}
}

func TestSAImagePullSecrets(t *testing.T) {
	g := newPodGraph(
		mkServiceAccount("default", "private", map[string]any{"image_pull_secret_count": 1}),
		mkServiceAccount("default", "private-noips", map[string]any{"image_pull_secret_count": 0}),
		mkServiceAccount("default", "public", map[string]any{"image_pull_secret_count": 0}),
		mkPodWithContainer("private-pod", map[string]any{"image": "registry.acme.invalid/web:v1"}),
		mkPodWithContainer("private-noips-pod", map[string]any{"image": "registry.acme.invalid/api:v1"}),
		mkPodWithContainer("public-pod", map[string]any{"image": "docker.io/nginx:1.21"}),
	)
	// Wire up service_account names on the pods.
	g.Add(func() core.Resource {
		p := mkPod("priv1", map[string]any{"service_account": "private"})
		c := p.Attributes["containers"].([]any)[0].(map[string]any)
		c["image"] = "registry.acme.invalid/x:v1"
		return p
	}())
	g.Add(func() core.Resource {
		p := mkPod("priv2", map[string]any{"service_account": "private-noips"})
		c := p.Attributes["containers"].([]any)[0].(map[string]any)
		c["image"] = "registry.acme.invalid/y:v1"
		return p
	}())
	g.Add(func() core.Resource {
		p := mkPod("pub", map[string]any{"service_account": "public"})
		c := p.Attributes["containers"].([]any)[0].(map[string]any)
		c["image"] = "docker.io/nginx:1.21"
		return p
	}())

	got := runCheck(t, SAImagePullSecrets, g)
	if got["private"] != core.StatusPass {
		t.Errorf("private: %v", got["private"])
	}
	if got["private-noips"] != core.StatusFail {
		t.Errorf("private-noips: %v", got["private-noips"])
	}
	if got["public"] != core.StatusSkip {
		t.Errorf("public: %v (want skip)", got["public"])
	}
}

func TestIsPrivateRegistryImage(t *testing.T) {
	cases := map[string]bool{
		"nginx":                               false, // implicit docker.io
		"nginx:1.21":                          false,
		"docker.io/library/nginx:1.21":        false,
		"quay.io/coreos/etcd:v3.5":            false,
		"ghcr.io/owner/repo:tag":              false,
		"registry.k8s.io/coredns/coredns:v1":  false,
		"registry.acme.invalid/team/app:v1":   true,
		"private-registry.local:5000/img:tag": true,
	}
	for in, want := range cases {
		if got := isPrivateRegistryImage(in); got != want {
			t.Errorf("isPrivateRegistryImage(%q) = %v, want %v", in, got, want)
		}
	}
}
