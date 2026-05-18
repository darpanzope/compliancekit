package k8s

import (
	"context"
	"testing"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// mkPod constructs a synthetic Pod resource with the attribute shape
// the collector produces. Tests override individual keys via the
// attrs param; the defaults represent a hardened baseline pod.
func mkPod(name string, attrs map[string]any) compliancekit.Resource {
	base := map[string]any{
		"namespace":          "default",
		"host_network":       false,
		"host_pid":           false,
		"host_ipc":           false,
		"automount_sa_token": "false",
		"host_path_volumes":  []string{},
		"pod_security": map[string]any{
			"run_as_non_root": true,
			"seccomp_type":    "RuntimeDefault",
		},
		"containers": []any{
			map[string]any{
				"name":                  "app",
				"kind":                  "container",
				"image":                 "registry.example.com/app:v1.2.3",
				"image_tag":             "v1.2.3",
				"image_pull_policy":     "IfNotPresent",
				"privileged":            false,
				"allow_priv_escalation": false,
				"run_as_non_root":       true,
				"read_only_root_fs":     true,
				"capabilities_add":      []string{},
				"capabilities_drop":     []string{"ALL"},
				"seccomp_type":          "RuntimeDefault",
				"has_cpu_limit":         true,
				"has_memory_limit":      true,
				"has_cpu_request":       true,
				"has_memory_request":    true,
				"has_liveness_probe":    true,
				"host_ports":            []int{},
			},
		},
	}
	for k, v := range attrs {
		base[k] = v
	}
	return compliancekit.Resource{
		ID:         "k8s.pod.prod.default." + name,
		Type:       k8scol.PodType,
		Name:       name,
		Provider:   "kubernetes",
		Attributes: base,
	}
}

// mkPodWithContainer returns mkPod with a single container whose
// attributes are overridden by the given map.
func mkPodWithContainer(name string, container map[string]any) compliancekit.Resource {
	pod := mkPod(name, nil)
	containers := pod.Attributes["containers"].([]any)
	c := containers[0].(map[string]any)
	for k, v := range container {
		c[k] = v
	}
	return pod
}

func newPodGraph(pods ...compliancekit.Resource) *compliancekit.ResourceGraph {
	g := compliancekit.NewResourceGraph()
	for _, p := range pods {
		g.Add(p)
	}
	return g
}

func runCheck(t *testing.T, fn compliancekit.CheckFunc, g *compliancekit.ResourceGraph) map[string]compliancekit.Status {
	t.Helper()
	findings, err := fn(context.Background(), g)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	out := map[string]compliancekit.Status{}
	for _, f := range findings {
		out[f.Resource.Name] = f.Status
	}
	return out
}

func TestPodPrivileged(t *testing.T) {
	g := newPodGraph(
		mkPod("good", nil),
		mkPodWithContainer("bad", map[string]any{"privileged": true}),
	)
	got := runCheck(t, PodPrivileged, g)
	if got["good"] != compliancekit.StatusPass {
		t.Errorf("good: got %v", got["good"])
	}
	if got["bad"] != compliancekit.StatusFail {
		t.Errorf("bad: got %v", got["bad"])
	}
}

func TestPodHostNetwork(t *testing.T) {
	g := newPodGraph(
		mkPod("good", nil),
		mkPod("bad", map[string]any{"host_network": true}),
	)
	got := runCheck(t, PodHostNetwork, g)
	if got["good"] != compliancekit.StatusPass || got["bad"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestPodHostPID(t *testing.T) {
	g := newPodGraph(
		mkPod("good", nil),
		mkPod("bad", map[string]any{"host_pid": true}),
	)
	got := runCheck(t, PodHostPID, g)
	if got["good"] != compliancekit.StatusPass || got["bad"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestPodHostIPC(t *testing.T) {
	g := newPodGraph(
		mkPod("good", nil),
		mkPod("bad", map[string]any{"host_ipc": true}),
	)
	got := runCheck(t, PodHostIPC, g)
	if got["good"] != compliancekit.StatusPass || got["bad"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestPodAllowPrivilegeEscalation(t *testing.T) {
	g := newPodGraph(
		mkPod("good", nil),
		mkPodWithContainer("bad", map[string]any{"allow_priv_escalation": true}),
		mkPodWithContainer("unset", map[string]any{"allow_priv_escalation": nil}),
	)
	got := runCheck(t, PodAllowPrivilegeEscalation, g)
	if got["good"] != compliancekit.StatusPass {
		t.Errorf("good: %v", got["good"])
	}
	if got["bad"] != compliancekit.StatusFail || got["unset"] != compliancekit.StatusFail {
		t.Errorf("bad/unset: %v / %v", got["bad"], got["unset"])
	}
}

func TestPodRunAsNonRoot(t *testing.T) {
	g := newPodGraph(
		mkPod("good", nil),
		mkPodWithContainer("bad", map[string]any{"run_as_non_root": nil, "run_as_user": int64(0)}),
		mkPodWithContainer("nonzero-uid", map[string]any{"run_as_non_root": nil, "run_as_user": int64(1000)}),
	)
	// Pod-level says non_root=true so the container default applies only when neither container nor pod sets it.
	// The "bad" pod overrides pod-level via per-container run_as_user=0.
	g2 := newPodGraph(
		mkPod("pod-says-yes", nil),
		mkPod("pod-says-no", map[string]any{"pod_security": map[string]any{"run_as_non_root": false}}),
	)
	got := runCheck(t, PodRunAsNonRoot, g)
	if got["good"] != compliancekit.StatusPass || got["nonzero-uid"] != compliancekit.StatusPass {
		t.Errorf("good/nonzero-uid: %v / %v", got["good"], got["nonzero-uid"])
	}
	if got["bad"] != compliancekit.StatusFail {
		t.Errorf("bad: %v", got["bad"])
	}
	got2 := runCheck(t, PodRunAsNonRoot, g2)
	if got2["pod-says-yes"] != compliancekit.StatusPass {
		t.Errorf("pod-says-yes: %v", got2["pod-says-yes"])
	}
}

func TestPodReadOnlyRootFS(t *testing.T) {
	g := newPodGraph(
		mkPod("good", nil),
		mkPodWithContainer("bad", map[string]any{"read_only_root_fs": false}),
	)
	got := runCheck(t, PodReadOnlyRootFS, g)
	if got["good"] != compliancekit.StatusPass || got["bad"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestPodCapabilitiesDropAll(t *testing.T) {
	g := newPodGraph(
		mkPod("good", nil),
		mkPodWithContainer("bad", map[string]any{"capabilities_drop": []string{"NET_RAW"}}),
		mkPodWithContainer("empty", map[string]any{"capabilities_drop": []string{}}),
	)
	got := runCheck(t, PodCapabilitiesDropAll, g)
	if got["good"] != compliancekit.StatusPass {
		t.Errorf("good: %v", got["good"])
	}
	if got["bad"] != compliancekit.StatusFail || got["empty"] != compliancekit.StatusFail {
		t.Errorf("bad/empty: %v / %v", got["bad"], got["empty"])
	}
}

func TestPodDangerousCapabilities(t *testing.T) {
	g := newPodGraph(
		mkPod("good", nil),
		mkPodWithContainer("netadmin", map[string]any{"capabilities_add": []string{"NET_ADMIN"}}),
		mkPodWithContainer("netbind", map[string]any{"capabilities_add": []string{"NET_BIND_SERVICE"}}),
	)
	got := runCheck(t, PodDangerousCapabilities, g)
	if got["good"] != compliancekit.StatusPass || got["netbind"] != compliancekit.StatusPass {
		t.Errorf("good/netbind: %v / %v", got["good"], got["netbind"])
	}
	if got["netadmin"] != compliancekit.StatusFail {
		t.Errorf("netadmin: %v", got["netadmin"])
	}
}

func TestPodSeccompProfile(t *testing.T) {
	// pod-unset has both pod-level and container-level seccomp empty.
	podUnset := mkPodWithContainer("pod-unset", map[string]any{"seccomp_type": ""})
	podUnset.Attributes["pod_security"] = map[string]any{}

	g := newPodGraph(
		mkPod("good", nil),
		mkPodWithContainer("unconfined", map[string]any{"seccomp_type": "Unconfined"}),
		mkPodWithContainer("inherits-pod", map[string]any{"seccomp_type": ""}),
		podUnset,
	)
	got := runCheck(t, PodSeccompProfile, g)
	if got["good"] != compliancekit.StatusPass || got["inherits-pod"] != compliancekit.StatusPass {
		t.Errorf("good/inherits-pod: %v / %v", got["good"], got["inherits-pod"])
	}
	if got["unconfined"] != compliancekit.StatusFail || got["pod-unset"] != compliancekit.StatusFail {
		t.Errorf("unconfined/pod-unset: %v / %v", got["unconfined"], got["pod-unset"])
	}
}

func TestPodResourceLimits(t *testing.T) {
	g := newPodGraph(
		mkPod("good", nil),
		mkPodWithContainer("no-cpu", map[string]any{"has_cpu_limit": false}),
		mkPodWithContainer("no-mem", map[string]any{"has_memory_limit": false}),
	)
	got := runCheck(t, PodResourceLimits, g)
	if got["good"] != compliancekit.StatusPass {
		t.Errorf("good: %v", got["good"])
	}
	if got["no-cpu"] != compliancekit.StatusFail || got["no-mem"] != compliancekit.StatusFail {
		t.Errorf("no-cpu/no-mem: %v / %v", got["no-cpu"], got["no-mem"])
	}
}

func TestPodResourceRequests(t *testing.T) {
	g := newPodGraph(
		mkPod("good", nil),
		mkPodWithContainer("no-req", map[string]any{"has_cpu_request": false, "has_memory_request": false}),
	)
	got := runCheck(t, PodResourceRequests, g)
	if got["good"] != compliancekit.StatusPass || got["no-req"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestPodImageTagLatest(t *testing.T) {
	g := newPodGraph(
		mkPod("good", nil),
		mkPodWithContainer("latest", map[string]any{"image_tag": "latest"}),
		mkPodWithContainer("untagged", map[string]any{"image_tag": ""}),
	)
	got := runCheck(t, PodImageTagLatest, g)
	if got["good"] != compliancekit.StatusPass {
		t.Errorf("good: %v", got["good"])
	}
	if got["latest"] != compliancekit.StatusFail || got["untagged"] != compliancekit.StatusFail {
		t.Errorf("latest/untagged: %v / %v", got["latest"], got["untagged"])
	}
}

func TestPodImagePullPolicy(t *testing.T) {
	g := newPodGraph(
		mkPod("good-pinned", nil), // tag=v1.2.3 IfNotPresent — fine
		mkPodWithContainer("latest-always", map[string]any{
			"image": "nginx:latest", "image_tag": "latest", "image_pull_policy": "Always",
		}),
		mkPodWithContainer("latest-ifnotpresent", map[string]any{
			"image": "nginx:latest", "image_tag": "latest", "image_pull_policy": "IfNotPresent",
		}),
		mkPodWithContainer("digest", map[string]any{
			"image": "nginx@sha256:deadbeef", "image_tag": "sha256:deadbeef", "image_pull_policy": "IfNotPresent",
		}),
	)
	got := runCheck(t, PodImagePullPolicy, g)
	for name, want := range map[string]compliancekit.Status{
		"good-pinned":         compliancekit.StatusPass,
		"latest-always":       compliancekit.StatusPass,
		"latest-ifnotpresent": compliancekit.StatusFail,
		"digest":              compliancekit.StatusPass,
	} {
		if got[name] != want {
			t.Errorf("%s: got %v, want %v", name, got[name], want)
		}
	}
}

func TestPodAutomountSAToken(t *testing.T) {
	g := newPodGraph(
		mkPod("good", nil), // automount_sa_token: "false"
		mkPod("default", map[string]any{"automount_sa_token": "unset"}), // unset
		mkPod("explicit-true", map[string]any{"automount_sa_token": "true"}),
	)
	got := runCheck(t, PodAutomountSAToken, g)
	if got["good"] != compliancekit.StatusPass {
		t.Errorf("good: %v", got["good"])
	}
	if got["default"] != compliancekit.StatusFail || got["explicit-true"] != compliancekit.StatusFail {
		t.Errorf("default/explicit-true: %v / %v", got["default"], got["explicit-true"])
	}
}

func TestPodHostPathVolume(t *testing.T) {
	g := newPodGraph(
		mkPod("good", nil),
		mkPod("bad", map[string]any{"host_path_volumes": []string{"node-sock:/var/run/docker.sock"}}),
	)
	got := runCheck(t, PodHostPathVolume, g)
	if got["good"] != compliancekit.StatusPass || got["bad"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestPodHostPort(t *testing.T) {
	g := newPodGraph(
		mkPod("good", nil),
		mkPodWithContainer("bad", map[string]any{"host_ports": []int{8080}}),
	)
	got := runCheck(t, PodHostPort, g)
	if got["good"] != compliancekit.StatusPass || got["bad"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestPodLivenessProbe(t *testing.T) {
	g := newPodGraph(
		mkPod("good", nil),
		mkPodWithContainer("bad", map[string]any{"has_liveness_probe": false}),
		mkPodWithContainer("init-only", map[string]any{"kind": "init", "has_liveness_probe": false}),
	)
	got := runCheck(t, PodLivenessProbe, g)
	if got["good"] != compliancekit.StatusPass || got["init-only"] != compliancekit.StatusPass {
		t.Errorf("good/init-only: %v / %v", got["good"], got["init-only"])
	}
	if got["bad"] != compliancekit.StatusFail {
		t.Errorf("bad: %v", got["bad"])
	}
}
