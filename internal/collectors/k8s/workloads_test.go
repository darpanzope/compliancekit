package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCollectWorkloads_FlattensPodSpec(t *testing.T) {
	hostPathType := corev1.HostPathDirectory
	priv := true
	rootFS := true
	noRoot := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "web-abc"},
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "web-sa",
			HostNetwork:        true,
			HostPID:            false,
			HostIPC:            false,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   &noRoot,
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Volumes: []corev1.Volume{
				{Name: "logs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log", Type: &hostPathType}}},
				{Name: "ephemeral", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			},
			Containers: []corev1.Container{
				{
					Name:  "app",
					Image: "registry.example.com/app:v1.2.3",
					SecurityContext: &corev1.SecurityContext{
						Privileged:             &priv,
						ReadOnlyRootFilesystem: &rootFS,
					},
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("500m"),
							corev1.ResourceMemory: resource.MustParse("256Mi"),
						},
					},
					LivenessProbe: &corev1.Probe{},
					Ports: []corev1.ContainerPort{
						{ContainerPort: 8080, HostPort: 8080},
					},
				},
			},
		},
	}

	cs := fake.NewSimpleClientset(pod)
	scope := &ContextScope{Name: "prod", Server: "https://api.example.invalid:6443", Client: cs}
	col := NewWithScopes([]*ContextScope{scope})

	resources, err := col.collectWorkloads(context.Background(), scope)
	if err != nil {
		t.Fatalf("collectWorkloads: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	r := resources[0]
	if r.Type != PodType {
		t.Errorf("Type = %q, want %q", r.Type, PodType)
	}
	if r.Name != "web" {
		t.Errorf("Name = %q", r.Name)
	}
	if r.Attributes["namespace"] != "default" {
		t.Errorf("namespace = %v", r.Attributes["namespace"])
	}
	if r.Attributes["host_network"] != true {
		t.Errorf("host_network = %v", r.Attributes["host_network"])
	}
	hpv := r.Attributes["host_path_volumes"].([]string)
	if len(hpv) != 1 || hpv[0] != "logs:/var/log" {
		t.Errorf("host_path_volumes = %v", hpv)
	}

	cs1 := r.Attributes["containers"].([]any)
	if len(cs1) != 1 {
		t.Fatalf("containers len = %d", len(cs1))
	}
	c := cs1[0].(map[string]any)
	if c["privileged"] != true {
		t.Errorf("container.privileged = %v", c["privileged"])
	}
	if c["image_tag"] != "v1.2.3" {
		t.Errorf("container.image_tag = %v", c["image_tag"])
	}
	if c["has_cpu_limit"] != true || c["has_memory_limit"] != true {
		t.Errorf("limit flags wrong: cpu=%v mem=%v", c["has_cpu_limit"], c["has_memory_limit"])
	}
	if c["has_liveness_probe"] != true {
		t.Errorf("has_liveness_probe = %v", c["has_liveness_probe"])
	}
	hp := c["host_ports"].([]int)
	if len(hp) != 1 || hp[0] != 8080 {
		t.Errorf("host_ports = %v", hp)
	}

	if r.Attributes["owner_kind"] != "ReplicaSet" {
		t.Errorf("owner_kind = %v", r.Attributes["owner_kind"])
	}
}

func TestCollectWorkloads_NamespaceExclude(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "default"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "kube-system"}},
	)
	scope := &ContextScope{
		Name:              "prod",
		Client:            cs,
		ExcludeNamespaces: []string{"kube-system"},
	}
	col := NewWithScopes([]*ContextScope{scope})
	resources, err := col.collectWorkloads(context.Background(), scope)
	if err != nil {
		t.Fatalf("collectWorkloads: %v", err)
	}
	if len(resources) != 1 || resources[0].Name != "a" {
		t.Errorf("unexpected pods: %v", resources)
	}
}

func TestImageTag(t *testing.T) {
	cases := map[string]string{
		"nginx":                             "latest",
		"nginx:1.21":                        "1.21",
		"registry.example.com/app:v1.2.3":   "v1.2.3",
		"registry.example.com:5000/app":     "latest",
		"registry.example.com:5000/app:1.0": "1.0",
		"nginx@sha256:abc123":               "sha256:abc123",
	}
	for in, want := range cases {
		if got := imageTag(in); got != want {
			t.Errorf("imageTag(%q) = %q, want %q", in, got, want)
		}
	}
}
