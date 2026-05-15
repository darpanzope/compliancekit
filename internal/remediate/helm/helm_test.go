package helm

import (
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

func TestRegistryCoverage(t *testing.T) {
	cases := []string{
		"k8s-pod-run-as-non-root",
		"k8s-pod-allow-privilege-escalation",
		"k8s-pod-readonly-root-fs",
		"k8s-pod-capabilities-drop-all",
		"k8s-pod-seccomp-profile",
		"k8s-pod-privileged",
		"k8s-pod-resource-limits",
		"k8s-pod-resource-requests",
		"k8s-deployment-pdb-missing",
		"k8s-statefulset-pdb-missing",
		"k8s-deployment-min-replicas",
		"k8s-networkpolicy-default-deny-ingress",
		"k8s-networkpolicy-default-deny-egress",
		"k8s-pod-automount-sa-token",
		"k8s-sa-default-automount",
	}
	for _, id := range cases {
		ss := remediate.Default.StrategiesFor(id)
		found := false
		for _, s := range ss {
			for _, f := range s.Formats() {
				if f == remediate.FormatHelm {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("CheckID %q has no Helm strategy", id)
		}
	}
}

func TestRenderPodSecurityOverlay(t *testing.T) {
	f := core.Finding{
		CheckID:  "k8s-pod-run-as-non-root",
		Resource: core.ResourceRef{Name: "checkout-api"},
	}
	s, err := remediate.Default.Render(f, remediate.FormatHelm)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"podSecurityContext:",
		"runAsNonRoot: true",
		"securityContext:",
		"allowPrivilegeEscalation: false",
		"readOnlyRootFilesystem: true",
		"capabilities:",
		"- ALL",
	} {
		if !strings.Contains(s.Content, want) {
			t.Errorf("missing %q in overlay:\n%s", want, s.Content)
		}
	}
}

func TestRenderPDBOverlay(t *testing.T) {
	f := core.Finding{
		CheckID:  "k8s-deployment-pdb-missing",
		Resource: core.ResourceRef{Name: "api-release"},
	}
	s, err := remediate.Default.Render(f, remediate.FormatHelm)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(s.Content, "api-release-pdb") {
		t.Errorf("release name not threaded: %s", s.Content)
	}
}
