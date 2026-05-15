package kubectl

import (
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("missing substring %q in:\n%s", needle, haystack)
	}
}

func k8sFinding(checkID, kind, namespace, name string) core.Finding {
	return core.Finding{
		CheckID: checkID,
		Resource: core.ResourceRef{
			ID:       "k8s." + strings.ToLower(kind) + ".prod." + namespace + "." + name,
			Type:     "k8s." + strings.ToLower(kind),
			Name:     name,
			Provider: "kubernetes",
		},
	}
}

func TestRegistryCoverage(t *testing.T) {
	cases := []string{
		// Pod security
		"k8s-pod-run-as-non-root",
		"k8s-pod-allow-privilege-escalation",
		"k8s-pod-readonly-root-fs",
		"k8s-pod-capabilities-drop-all",
		"k8s-pod-dangerous-capabilities",
		"k8s-pod-seccomp-profile",
		"k8s-pod-privileged",
		"k8s-pod-host-network",
		"k8s-pod-host-pid",
		"k8s-pod-host-ipc",
		"k8s-pod-host-path-volume",
		"k8s-pod-automount-sa-token",
		"k8s-sa-default-automount",
		"k8s-pod-image-tag-latest",
		"k8s-pod-image-pull-policy",
		// Workload reliability
		"k8s-deployment-pdb-missing",
		"k8s-statefulset-pdb-missing",
		"k8s-deployment-min-replicas",
		"k8s-deployment-anti-affinity",
		"k8s-deployment-rolling-update",
		"k8s-pod-liveness-probe",
		"k8s-pod-resource-limits",
		"k8s-pod-resource-requests",
		// Ingress / Service
		"k8s-ingress-tls-missing",
		"k8s-ingress-class-set",
		"k8s-service-loadbalancer-source-ranges",
		"k8s-service-external-ips",
		// NetworkPolicy
		"k8s-networkpolicy-default-deny-ingress",
		"k8s-networkpolicy-default-deny-egress",
		"k8s-service-public-without-network-policy",
		// Namespace
		"k8s-namespace-psa-label",
		"k8s-namespace-limitrange-missing",
		"k8s-limitrange-container-defaults",
		"k8s-namespace-resourcequota-missing",
		// RBAC (manual)
		"k8s-rbac-full-wildcard",
		"k8s-rbac-wildcard-apigroups",
		"k8s-rbac-wildcard-resources",
		"k8s-rbac-wildcard-verbs",
		"k8s-rbac-cluster-admin-non-system",
		"k8s-rbac-escalate",
		"k8s-rbac-impersonate",
		"k8s-rbac-anonymous-bind",
		"k8s-rbac-secrets-writable",
		"k8s-rbac-pods-exec",
	}
	for _, id := range cases {
		if got := remediate.Default.StrategiesFor(id); len(got) == 0 {
			t.Errorf("CheckID %q has no registered kubectl strategy", id)
		}
	}
}

func TestRenderRunAsNonRoot(t *testing.T) {
	f := k8sFinding("k8s-pod-run-as-non-root", "Deployment", "prod", "checkout-api")
	s, err := remediate.Default.Render(f, remediate.FormatKubectl)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if s.Risk != remediate.RiskReview {
		t.Errorf("Risk = %v, want review", s.Risk)
	}
	mustContain(t, s.Content, "kubectl patch deployment checkout-api")
	mustContain(t, s.Content, "-n prod")
	mustContain(t, s.Content, "runAsNonRoot: true")
	mustContain(t, s.Content, "# === kubectl patch (live) ===")
	mustContain(t, s.Content, "# === Manifest (GitOps) ===")
}

func TestRenderNetworkPolicyDefaultDeny(t *testing.T) {
	f := k8sFinding("k8s-networkpolicy-default-deny-ingress", "Namespace", "prod", "prod")
	s, err := remediate.Default.Render(f, remediate.FormatKubectl)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContain(t, s.Content, "default-deny-ingress")
	mustContain(t, s.Content, "default-deny-egress")
	mustContain(t, s.Content, "kube-system") // DNS allow rule
}

func TestRenderRBACManual(t *testing.T) {
	cases := []string{
		"k8s-rbac-full-wildcard",
		"k8s-rbac-cluster-admin-non-system",
		"k8s-rbac-escalate",
	}
	for _, id := range cases {
		f := core.Finding{CheckID: id, Resource: core.ResourceRef{Name: "kubeadm-anyuser"}}
		s, err := remediate.Default.Render(f, remediate.FormatKubectl)
		if err != nil {
			t.Errorf("Render(%q): %v", id, err)
			continue
		}
		if s.Risk != remediate.RiskManual {
			t.Errorf("%q Risk = %v, want manual", id, s.Risk)
		}
		mustContain(t, s.Notes, "audit log")
	}
}

func TestRenderPSAlabel(t *testing.T) {
	f := core.Finding{
		CheckID:  "k8s-namespace-psa-label",
		Resource: core.ResourceRef{Name: "prod"},
	}
	s, err := remediate.Default.Render(f, remediate.FormatKubectl)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContain(t, s.Content, "pod-security.kubernetes.io/enforce=restricted")
	mustContain(t, s.Content, "kubectl label namespace prod")
}

func TestRenderPDB(t *testing.T) {
	f := k8sFinding("k8s-deployment-pdb-missing", "Deployment", "prod", "checkout-api")
	s, err := remediate.Default.Render(f, remediate.FormatKubectl)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContain(t, s.Content, "kind: PodDisruptionBudget")
	mustContain(t, s.Content, "checkout-api-pdb")
}

func TestRenderHostNamespacesGroupedCheckIDs(t *testing.T) {
	// One strategy covers hostNetwork / hostPID / hostIPC — verify each
	// resolves to identical Content.
	cases := []string{
		"k8s-pod-host-network",
		"k8s-pod-host-pid",
		"k8s-pod-host-ipc",
	}
	var first string
	for i, id := range cases {
		f := k8sFinding(id, "Deployment", "prod", "host-namespaced-app")
		s, err := remediate.Default.Render(f, remediate.FormatKubectl)
		if err != nil {
			t.Fatalf("Render(%q): %v", id, err)
		}
		if i == 0 {
			first = s.Content
		} else if s.Content != first {
			t.Errorf("grouped CheckID %q has different Content from first", id)
		}
	}
}

func TestRenderDeterministic(t *testing.T) {
	f := k8sFinding("k8s-pod-resource-limits", "Deployment", "prod", "limits-test")
	a, _ := remediate.Default.Render(f, remediate.FormatKubectl)
	b, _ := remediate.Default.Render(f, remediate.FormatKubectl)
	if a.Content != b.Content {
		t.Errorf("non-deterministic render")
	}
}

func TestRenderServiceExternalIPs(t *testing.T) {
	f := k8sFinding("k8s-service-external-ips", "Service", "prod", "legacy-svc")
	s, err := remediate.Default.Render(f, remediate.FormatKubectl)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContain(t, s.Content, "--type=json")
	mustContain(t, s.Content, "/spec/externalIPs")
}

func TestRenderIngressTLS(t *testing.T) {
	f := k8sFinding("k8s-ingress-tls-missing", "Ingress", "prod", "web")
	s, err := remediate.Default.Render(f, remediate.FormatKubectl)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContain(t, s.Content, "cert-manager.io/cluster-issuer")
	mustContain(t, s.Content, "secretName: web-tls")
}
