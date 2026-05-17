package kubectl

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.21 phase 7 — kubectl strategies for the 15 control-plane manual-
// verify checks. Each is workflow-shaped (ssh + grep + edit + restart)
// rather than kubectl patch-shaped, since control-plane flags live on
// the static pod manifest or kubelet config — neither in the apiserver.

var controlPlaneStrategies = map[string]string{
	"k8s-cp-apiserver-anonymous-auth":             "Edit /etc/kubernetes/manifests/kube-apiserver.yaml on the control-plane node:\n  - --anonymous-auth=false\nThe kubelet reloads the static pod automatically when the manifest changes.\n\nOn managed K8s (EKS / GKE / DOKS) the flag is vendor-fixed; confirm in vendor docs + waive via waivers.yaml if vendor sets it correctly.",
	"k8s-cp-apiserver-authorization-mode":         "Edit /etc/kubernetes/manifests/kube-apiserver.yaml:\n  - --authorization-mode=Node,RBAC\nOrder matters: Node first so kubelet authz hits the per-node check before RBAC.",
	"k8s-cp-apiserver-node-restriction-admission": "Edit /etc/kubernetes/manifests/kube-apiserver.yaml:\n  - --enable-admission-plugins=NodeRestriction,PodSecurity,ServiceAccount,...   # keep NodeRestriction in the list",
	"k8s-cp-apiserver-audit-log-path":             "Add to /etc/kubernetes/manifests/kube-apiserver.yaml:\n  - --audit-log-path=/var/log/kubernetes/audit/audit.log\n  - --audit-policy-file=/etc/kubernetes/audit-policy.yaml\n\nAudit policy example (audit-policy.yaml):\n\napiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n  - level: RequestResponse\n    resources:\n      - group: \"\"\n        resources: [\"secrets\", \"configmaps\"]\n  - level: Metadata",
	"k8s-cp-apiserver-audit-log-retention":        "Edit /etc/kubernetes/manifests/kube-apiserver.yaml:\n  - --audit-log-maxage=30\n  - --audit-log-maxbackup=10\n  - --audit-log-maxsize=100\n\nOn managed K8s (EKS / GKE / DOKS) configure cloud-side log retention ≥30d:\n  EKS:  CloudWatch log group retention\n  GKE:  Logging exclusion + bucket retention\n  DOKS: doctl monitoring alert policy",
	"k8s-cp-apiserver-encryption-at-rest":         "Create /etc/kubernetes/encryption.yaml:\n\napiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n  - resources: [secrets]\n    providers:\n      - aescbc:\n          keys:\n            - name: key1\n              secret: <base64 of 32 random bytes>\n      - identity: {}\n\nThen in /etc/kubernetes/manifests/kube-apiserver.yaml:\n  - --encryption-provider-config=/etc/kubernetes/encryption.yaml\n\nAfter applying, re-encrypt existing Secrets:\n  kubectl get secrets -A -o json | kubectl replace -f -",
	"k8s-cp-apiserver-profiling-disabled":         "Edit /etc/kubernetes/manifests/kube-apiserver.yaml + kube-controller-manager.yaml + kube-scheduler.yaml:\n  - --profiling=false",
	"k8s-cp-etcd-client-cert-auth":                "Edit /etc/kubernetes/manifests/etcd.yaml:\n  - --client-cert-auth=true\n  - --cert-file=/etc/kubernetes/pki/etcd/server.crt\n  - --key-file=/etc/kubernetes/pki/etcd/server.key\n  - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt",
	"k8s-cp-etcd-peer-client-cert-auth":           "Edit /etc/kubernetes/manifests/etcd.yaml:\n  - --peer-client-cert-auth=true\n  - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt\n  - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key\n  - --peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt",
	"k8s-cp-etcd-auto-tls-false":                  "Edit /etc/kubernetes/manifests/etcd.yaml:\n  - --auto-tls=false\n  - --peer-auto-tls=false\nReplace with proper --cert-file + --peer-cert-file referring to operator-issued certs.",
	"k8s-cp-cm-use-service-account-credentials":   "Edit /etc/kubernetes/manifests/kube-controller-manager.yaml:\n  - --use-service-account-credentials=true\nDefault is true on k8s ≥ 1.6; confirm not overridden in custom kubeadm configs.",
	"k8s-cp-cm-bind-address-localhost":            "Edit /etc/kubernetes/manifests/kube-controller-manager.yaml:\n  - --bind-address=127.0.0.1\nDisables external access to healthz + metrics endpoints.",
	"k8s-cp-scheduler-bind-address-localhost":     "Edit /etc/kubernetes/manifests/kube-scheduler.yaml:\n  - --bind-address=127.0.0.1",
	"k8s-cp-kubelet-anonymous-auth-false":         "Edit /var/lib/kubelet/config.yaml on every node:\n\napiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nauthentication:\n  anonymous:\n    enabled: false\n  webhook:\n    enabled: true\nauthorization:\n  mode: Webhook\n\nThen: sudo systemctl restart kubelet",
	"k8s-cp-kubelet-read-only-port-zero":          "Edit /var/lib/kubelet/config.yaml:\n\nreadOnlyPort: 0\n\nThen: sudo systemctl restart kubelet",
}

func init() {
	for id, body := range controlPlaneStrategies {
		id := id
		body := body
		register("kubectl-"+id, []string{id}, func(_ core.Finding) (remediate.Snippet, error) {
			content := fmt.Sprintf("# Manual remediation — control-plane configuration lives on the node, not in the apiserver.\n# %s\n\n%s\n",
				id, body)
			return remediate.Snippet{
				Risk: remediate.RiskManual, Idempotent: false, Content: content,
				Notes: "Control-plane edits require ssh access to the control-plane node (self-managed K8s) or vendor confirmation (managed K8s). Most managed K8s providers fix these flags correctly by default — waive via waivers.yaml after confirming in vendor docs.",
			}, nil
		})
	}
}
