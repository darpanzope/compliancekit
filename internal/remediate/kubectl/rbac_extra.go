package kubectl

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.21 phase 3 — kubectl strategies for the 10 RBAC-depth checks.
// All ten are "strip the offending verb from the matching policy rule"
// at the Role / ClusterRole level — one shared renderer parameterized
// by the (verb, resource, apiGroup) tuple from the spec.

type rbacExtraStrategy struct {
	verbs    string // "update,patch"
	resource string // "clusterroles"
	apiGroup string // "rbac.authorization.k8s.io" or "" for core
	scope    string // "ClusterRole" / "Role"
}

var rbacExtraStrategies = map[string]rbacExtraStrategy{
	"k8s-rbac-no-update-clusterroles":             {"update,patch", "clusterroles", "rbac.authorization.k8s.io", "ClusterRole"},
	"k8s-rbac-no-patch-nodes":                     {"patch,update", "nodes", "", "ClusterRole"},
	"k8s-rbac-no-update-pods-status":              {"update,patch", "pods/status", "", "ClusterRole"},
	"k8s-rbac-no-csr-create":                      {"create", "certificatesigningrequests", "certificates.k8s.io", "ClusterRole"},
	"k8s-rbac-no-mutatingwebhook-write":           {"create,update,patch,delete", "mutatingwebhookconfigurations", "admissionregistration.k8s.io", "ClusterRole"},
	"k8s-rbac-no-validatingwebhook-write":         {"create,update,patch,delete", "validatingwebhookconfigurations", "admissionregistration.k8s.io", "ClusterRole"},
	"k8s-rbac-no-namespaces-write":                {"create,update,patch,delete,deletecollection", "namespaces", "", "ClusterRole"},
	"k8s-rbac-no-deletecollection-pods":           {"deletecollection", "pods", "", "ClusterRole"},
	"k8s-rbac-no-create-pods-eviction":            {"create", "pods/eviction", "", "ClusterRole"},
	"k8s-rbac-no-update-pods-ephemeralcontainers": {"create,update,patch", "pods/ephemeralcontainers", "", "ClusterRole"},
}

func init() {
	for id, s := range rbacExtraStrategies {
		id := id
		s := s
		register("kubectl-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			ag := s.apiGroup
			if ag == "" {
				ag = `""   # core API group`
			}
			content := fmt.Sprintf(`# === kubectl patch ===
# Inspect the offending ClusterRole rules + strip the matching verb-set.
# Replace <NAME> with the ClusterRole the finding flagged.

kubectl get clusterrole <NAME> -o yaml > /tmp/cr.yaml

# Edit /tmp/cr.yaml — remove the rule entry whose apiGroups + resources +
# verbs match the offending tuple:
#   apiGroups:     [%s]
#   resources:     [%s]
#   verbs that must NOT appear: %s

kubectl apply -f /tmp/cr.yaml --server-side --force-conflicts

# === Manifest (GitOps) ===
# In the source manifest, locate the rule block matching the tuple
# above and either:
#   1. Remove the offending verb(s) — keep the rule with the safe verbs
#   2. Replace the rule with a resourceNames-scoped equivalent if the
#      subject needs the verb on a specific named resource only.
#
# Example safe replacement for create on namespaces:
#
#   - apiGroups: [""]
#     resources: ["namespaces"]
#     resourceNames: ["my-tenant-ns"]   # scope to a single namespace
#     verbs: ["create", "delete"]
`, ag, s.resource, s.verbs)
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: false, Content: content,
				VerifyCmd: fmt.Sprintf(`kubectl get clusterrole <NAME> -o jsonpath='{.rules[?(@.resources[0]==%q)]}'`, s.resource),
				Notes:     "RBAC stripping can lock out controllers that legitimately need the verb — verify the subject of the bound role doesn't include kube-system or operator service accounts before applying. Audit-log the change at the apiserver.",
			}, nil
		})
	}
}

// v0.21 phase 10 — kubectl backfill for the 6 legacy RBAC check IDs.
// Each pulls the per-check Remediation from the Check struct + an
// `kubectl get clusterrole,clusterrolebinding,...` audit preface.
// See backfill_helper.go for the renderer.
func init() {
	registerBackfillIDs(
		"k8s-rbac-bind",
		"k8s-rbac-empty-subjects",
		"k8s-rbac-pods-portforward",
		"k8s-rbac-secrets-readable",
		"k8s-rbac-stale-role-ref",
		"k8s-rbac-user-subject",
	)
}
