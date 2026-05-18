package kubectl

import (
	"fmt"
	"strings"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.21 phase 10 — shared kubectl parity backfill helper.
//
// Splits across per-category files (doks_backfill.go,
// eks_backfill.go, etc.) so the registration site lives near the
// other strategies for the same surface. The helper centralizes:
//
//   - auditCommandForID(id) — kubectl / cloud-CLI audit command
//                              derived from the check ID's prefix.
//   - riskForBackfilledID(id) — RiskClass per category convention.
//   - registerBackfillIDs(ids…) — bulk-register the per-category
//                                  legacy ID list against a shared
//                                  renderer that pulls the Check's
//                                  own Remediation text.
//
// Per-category files just call registerBackfillIDs() inside an
// init() block listing the IDs they own. Adding a new legacy ID
// to a category is one line.

// auditPrefixCommands maps "k8s-<service>-" prefix substrings to the
// audit command run before applying the per-check remediation. First-
// match-wins via the slice (matters when multiple prefixes overlap —
// e.g. "k8s-mutating-webhook-" must be checked before "k8s-webhook-").
var auditPrefixCommands = []struct {
	prefix string
	cmd    string
}{
	{"k8s-doks-", "doctl kubernetes cluster get <cluster> -o json | jq '.cluster'"},
	{"k8s-eks-", "aws eks describe-cluster --name <cluster> --query 'cluster'"},
	{"k8s-gke-", "gcloud container clusters describe <cluster> --format=yaml"},
	{"k8s-rbac-", "kubectl get clusterrole,clusterrolebinding,role,rolebinding -A -o yaml"},
	{"k8s-pod-", "kubectl get pods -A -o yaml"},
	{"k8s-pvc-", "kubectl get pvc -A -o yaml"},
	{"k8s-pv-", "kubectl get pv -o yaml"},
	{"k8s-storageclass-", "kubectl get storageclass -o yaml"},
	{"k8s-secret-", "kubectl get secret -A -o yaml"},
	{"k8s-configmap-", "kubectl get configmap -A -o yaml"},
	{"k8s-namespace-", "kubectl get namespace -o yaml"},
	{"k8s-node-", "kubectl get nodes -o yaml"},
	{"k8s-networkpolicy-", "kubectl get networkpolicy -A -o yaml"},
	{"k8s-service-", "kubectl get svc -A -o yaml"},
	{"k8s-ingress-", "kubectl get ingress -A -o yaml"},
	{"k8s-cronjob-", "kubectl get cronjob -A -o yaml"},
	{"k8s-job-", "kubectl get job -A -o yaml"},
	{"k8s-daemonset-", "kubectl get daemonset -A -o yaml"},
	{"k8s-resourcequota-", "kubectl get resourcequota -A -o yaml"},
	{"k8s-sa-", "kubectl get serviceaccount -A -o yaml"},
	{"k8s-mutating-webhook-", "kubectl get mutatingwebhookconfiguration -o yaml"},
	{"k8s-validating-webhook-", "kubectl get validatingwebhookconfiguration -o yaml"},
	{"k8s-webhook-", "kubectl get validatingwebhookconfiguration,mutatingwebhookconfiguration -o yaml"},
}

// auditCommandForID returns the audit command for a backfilled check ID.
func auditCommandForID(checkID string) string {
	for _, p := range auditPrefixCommands {
		if strings.HasPrefix(checkID, p.prefix) {
			return p.cmd
		}
	}
	return "kubectl get all -A"
}

// riskForBackfilledID maps a backfilled ID to its RiskClass. Node-
// level + stale-role-ref remediations are Manual (workload-design
// decisions); everything else is Review.
func riskForBackfilledID(checkID string) remediate.RiskClass {
	switch {
	case strings.HasPrefix(checkID, "k8s-node-") || checkID == "k8s-rbac-stale-role-ref":
		return remediate.RiskManual
	default:
		return remediate.RiskReview
	}
}

// registerBackfillIDs bulk-registers a per-category list of legacy
// check IDs against the shared renderer. Per-category files just
// list the IDs inside their own init().
func registerBackfillIDs(ids ...string) {
	for _, id := range ids {
		id := id
		register("kubectl-backfill-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			remediation := ""
			if check, ok := compliancekit.LookupCheck(id); ok {
				remediation = check.Remediation
			}
			if remediation == "" {
				remediation = "See finding Message for context — no inline remediation text registered with this check."
			}
			body := fmt.Sprintf("# === Audit: see current state ===\n%s\n\n# === Remediation ===\n%s\n",
				auditCommandForID(id), remediation)
			return remediate.Snippet{
				Risk: riskForBackfilledID(id), Idempotent: false, Content: body,
				Notes: "Auto-generated kubectl backfill at v0.21 phase 10 — pulls per-check remediation from the Check struct. Re-author with a hand-written two-block patch + manifest when this check intersects often.",
			}, nil
		})
	}
}
