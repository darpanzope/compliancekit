package k8s

import (
	"context"
	"fmt"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.22 phase 4 — ResourceQuota + LimitRange checks split out of
// cluster.go to satisfy the 600-LoC invariant.

// ----- ResourceQuota pod limit -----------------------------------

var CheckRQPodLimit = compliancekit.Check{
	ID:           "k8s-resourcequota-pod-limit",
	Title:        "ResourceQuotas should cap pod counts",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "cluster",
	ResourceType: k8scol.ResourceQuotaType,
	Description: "A pod cap (`hard.pods: <n>`) prevents a runaway " +
		"controller from spawning thousands of pods and exhausting node " +
		"capacity. Pair with `count/secrets` and `count/configmaps` " +
		"to bound etcd object count.",
	Remediation: "Add `spec.hard.pods: 50` (or your operational " +
		"ceiling) to every ResourceQuota.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "quota"},
	Scanner: "cluster.RQPodLimit",
}

func RQPodLimit(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return rqAttrCheck(g, CheckRQPodLimit, "has_pods", "pods cap set", "no pod count cap"), nil
}

// ----- ResourceQuota CPU/memory ----------------------------------

var CheckRQComputeLimit = compliancekit.Check{
	ID:           "k8s-resourcequota-compute-limit",
	Title:        "ResourceQuotas should cap CPU and memory",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "cluster",
	ResourceType: k8scol.ResourceQuotaType,
	Description: "Without compute caps, a single tenant can consume all " +
		"of a cluster's CPU or memory headroom. `limits.cpu` + " +
		"`limits.memory` plus the matching `requests.*` keep namespace " +
		"consumption bounded.",
	Remediation: "Add `hard.limits.cpu` and `hard.limits.memory` (and " +
		"`hard.requests.cpu` / `hard.requests.memory`).",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "quota"},
	Scanner: "cluster.RQComputeLimit",
}

func RQComputeLimit(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, rq := range g.ByType(k8scol.ResourceQuotaType) {
		cpu, _ := rq.Attributes["has_cpu"].(bool)
		mem, _ := rq.Attributes["has_memory"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckRQComputeLimit.ID,
			Severity: CheckRQComputeLimit.Severity,
			Resource: rq.Ref(),
			Tags:     CheckRQComputeLimit.Tags,
		}
		if cpu && mem {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("resourcequota %q: cpu+memory caps set", workloadDesc(rq))
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("resourcequota %q: missing %s cap(s)", workloadDesc(rq), missingResourceList(cpu, mem))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- ResourceQuota object counts -------------------------------

var CheckRQObjectCounts = compliancekit.Check{
	ID:           "k8s-resourcequota-object-counts",
	Title:        "ResourceQuotas should cap object counts",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "cluster",
	ResourceType: k8scol.ResourceQuotaType,
	Description: "etcd has practical ceilings on object count. Without " +
		"`count/configmaps`, `count/secrets`, `persistentvolumeclaims` " +
		"caps, a chatty controller can fill etcd within a namespace.",
	Remediation: "Add `hard.count/configmaps`, `hard.count/secrets`, " +
		"and `hard.persistentvolumeclaims` to every ResourceQuota.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "quota"},
	Scanner: "cluster.RQObjectCounts",
}

func RQObjectCounts(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return rqAttrCheck(g, CheckRQObjectCounts, "has_objects", "object count cap set", "no object count cap"), nil
}

// ----- LimitRange default set -----------------------------------

var CheckLRDefaultSet = compliancekit.Check{
	ID:           "k8s-limitrange-container-defaults",
	Title:        "LimitRanges should set container default requests/limits",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "cluster",
	ResourceType: k8scol.LimitRangeType,
	Description: "A LimitRange without `default` and `defaultRequest` " +
		"for the Container type does not actually supply defaults to " +
		"unannotated pods — it only enforces min/max if those are set. " +
		"Defaults are the operational primitive that makes the pod-" +
		"security resource-limit check pass for every pod.",
	Remediation: "Add `default` and `defaultRequest` for `cpu` and " +
		"`memory` to the LimitRange's container entry.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "limitrange"},
	Scanner: "cluster.LRDefaultSet",
}

func LRDefaultSet(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, lr := range g.ByType(k8scol.LimitRangeType) {
		has, _ := lr.Attributes["has_container_defaults"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckLRDefaultSet.ID,
			Severity: CheckLRDefaultSet.Severity,
			Resource: lr.Ref(),
			Tags:     CheckLRDefaultSet.Tags,
		}
		if has {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("limitrange %q: container defaults set", workloadDesc(lr))
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("limitrange %q: no container defaults", workloadDesc(lr))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckRQPodLimit, RQPodLimit)
	compliancekit.Register(CheckRQComputeLimit, RQComputeLimit)
	compliancekit.Register(CheckRQObjectCounts, RQObjectCounts)
	compliancekit.Register(CheckLRDefaultSet, LRDefaultSet)
}
