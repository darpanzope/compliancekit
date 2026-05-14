package k8s

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// collectNodes fetches every Node and flattens the condition + runtime
// info checks read.
func (c *Collector) collectNodes(ctx context.Context, scope *ContextScope) ([]core.Resource, error) {
	nodes, err := scope.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	out := make([]core.Resource, 0, len(nodes.Items))
	for i := range nodes.Items {
		out = append(out, c.nodeResource(scope, &nodes.Items[i]))
	}
	return out, nil
}

func (c *Collector) nodeResource(scope *ContextScope, n *corev1.Node) core.Resource {
	conditions := map[string]string{}
	for _, cond := range n.Status.Conditions {
		conditions[string(cond.Type)] = string(cond.Status)
	}
	taints := make([]map[string]string, 0, len(n.Spec.Taints))
	for _, t := range n.Spec.Taints {
		taints = append(taints, map[string]string{
			"key":    t.Key,
			"value":  t.Value,
			"effect": string(t.Effect),
		})
	}
	attrs := map[string]any{
		"conditions":         conditions,
		"kubelet_version":    n.Status.NodeInfo.KubeletVersion,
		"kernel_version":     n.Status.NodeInfo.KernelVersion,
		"os_image":           n.Status.NodeInfo.OSImage,
		"container_runtime":  n.Status.NodeInfo.ContainerRuntimeVersion,
		"operating_system":   n.Status.NodeInfo.OperatingSystem,
		"architecture":       n.Status.NodeInfo.Architecture,
		"unschedulable":      n.Spec.Unschedulable,
		"labels":             copyStringMap(n.Labels),
		"taints":             taints,
		"has_zone_label":     n.Labels["topology.kubernetes.io/zone"] != "",
		"has_region_label":   n.Labels["topology.kubernetes.io/region"] != "",
		"creation_timestamp": n.CreationTimestamp.Time,
		"age_days":           int(time.Since(n.CreationTimestamp.Time).Hours() / 24),
		"is_control_plane":   nodeIsControlPlane(n),
	}
	r := core.Resource{
		ID:         fmt.Sprintf("%s.%s.%s", NodeType, scope.Name, n.Name),
		Type:       NodeType,
		Name:       n.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

func nodeIsControlPlane(n *corev1.Node) bool {
	if _, ok := n.Labels["node-role.kubernetes.io/control-plane"]; ok {
		return true
	}
	if _, ok := n.Labels["node-role.kubernetes.io/master"]; ok {
		return true
	}
	for _, t := range n.Spec.Taints {
		if t.Key == "node-role.kubernetes.io/control-plane" || t.Key == "node-role.kubernetes.io/master" {
			return true
		}
	}
	return false
}
