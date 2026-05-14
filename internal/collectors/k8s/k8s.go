// Package k8s is the Kubernetes collector.
//
// It reads a kubeconfig file, fans out across the operator's selected
// contexts, and emits typed core.Resource values for every supported
// Kubernetes resource kind. v0.11 ships generic Kubernetes posture
// across any cluster (kind/k3s/EKS/GKE/DOKS/on-prem) plus per-cloud
// EKS/GKE/DOKS enrichment via sibling collectors.
//
// Authentication is the standard kubeconfig chain (file path from
// config or KUBECONFIG env or ~/.kube/config). Each context's
// in-cluster credentials are loaded via client-go's normal client
// builder; no extra credentials live in compliancekit's config.
//
// Auth/config failures abort the scan; per-service permission denials
// land as k8s.collect_error placeholders rather than aborting, so a
// single restricted API group doesn't lose findings from the rest.
// Same pattern as AWS (v0.7), GCP (v0.8), DO (v0.9), Hetzner (v0.10).
package k8s

import (
	"context"
	"fmt"
	"net/url"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

const (
	providerName = "kubernetes"

	// ClusterType is the per-context anchor resource. One emitted
	// per kubeconfig context the operator scans. Cross-cutting
	// cluster-level checks attach here.
	ClusterType = "k8s.cluster"

	// CollectErrorType is the placeholder resource emitted when a
	// per-service collector fails. Checks can opt-in to look at
	// these; the reporter surfaces the count in the scan footer.
	CollectErrorType = "k8s.collect_error"
)

// ContextScope describes one kubeconfig context being scanned. A
// Collector holds one ContextScope per selected context and fans out
// per-service sub-collectors against each.
type ContextScope struct {
	// Name is the kubeconfig context name. Used as cloudcommon
	// AccountID — stable per-cluster and unique within an operator's
	// kubeconfig.
	Name string

	// Server is the cluster API server URL from the kubeconfig
	// cluster block. Used as cloudcommon Region (parsed to host).
	Server string

	// Namespaces narrows the scan to a fixed list. Empty means
	// "all namespaces" subject to ExcludeNamespaces.
	Namespaces []string

	// ExcludeNamespaces strips matching namespaces from the scan
	// after Namespaces is applied. Useful for skipping noisy
	// platform namespaces (kube-system, kube-public).
	ExcludeNamespaces []string

	// Client is the typed client-go clientset used by per-service
	// collectors. Lazily constructed in production; injected for
	// tests via NewWithScopes.
	Client kubernetes.Interface

	// restConfig is the resolved REST config for the context. Kept
	// so cloud-enrichment adapters can build their own typed clients
	// (CRDs, dynamic clients) without re-walking the kubeconfig.
	restConfig *rest.Config
}

// AccountID returns the cloudcommon AccountID for resources collected
// from this context. The kubeconfig context name is stable per-cluster
// and is the most operator-meaningful identifier available.
func (s *ContextScope) AccountID() string { return s.Name }

// Region returns the API server hostname. K8s has no cloud-style
// region; the server host is a stable, human-readable column that
// disambiguates clusters when context names collide.
func (s *ContextScope) Region() string {
	if s.Server == "" {
		return ""
	}
	if u, err := url.Parse(s.Server); err == nil && u.Host != "" {
		return u.Host
	}
	return s.Server
}

// Options configures Collector construction.
type Options struct {
	// KubeconfigPath optionally overrides the kubeconfig file. When
	// empty, the standard chain applies (KUBECONFIG env, then
	// ~/.kube/config).
	KubeconfigPath string

	// Contexts narrows the scan to specific kubeconfig contexts.
	// Empty means "just the current-context."
	Contexts []string

	// Namespaces narrows the scan within each context.
	Namespaces []string

	// ExcludeNamespaces strips namespaces post-include.
	ExcludeNamespaces []string
}

// Collector fans out across one or more kubeconfig contexts and emits
// core.Resource values for every supported Kubernetes resource kind.
type Collector struct {
	contexts []*ContextScope
}

// New constructs a Collector by reading the kubeconfig at opts.KubeconfigPath
// (or the standard chain if empty) and resolving the operator's context
// selection.
func New(opts Options) (*Collector, error) {
	scopes, err := loadScopes(opts)
	if err != nil {
		return nil, err
	}
	return &Collector{contexts: scopes}, nil
}

// NewWithScopes constructs a Collector from already-resolved scopes.
// Tests use this entry point to inject fake clientsets without
// touching a real kubeconfig.
func NewWithScopes(scopes []*ContextScope) *Collector {
	return &Collector{contexts: scopes}
}

// Name returns the provider identifier.
func (c *Collector) Name() string { return providerName }

// Contexts returns the resolved context names. Used by doctor and the
// scan banner to report what the operator is actually scanning.
func (c *Collector) Contexts() []string {
	out := make([]string, len(c.contexts))
	for i, s := range c.contexts {
		out[i] = s.Name
	}
	return out
}

// Collect emits the per-context anchor and runs every registered
// sub-collector. Per-service errors land as k8s.collect_error
// placeholders rather than aborting the rest of the scan.
//
// Order of operations:
//
//  1. For each ContextScope, emit the cluster anchor first.
//  2. Run per-service sub-collectors in declaration order. Each
//     captures its own errors as a placeholder and the loop
//     continues to the next service.
//  3. After the per-context iteration completes, append everything
//     to the result slice. Cross-context linking, when added in
//     later phases, will happen here.
func (c *Collector) Collect(ctx context.Context) ([]core.Resource, error) {
	// Pre-allocate for the anchors; per-service collectors append.
	out := make([]core.Resource, 0, len(c.contexts))

	type subCollector struct {
		service string
		run     func(context.Context, *ContextScope) ([]core.Resource, error)
	}

	for _, scope := range c.contexts {
		out = append(out, c.clusterAnchor(scope))

		// Per-phase additions land here as additional entries.
		// Phase 1 ships workloads (Pods); phases 2-7 add the rest.
		subs := []subCollector{
			{"workloads", c.collectWorkloads},
		}

		for _, s := range subs {
			partial, err := s.run(ctx, scope)
			if err != nil {
				out = append(out, c.collectError(scope, s.service, err))
				continue
			}
			out = append(out, partial...)
		}
	}
	return out, nil
}

// clusterAnchor emits the singleton-per-context anchor resource.
func (c *Collector) clusterAnchor(scope *ContextScope) core.Resource {
	r := core.Resource{
		ID:       fmt.Sprintf("%s.%s", ClusterType, scope.Name),
		Type:     ClusterType,
		Name:     scope.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"context": scope.Name,
			"server":  scope.Server,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: scope.AccountID(),
		Region:    scope.Region(),
	})
	return r
}

// collectError emits a placeholder when a per-service sub-collector
// fails outright.
func (c *Collector) collectError(scope *ContextScope, service string, err error) core.Resource {
	r := core.Resource{
		ID:       fmt.Sprintf("%s.%s.%s", CollectErrorType, scope.Name, service),
		Type:     CollectErrorType,
		Name:     service,
		Provider: providerName,
		Attributes: map[string]any{
			"context": scope.Name,
			"service": service,
			"error":   err.Error(),
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: scope.AccountID(),
		Region:    scope.Region(),
	})
	return r
}
