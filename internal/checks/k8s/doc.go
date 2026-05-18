// Package k8s holds the Kubernetes check catalog. Each per-service
// file (pods.go, workloads.go, rbac.go, ...) registers its checks
// via init() into compliancekit.DefaultRegistry. The main binary and
// gencheckdocs side-effect-import this package so the catalog is
// complete at scan/render time.
package k8s
