// Package k8s holds the Kubernetes check catalog. Each per-service
// file (workloads.go, rbac.go, network.go, ...) registers its checks
// via init() against the global core registry; the main binary and
// gencheckdocs both side-effect-import this package so the catalog
// is complete at scan/render time.
//
// v0.11 phase 0 lands the package stub so the side-effect import
// compiles. Phases 1-7 land the generic Kubernetes checks; phases
// 8-10 land the per-cloud EKS/GKE/DOKS enrichment checks.
package k8s
