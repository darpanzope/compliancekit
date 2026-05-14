package k8s

// Resource type constants for every kind the Kubernetes collector
// emits. Check packages import these so they can ByType() the graph
// without taking a direct dependency on client-go.
//
// Cluster-scoped types do not carry a namespace attribute. Namespaced
// types always carry a "namespace" attribute on the resource.
const (
	// Cluster-scoped
	NamespaceType               = "k8s.namespace"
	NodeType                    = "k8s.node"
	PersistentVolumeType        = "k8s.persistentvolume"
	StorageClassType            = "k8s.storageclass"
	ClusterRoleType             = "k8s.clusterrole"
	ClusterRoleBindingType      = "k8s.clusterrolebinding"
	ValidatingWebhookConfigType = "k8s.validatingwebhookconfig"
	MutatingWebhookConfigType   = "k8s.mutatingwebhookconfig"

	// Namespaced workloads
	PodType         = "k8s.pod"
	DeploymentType  = "k8s.deployment"
	StatefulSetType = "k8s.statefulset"
	DaemonSetType   = "k8s.daemonset"
	ReplicaSetType  = "k8s.replicaset"
	JobType         = "k8s.job"
	CronJobType     = "k8s.cronjob"

	// Namespaced network
	ServiceType       = "k8s.service"
	IngressType       = "k8s.ingress"
	NetworkPolicyType = "k8s.networkpolicy"

	// Namespaced identity & RBAC
	ServiceAccountType = "k8s.serviceaccount"
	RoleType           = "k8s.role"
	RoleBindingType    = "k8s.rolebinding"

	// Namespaced storage & config
	SecretType                = "k8s.secret"
	ConfigMapType             = "k8s.configmap"
	PersistentVolumeClaimType = "k8s.persistentvolumeclaim"
	PodDisruptionBudgetType   = "k8s.poddisruptionbudget"
	ResourceQuotaType         = "k8s.resourcequota"
	LimitRangeType            = "k8s.limitrange"

	// Per-cloud cluster enrichment anchors. Sibling collectors at
	// internal/collectors/aws/eks/, gcp/gke/, digitalocean/doks/
	// emit these and link them to a k8s.cluster via the matching
	// context. Phase 8-10 of v0.11.
	EKSClusterType  = "k8s.eks_cluster"
	GKEClusterType  = "k8s.gke_cluster"
	DOKSClusterType = "k8s.doks_cluster"
)
