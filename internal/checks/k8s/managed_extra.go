package k8s

import (
	"context"
	"fmt"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.21 phase 8 — DOKS / EKS / GKE deepening. 15 manual-verify
// checks covering managed-K8s control-plane hardening dimensions
// the vendor exposes via cloud console / cloud SDK rather than the
// K8s API. Auditor verifies via the cloud provider's UI or CLI.
//
// All emit one StatusError per cluster context. The full deep
// integration (DO/AWS/GCP SDK collectors emitting these as real-
// data) is appropriately a v0.22+ task; this phase ships the
// checklist + remediation guidance so auditors have the surface
// covered immediately.

type mkSpec struct {
	id, title, vendor string
	severity          core.Severity
	soc2, iso, cis    []string
	tags              []string
	descSuffix        string
	hint              string
	remediation       string
	scanner           string
}

var managedExtraSpecs = []mkSpec{
	// ----- DOKS -----
	{
		id: "k8s-doks-public-endpoint-disabled", title: "DOKS cluster should disable the public apiserver endpoint", vendor: "doks",
		severity: core.SeverityHigh, soc2: []string{"CC6.1"}, iso: []string{"A.8.20"}, cis: []string{"5.6.5"},
		tags: []string{"k8s", "doks", "endpoint", "manual-verify"},
		descSuffix: "Private endpoint forces all apiserver calls through the DO VPC. " +
			"Without it the apiserver is reachable from the internet (NLB-fronted).",
		remediation: "`doctl kubernetes cluster update <cluster> --set-public-access=false` " +
			"or via UI: Cluster → Settings → Networking → Public Access OFF. " +
			"Plan operator access via a bastion / VPN before flipping.",
		hint:    "doctl kubernetes cluster get <cluster> -o json | jq '.cluster.public_access'  # should be false",
		scanner: "doks.PrivateEndpoint",
	},
	{
		id: "k8s-doks-vpc-firewall-restricted", title: "DOKS VPC firewall should restrict apiserver inbound to operator CIDRs", vendor: "doks",
		severity: core.SeverityHigh, soc2: []string{"CC6.6"}, iso: []string{"A.8.22"}, cis: []string{"5.6.5"},
		tags: []string{"k8s", "doks", "firewall", "manual-verify"},
		descSuffix: "Even with private endpoint enabled, the cluster's underlying VPC " +
			"firewall must restrict source IPs to operator + CI ranges. CIS recommends " +
			"explicit allowlist rather than relying on private endpoint alone.",
		remediation: "Configure VPC firewall rules via `doctl compute firewall update " +
			"<fw> --inbound-rules='...'` to restrict tcp/443 to operator CIDRs.",
		hint:    "doctl compute firewall list  # then audit inbound rules per-firewall",
		scanner: "doks.VPCFirewallRestricted",
	},
	{
		id: "k8s-doks-audit-log-shipping-configured", title: "DOKS audit logs should ship to DO Logging or external SIEM", vendor: "doks",
		severity: core.SeverityMedium, soc2: []string{"CC7.2"}, iso: []string{"A.8.15"}, cis: []string{"5.5.1"},
		tags: []string{"k8s", "doks", "audit", "manual-verify"},
		descSuffix: "DOKS exposes the apiserver audit log via DO Logging. Without log " +
			"shipping the operator has no off-cluster trail of API access.",
		remediation: "Enable DO Logging on the cluster: Cluster → Insights → enable log " +
			"forwarding to DO Logging or a third-party SIEM (Datadog, Logz.io).",
		hint:    "doctl monitoring alert-policy list | grep -i k8s  # confirm audit-shape alerts exist",
		scanner: "doks.AuditLogShipping",
	},
	{
		id: "k8s-doks-image-pull-from-do-registry", title: "DOKS pods should pull from DO Container Registry not arbitrary public", vendor: "doks",
		severity: core.SeverityLow, soc2: []string{"CC6.7"}, iso: []string{"A.8.32"}, cis: []string{"5.5.1"},
		tags: []string{"k8s", "doks", "registry", "manual-verify"},
		descSuffix: "DOCR is the DO-native registry with built-in IAM integration. " +
			"Workloads pulling from arbitrary public registries miss the integrated " +
			"audit + IAM-bound access.",
		remediation: "Mirror upstream images into DOCR: `doctl registry repository list` " +
			"+ `crane copy <upstream> registry.digitalocean.com/<my-registry>/<name>`. " +
			"Update manifests to reference the mirrored registry.",
		hint:    "kubectl get pods -A -o jsonpath='{.items[*].spec.containers[*].image}' | tr ' ' '\\n' | grep -v registry.digitalocean.com | sort -u",
		scanner: "doks.ImagePullFromDOCR",
	},
	{
		id: "k8s-doks-nodepool-auto-upgrade-explicit", title: "DOKS node pools should enable auto-upgrade", vendor: "doks",
		severity: core.SeverityMedium, soc2: []string{"CC7.1"}, iso: []string{"A.8.8"}, cis: []string{"5.5.1"},
		tags: []string{"k8s", "doks", "patching", "manual-verify"},
		descSuffix: "DOKS auto-upgrade lifts node-pool images to the latest patch " +
			"during the maintenance window without operator intervention. Without it, " +
			"nodes accumulate kernel + container-runtime CVEs.",
		remediation: "doctl kubernetes cluster node-pool update <cluster> <pool> --auto-upgrade=true",
		hint:        "doctl kubernetes cluster node-pool list <cluster> -o json | jq '.[].auto_upgrade'  # should all be true",
		scanner:     "doks.NodePoolAutoUpgrade",
	},
	// ----- EKS -----
	{
		id: "k8s-eks-endpoint-fully-private", title: "EKS cluster endpoint should be private-only", vendor: "eks",
		severity: core.SeverityHigh, soc2: []string{"CC6.1"}, iso: []string{"A.8.20"}, cis: []string{"5.4.2"},
		tags: []string{"k8s", "eks", "endpoint", "manual-verify"},
		descSuffix: "EKS clusters default to public + private endpoint. Best practice " +
			"for production: private-only or public restricted to operator CIDR ranges.",
		remediation: "aws eks update-cluster-config --name <cluster> --resources-vpc-config " +
			"endpointPublicAccess=false,endpointPrivateAccess=true",
		hint:    "aws eks describe-cluster --name <cluster> --query 'cluster.resourcesVpcConfig.endpointPublicAccess'  # should be false",
		scanner: "eks.PrivateEndpoint",
	},
	{
		id: "k8s-eks-control-plane-logs-comprehensive", title: "EKS should enable all 5 control-plane log types", vendor: "eks",
		severity: core.SeverityHigh, soc2: []string{"CC7.2"}, iso: []string{"A.8.15"}, cis: []string{"5.5.1"},
		tags: []string{"k8s", "eks", "logging", "manual-verify"},
		descSuffix: "EKS supports 5 log types: api, audit, authenticator, controllerManager, " +
			"scheduler. CIS + SOC 2 evidence needs at least api + audit + authenticator. " +
			"All five is the production default.",
		remediation: "aws eks update-cluster-config --name <cluster> --logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}]}'",
		hint:        "aws eks describe-cluster --name <cluster> --query 'cluster.logging.clusterLogging[?enabled==`true`].types'",
		scanner:     "eks.ControlPlaneLogs",
	},
	{
		id: "k8s-eks-secrets-kms-cmk", title: "EKS secrets must be envelope-encrypted with KMS", vendor: "eks",
		severity: core.SeverityHigh, soc2: []string{"CC6.1", "CC6.7"}, iso: []string{"A.8.24"}, cis: []string{"5.3.1"},
		tags: []string{"k8s", "eks", "encryption", "manual-verify"},
		descSuffix: "EKS Secrets Encryption uses a customer-managed KMS key to wrap " +
			"the etcd-side encryption keys. Without it, secrets at-rest in etcd use " +
			"only EKS-default encryption.",
		remediation: "aws eks associate-encryption-config --cluster-name <cluster> " +
			"--encryption-config '[{\"resources\":[\"secrets\"],\"provider\":{\"keyArn\":\"<KMS_ARN>\"}}]'",
		hint:    "aws eks describe-cluster --name <cluster> --query 'cluster.encryptionConfig'",
		scanner: "eks.SecretsKMSEncrypted",
	},
	{
		id: "k8s-eks-irsa-workload-scoped", title: "EKS workloads should use IRSA (IAM Roles for Service Accounts) not node IAM", vendor: "eks",
		severity: core.SeverityMedium, soc2: []string{"CC6.1"}, iso: []string{"A.5.15"}, cis: []string{"5.5.1"},
		tags: []string{"k8s", "eks", "iam", "irsa", "manual-verify"},
		descSuffix: "IRSA scopes AWS IAM credentials per-pod via the cluster's OIDC " +
			"provider. Without it, every pod inherits the node IAM role — broad " +
			"blast radius.",
		remediation: "1) aws eks describe-cluster --query 'cluster.identity.oidc.issuer' " +
			"to confirm OIDC enabled. 2) Per workload, create IAM role + trust " +
			"policy bound to (cluster, namespace, serviceaccount). 3) Annotate the " +
			"SA: eks.amazonaws.com/role-arn=<arn>.",
		hint:    "kubectl get sa -A -o jsonpath='{range .items[?(@.metadata.annotations.eks\\.amazonaws\\.com/role-arn)]}{.metadata.namespace}/{.metadata.name}{\"\\n\"}{end}'",
		scanner: "eks.IRSAConfigured",
	},
	{
		id: "k8s-eks-node-imdsv2-required", title: "EKS node IMDS should require IMDSv2 + hop-limit 1", vendor: "eks",
		severity: core.SeverityHigh, soc2: []string{"CC6.1"}, iso: []string{"A.8.20"}, cis: []string{"5.4.1"},
		tags: []string{"k8s", "eks", "imds", "manual-verify"},
		descSuffix: "IMDSv2 with hop-limit-1 prevents in-cluster pods from " +
			"reaching the EC2 instance metadata service (169.254.169.254) — " +
			"the pivot point for AWS credential theft via SSRF.",
		remediation: "Update node group launch template metadata options:\n  " +
			"HttpTokens: required\n  HttpPutResponseHopLimit: 1\n  HttpEndpoint: enabled\n" +
			"Apply via `aws ec2 modify-launch-template` + roll the node group.",
		hint:    "aws ec2 describe-instances --filters 'Name=tag:aws:eks:cluster-name,Values=<cluster>' --query 'Reservations[].Instances[].MetadataOptions'",
		scanner: "eks.NodeIMDSv2",
	},
	// ----- GKE -----
	{
		id: "k8s-gke-private-nodes-and-endpoint", title: "GKE cluster should be private (no public node IPs, private endpoint)", vendor: "gke",
		severity: core.SeverityHigh, soc2: []string{"CC6.1"}, iso: []string{"A.8.20"}, cis: []string{"5.6.5"},
		tags: []string{"k8s", "gke", "endpoint", "manual-verify"},
		descSuffix: "Private GKE cluster removes public IPs from nodes + makes the " +
			"apiserver private-endpoint-only. The standard production posture for " +
			"GKE workloads handling regulated data.",
		remediation: "gcloud container clusters update <cluster> --enable-private-nodes " +
			"--enable-private-endpoint --master-ipv4-cidr=172.16.0.0/28",
		hint:    "gcloud container clusters describe <cluster> --format='value(privateClusterConfig.enablePrivateNodes,privateClusterConfig.enablePrivateEndpoint)'",
		scanner: "gke.PrivateCluster",
	},
	{
		id: "k8s-gke-shielded-nodes-secure-boot", title: "GKE node pools should enable Shielded Nodes", vendor: "gke",
		severity: core.SeverityHigh, soc2: []string{"CC6.1"}, iso: []string{"A.8.20"}, cis: []string{"5.1.4"},
		tags: []string{"k8s", "gke", "shielded-nodes", "manual-verify"},
		descSuffix: "Shielded Nodes enable Secure Boot + integrity monitoring + " +
			"vTPM on GKE nodes. Blocks kernel-mode rootkits + boot-time tampering. " +
			"Default-on for new clusters since 2020 but pre-existing pools may not.",
		remediation: "gcloud container clusters update <cluster> --enable-shielded-nodes",
		hint:        "gcloud container clusters describe <cluster> --format='value(shieldedNodes.enabled)'",
		scanner:     "gke.ShieldedNodes",
	},
	{
		id: "k8s-gke-workload-identity-cluster-wide", title: "GKE should enable Workload Identity for GCP IAM scoping", vendor: "gke",
		severity: core.SeverityHigh, soc2: []string{"CC6.1"}, iso: []string{"A.5.15"}, cis: []string{"5.5.1"},
		tags: []string{"k8s", "gke", "workload-identity", "manual-verify"},
		descSuffix: "Workload Identity binds Kubernetes ServiceAccount → GCP " +
			"ServiceAccount via the cluster's OIDC, scoping cloud IAM per-pod. " +
			"Without it every pod inherits the node SA — broad blast radius.",
		remediation: "gcloud container clusters update <cluster> --workload-pool=<PROJECT>.svc.id.goog",
		hint:        "gcloud container clusters describe <cluster> --format='value(workloadIdentityConfig.workloadPool)'",
		scanner:     "gke.WorkloadIdentity",
	},
	{
		id: "k8s-gke-binary-authorization-enforce", title: "GKE should enable Binary Authorization for image signature enforcement", vendor: "gke",
		severity: core.SeverityMedium, soc2: []string{"CC6.7"}, iso: []string{"A.8.32"}, cis: []string{"5.5.1"},
		tags: []string{"k8s", "gke", "binary-auth", "supply-chain", "manual-verify"},
		descSuffix: "Binary Authorization enforces image-signature policies at " +
			"deploy time — only images signed by approved attestors can run. " +
			"GCP-native equivalent of cosign verify-images at admission.",
		remediation: "1) gcloud container clusters update <cluster> --binauthz-evaluation-mode=PROJECT_SINGLETON_POLICY_ENFORCE. " +
			"2) Define a Policy: gcloud container binauthz policy import policy.yaml.",
		hint:    "gcloud container clusters describe <cluster> --format='value(binaryAuthorization.evaluationMode)'",
		scanner: "gke.BinaryAuthorization",
	},
	{
		id: "k8s-gke-database-encryption-cmek", title: "GKE etcd secrets should use customer-managed KMS encryption (CMEK)", vendor: "gke",
		severity: core.SeverityMedium, soc2: []string{"CC6.7"}, iso: []string{"A.8.24"}, cis: []string{"5.3.1"},
		tags: []string{"k8s", "gke", "encryption", "cmek", "manual-verify"},
		descSuffix: "GKE Application-layer Secrets Encryption wraps etcd-stored " +
			"Secrets with a customer-managed Cloud KMS key. CMEK = customer-managed " +
			"= operator controls the key lifecycle, rotation, and access audit.",
		remediation: "1) Create Cloud KMS key. 2) Grant the GKE service account " +
			"roles/cloudkms.cryptoKeyEncrypterDecrypter on the key. 3) gcloud container " +
			"clusters update <cluster> --database-encryption-key=projects/<P>/locations/<L>/keyRings/<R>/cryptoKeys/<K>",
		hint:    "gcloud container clusters describe <cluster> --format='value(databaseEncryption.state,databaseEncryption.keyName)'",
		scanner: "gke.DatabaseEncryptionCMEK",
	},
}

func init() {
	for _, spec := range managedExtraSpecs {
		spec := spec
		core.Register(mkCheck(spec), mkCheckFunc(spec))
	}
}

func mkCheck(spec mkSpec) core.Check {
	return core.Check{
		ID: spec.id, Title: spec.title, Severity: spec.severity,
		Provider:     "kubernetes",
		Service:      spec.vendor,
		ResourceType: k8scol.ClusterType,
		Description:  fmt.Sprintf("%s deepening. %s", spec.vendor, spec.descSuffix),
		Remediation:  spec.remediation,
		Frameworks: map[string][]string{
			"soc2":     spec.soc2,
			"iso27001": spec.iso,
			"cis-v8":   spec.cis,
		},
		Tags:    spec.tags,
		Scanner: spec.scanner,
	}
}

func mkCheckFunc(spec mkSpec) core.CheckFunc {
	return func(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
		findings := []core.Finding{}
		ctxs := g.ByType(k8scol.ClusterType)
		if len(ctxs) == 0 {
			return findings, nil
		}
		for _, c := range ctxs {
			findings = append(findings, core.Finding{
				CheckID: spec.id, Severity: spec.severity,
				Resource: c.Ref(), Tags: spec.tags,
				Status: core.StatusError,
				Message: fmt.Sprintf("cluster %q (%s deepening): %s — hint: %s",
					c.Name, spec.vendor, spec.title, spec.hint),
			})
		}
		return findings, nil
	}
}
