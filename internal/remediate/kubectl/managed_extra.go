package kubectl

import (
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.21 phase 8 — kubectl strategies for the 15 managed-K8s
// (DOKS / EKS / GKE) deepening checks. Most remediations are cloud-
// CLI shaped (doctl / aws / gcloud) since the dimension lives in the
// cloud control plane, not the cluster. Snippet still routes to
// FormatKubectl because that's what the parity gate measures + the
// snippet's content can be any executable shell.

var managedStrategies = map[string]string{
	"k8s-doks-public-endpoint-disabled":        "doctl kubernetes cluster update <cluster> --set-public-access=false\n\n# Plan operator access via bastion / VPN BEFORE flipping — once private,\n# the apiserver is reachable only from within the DO VPC.",
	"k8s-doks-vpc-firewall-restricted":         "# List your DO firewalls + add rules restricting tcp/443 to operator CIDRs:\ndoctl compute firewall list\ndoctl compute firewall update <FW-ID> --inbound-rules='protocol:tcp,ports:443,address:203.0.113.0/24'",
	"k8s-doks-audit-log-shipping-configured":   "# Enable DO Logging on the cluster via UI:\n#   Cluster → Insights → Logs → Enable\n# Or via API:\ncurl -X POST -H 'Authorization: Bearer $DO_API_TOKEN' \\\n  -d '{\"target\":\"datadog\",\"config\":{\"api_key\":\"<KEY>\"}}' \\\n  https://api.digitalocean.com/v2/monitoring/log-destinations",
	"k8s-doks-image-pull-from-do-registry":     "# Mirror upstream into DOCR + update manifest refs:\ndoctl registry login\ncrane copy docker.io/nginx:1.25.3 registry.digitalocean.com/myregistry/nginx:1.25.3\nkubectl set image deployment/<NAME> nginx=registry.digitalocean.com/myregistry/nginx:1.25.3 -n <NS>",
	"k8s-doks-nodepool-auto-upgrade-explicit":  "doctl kubernetes cluster node-pool update <CLUSTER> <POOL> --auto-upgrade=true\n\n# Confirm:\ndoctl kubernetes cluster node-pool list <CLUSTER> -o json | jq '.[].auto_upgrade'",
	"k8s-eks-endpoint-fully-private":           "aws eks update-cluster-config \\\n  --name <cluster> \\\n  --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true\n\n# Plan operator access via bastion / VPN before flipping — VPC private\n# endpoint reachable only from inside the cluster VPC + peered networks.",
	"k8s-eks-control-plane-logs-comprehensive": "aws eks update-cluster-config \\\n  --name <cluster> \\\n  --logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}]}'\n\n# Then ensure CloudWatch log group retention is set to ≥30d:\naws logs put-retention-policy \\\n  --log-group-name /aws/eks/<cluster>/cluster \\\n  --retention-in-days 30",
	"k8s-eks-secrets-kms-cmk":                  "# Create KMS key + grant EKS access:\nKEY_ARN=$(aws kms create-key --description 'EKS secrets encryption' --query 'KeyMetadata.Arn' --output text)\n\n# Associate with cluster (one-time, irreversible without cluster rebuild):\naws eks associate-encryption-config \\\n  --cluster-name <cluster> \\\n  --encryption-config '[{\"resources\":[\"secrets\"],\"provider\":{\"keyArn\":\"'$KEY_ARN'\"}}]'\n\n# Re-encrypt existing secrets:\nkubectl get secrets -A -o json | kubectl replace -f -",
	"k8s-eks-irsa-workload-scoped":             "# 1. Confirm OIDC provider exists for the cluster:\nOIDC_ISSUER=$(aws eks describe-cluster --name <cluster> --query 'cluster.identity.oidc.issuer' --output text)\n\n# 2. Create IAM role with trust policy scoped to (namespace, SA):\naws iam create-role --role-name myapp-sa-role --assume-role-policy-document '{...}'\n\n# 3. Annotate the K8s ServiceAccount:\nkubectl annotate serviceaccount -n <ns> <sa> eks.amazonaws.com/role-arn=arn:aws:iam::ACCOUNT:role/myapp-sa-role\n\n# 4. Use the SA in the pod:\nkubectl patch deployment <name> -n <ns> --type=json -p='[{\"op\":\"replace\",\"path\":\"/spec/template/spec/serviceAccountName\",\"value\":\"<sa>\"}]'",
	"k8s-eks-node-imdsv2-required":             "# Update the launch template metadata options:\naws ec2 modify-launch-template \\\n  --launch-template-id <lt-id> \\\n  --launch-template-data 'MetadataOptions={HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled}'\n\n# Roll the node group so existing nodes get the new launch template:\naws eks update-nodegroup-version --cluster-name <cluster> --nodegroup-name <ng> --force",
	"k8s-gke-private-nodes-and-endpoint":       "gcloud container clusters update <cluster> \\\n  --enable-private-nodes \\\n  --enable-private-endpoint \\\n  --master-ipv4-cidr=172.16.0.0/28\n\n# Operator access then requires Cloud VPN, Cloud Interconnect, or\n# Identity-Aware Proxy with TCP tunneling.",
	"k8s-gke-shielded-nodes-secure-boot":       "gcloud container clusters update <cluster> --enable-shielded-nodes\n\n# Per-pool override if needed:\ngcloud container node-pools update <pool> --cluster <cluster> --shielded-secure-boot --shielded-integrity-monitoring",
	"k8s-gke-workload-identity-cluster-wide":   "# Enable on cluster:\ngcloud container clusters update <cluster> --workload-pool=<PROJECT>.svc.id.goog\n\n# Per node pool (one-time):\ngcloud container node-pools update <pool> --cluster <cluster> --workload-metadata=GKE_METADATA\n\n# Bind K8s SA to GCP SA:\ngcloud iam service-accounts add-iam-policy-binding GSA@<PROJECT>.iam.gserviceaccount.com \\\n  --role roles/iam.workloadIdentityUser \\\n  --member serviceAccount:<PROJECT>.svc.id.goog[<ns>/<ksa>]\n\nkubectl annotate serviceaccount <ksa> -n <ns> iam.gke.io/gcp-service-account=GSA@<PROJECT>.iam.gserviceaccount.com",
	"k8s-gke-binary-authorization-enforce":     "# Enable enforcement:\ngcloud container clusters update <cluster> --binauthz-evaluation-mode=PROJECT_SINGLETON_POLICY_ENFORCE\n\n# Import a Policy:\ncat > policy.yaml <<EOF\ndefaultAdmissionRule:\n  evaluationMode: REQUIRE_ATTESTATION\n  enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG\n  requireAttestationsBy:\n    - projects/<PROJECT>/attestors/my-attestor\nEOF\n\ngcloud container binauthz policy import policy.yaml",
	"k8s-gke-database-encryption-cmek":         "# 1. Create Cloud KMS key:\ngcloud kms keys create gke-secrets-key --location us-central1 --keyring gke-keyring --purpose encryption\n\n# 2. Grant GKE service account access:\ngcloud kms keys add-iam-policy-binding gke-secrets-key --location us-central1 --keyring gke-keyring \\\n  --member 'serviceAccount:service-<PROJECT_NUMBER>@container-engine-robot.iam.gserviceaccount.com' \\\n  --role roles/cloudkms.cryptoKeyEncrypterDecrypter\n\n# 3. Update cluster:\ngcloud container clusters update <cluster> \\\n  --database-encryption-key=projects/<P>/locations/us-central1/keyRings/gke-keyring/cryptoKeys/gke-secrets-key",
}

func init() {
	for id, body := range managedStrategies {
		id := id
		body := body
		register("kubectl-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: false,
				Content: "# Managed K8s deepening — remediation lives in the cloud control plane.\n# " + id + "\n\n" + body + "\n",
				Notes:   "Most managed-K8s hardening changes are one-time cluster-config flips. Test on a non-prod cluster first when the change affects endpoint accessibility (private cluster, IMDSv2 hop limit). Some flips are irreversible (EKS Secrets Encryption association).",
			}, nil
		})
	}
}
