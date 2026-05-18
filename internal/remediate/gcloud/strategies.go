package gcloud

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/remediate/render"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func init() {
	register("gcloud-storage-pap",
		[]string{"gcp-storage-public-access-prevention"}, renderStoragePAP)
	register("gcloud-storage-ubla",
		[]string{"gcp-storage-uniform-bucket-level-access"}, renderStorageUBLA)
	register("gcloud-storage-versioning",
		[]string{"gcp-storage-versioning"}, renderStorageVersioning)
	register("gcloud-sql-no-public-ip",
		[]string{"gcp-sql-no-public-ip"}, renderSQLNoPublic)
	register("gcloud-sql-deletion-protection",
		[]string{"gcp-sql-deletion-protection"}, renderSQLDeletionProtection)
	register("gcloud-sql-automated-backups",
		[]string{"gcp-sql-automated-backups"}, renderSQLBackups)
	register("gcloud-compute-shielded-vm",
		[]string{"gcp-compute-shielded-vm"}, renderShieldedVM)
	register("gcloud-compute-os-login",
		[]string{"gcp-compute-os-login-enabled"}, renderOSLogin)
	register("gcloud-compute-ssh-revoke",
		[]string{"gcp-compute-no-ssh-from-any"}, renderRevokeSSHAny)
	register("gcloud-kms-rotation",
		[]string{"gcp-kms-key-rotation"}, renderKMSRotation)
	register("gcloud-iam-primitive-manual",
		[]string{"gcp-iam-no-primitive-roles", "gcp-iam-no-broad-token-creator"},
		renderIAMPrimitiveManual)
	register("gcloud-iam-sa-keys-manual",
		[]string{"gcp-iam-no-user-managed-sa-keys", "gcp-iam-sa-key-age"},
		renderSAKeysManual)
	register("gcloud-logging-sink-exists",
		[]string{"gcp-logging-sink-exists"}, renderLoggingSink)
}

func renderStoragePAP(f compliancekit.Finding) (remediate.Snippet, error) {
	bucket := f.Resource.Name
	if bucket == "" {
		bucket = f.Resource.ID
	}
	cmd := fmt.Sprintf("gcloud storage buckets update gs://%s --public-access-prevention", bucket)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: cmd,
		VerifyCmd:   fmt.Sprintf("gcloud storage buckets describe gs://%s --format='value(publicAccessPrevention)'", bucket),
		RollbackCmd: fmt.Sprintf("gcloud storage buckets update gs://%s --no-public-access-prevention", bucket),
		Notes:       "Enforced PAP refuses every IAM binding granting allUsers / allAuthenticatedUsers, even retroactively.",
	}, nil
}

func renderStorageUBLA(f compliancekit.Finding) (remediate.Snippet, error) {
	bucket := f.Resource.Name
	if bucket == "" {
		bucket = f.Resource.ID
	}
	cmd := fmt.Sprintf("gcloud storage buckets update gs://%s --uniform-bucket-level-access", bucket)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: cmd,
		VerifyCmd: fmt.Sprintf("gcloud storage buckets describe gs://%s --format='value(iamConfiguration.uniformBucketLevelAccess.enabled)'", bucket),
		Notes:     "Disables per-object ACLs. Cannot be reverted for 90 days after enablement; migrate any existing per-object ACLs to bucket-scoped IAM before applying.",
	}, nil
}

func renderStorageVersioning(f compliancekit.Finding) (remediate.Snippet, error) {
	bucket := f.Resource.Name
	if bucket == "" {
		bucket = f.Resource.ID
	}
	cmd := fmt.Sprintf("gcloud storage buckets update gs://%s --versioning", bucket)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: cmd,
		VerifyCmd:   fmt.Sprintf("gcloud storage buckets describe gs://%s --format='value(versioning.enabled)'", bucket),
		RollbackCmd: fmt.Sprintf("gcloud storage buckets update gs://%s --no-versioning", bucket),
		Notes:       "Pair with a lifecycle rule (--lifecycle-file) to expire noncurrent versions.",
	}, nil
}

func renderSQLNoPublic(f compliancekit.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	cmd := fmt.Sprintf(
		"gcloud sql instances patch %s --no-assign-ip --network=projects/$PROJECT/global/networks/private --enable-google-private-path",
		render.ShellQuote(name))
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: cmd,
		VerifyCmd: fmt.Sprintf("gcloud sql instances describe %s --format='value(ipAddresses[].type)'", render.ShellQuote(name)),
		Notes:     "External consumers will need Cloud SQL Auth Proxy or VPC peering. Replace $PROJECT and the network reference.",
	}, nil
}

func renderSQLDeletionProtection(f compliancekit.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	cmd := fmt.Sprintf("gcloud sql instances patch %s --deletion-protection", render.ShellQuote(name))
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: cmd,
		VerifyCmd:   fmt.Sprintf("gcloud sql instances describe %s --format='value(settings.deletionProtectionEnabled)'", render.ShellQuote(name)),
		RollbackCmd: fmt.Sprintf("gcloud sql instances patch %s --no-deletion-protection", render.ShellQuote(name)),
	}, nil
}

func renderSQLBackups(f compliancekit.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	cmd := fmt.Sprintf(
		"gcloud sql instances patch %s --backup-start-time=03:00 --enable-bin-log --retained-backups-count=7",
		render.ShellQuote(name))
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: cmd,
		VerifyCmd: fmt.Sprintf("gcloud sql instances describe %s --format='value(settings.backupConfiguration)'", render.ShellQuote(name)),
		Notes:     "Enables daily backups at 03:00 UTC + binary log for PITR. --enable-bin-log applies only to MySQL; use --enable-point-in-time-recovery for Postgres.",
	}, nil
}

func renderShieldedVM(f compliancekit.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	zone := f.Resource.Region
	if zone == "" {
		zone = "us-central1-a"
	}
	cmd := fmt.Sprintf(
		"gcloud compute instances update %s --zone=%s --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring",
		render.ShellQuote(name), render.ShellQuote(zone))
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: cmd,
		VerifyCmd: fmt.Sprintf("gcloud compute instances describe %s --zone=%s --format='value(shieldedInstanceConfig)'", render.ShellQuote(name), render.ShellQuote(zone)),
		Notes:     "Custom unsigned kernels won't boot under Secure Boot. Container-Optimized OS, recent Ubuntu, RHEL all work out of the box.",
	}, nil
}

func renderOSLogin(_ compliancekit.Finding) (remediate.Snippet, error) {
	cmd := "gcloud compute project-info add-metadata --metadata=enable-oslogin=TRUE"
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: cmd,
		VerifyCmd: "gcloud compute project-info describe --format='value(commonInstanceMetadata.items[].value)' | grep -E 'enable-oslogin|TRUE'",
		Notes:     "Project-level metadata. OS Login replaces SSH-keys metadata with IAM-based access. SSH key sharing via the API stops working; users must have iam.osAdminLogin / iam.osLogin roles.",
	}, nil
}

func renderRevokeSSHAny(f compliancekit.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = "allow-ssh-from-any"
	}
	cmd := fmt.Sprintf(
		`# Replace the firewall's source range — adjust to your trusted CIDR.
gcloud compute firewall-rules update %s --source-ranges=10.0.0.0/8`,
		render.ShellQuote(name))
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: cmd,
		VerifyCmd: fmt.Sprintf("gcloud compute firewall-rules describe %s --format='value(sourceRanges)'", render.ShellQuote(name)),
		Notes:     "0.0.0.0/0 on SSH (port 22) means anyone on the internet can attempt to log in. IAP TCP forwarding (35.235.240.0/20 only) is the recommended replacement.",
	}, nil
}

func renderKMSRotation(f compliancekit.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = "REPLACE_KEY"
	}
	cmd := fmt.Sprintf(
		`# Replace LOCATION + KEYRING with your values.
gcloud kms keys update %s --location=LOCATION --keyring=KEYRING --rotation-period=90d --next-rotation-time=$(date -u -d '+1 day' +%%Y-%%m-%%dT%%H:%%M:%%SZ)`,
		render.ShellQuote(name))
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: cmd,
		VerifyCmd: fmt.Sprintf("gcloud kms keys describe %s --location=LOCATION --keyring=KEYRING --format='value(rotationPeriod)'", render.ShellQuote(name)),
		Notes:     "90-day rotation per CIS GCP Foundations. Asymmetric keys cannot auto-rotate; document manual rotation instead.",
	}, nil
}

func renderIAMPrimitiveManual(f compliancekit.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false,
		Content: "# Manual remediation — primitive role replacement requires usage analysis.\n",
		Notes: fmt.Sprintf(
			"Finding %q reports a primitive role (roles/owner, roles/editor, roles/viewer) or broad token-creator. Replace each binding with the least-privilege predefined role for the principal's actual access. Inspect via `gcloud logging read 'protoPayload.authenticationInfo.principalEmail=\"$EMAIL\"'` over the past 30 days; map API calls to predefined roles. Track via POA&M.",
			f.CheckID),
	}, nil
}

func renderSAKeysManual(f compliancekit.Finding) (remediate.Snippet, error) {
	sa := f.Resource.Name
	if sa == "" {
		sa = "REPLACE_SA_EMAIL"
	}
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false,
		Content: fmt.Sprintf(
			"# Audit existing keys, plan a rotation, then revoke the old.\n"+
				"gcloud iam service-accounts keys list --iam-account=%s\n"+
				"# gcloud iam service-accounts keys create new-key.json --iam-account=%s\n"+
				"# distribute new-key.json, update applications, then:\n"+
				"# gcloud iam service-accounts keys delete OLD_KEY_ID --iam-account=%s",
			sa, sa, sa),
		Notes: "Prefer Workload Identity (or Workload Identity Federation for external workloads) to eliminate user-managed SA keys entirely.",
	}, nil
}

func renderLoggingSink(f compliancekit.Finding) (remediate.Snippet, error) {
	cmd := `# Create an org-level export-everything sink to a BigQuery dataset (or GCS, or Pub/Sub).
gcloud logging sinks create org-audit-sink bigquery.googleapis.com/projects/$PROJECT/datasets/audit_logs \
  --organization=$ORG_ID --log-filter='logName:"cloudaudit.googleapis.com"' --include-children`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: cmd,
		VerifyCmd: "gcloud logging sinks list --organization=$ORG_ID",
		Notes:     "Replace $ORG_ID and $PROJECT. Requires the writer-identity service account returned by sinks create to have BigQuery Data Editor on the destination dataset.",
		Refs:      []string{"https://cloud.google.com/logging/docs/export/aggregated_sinks"},
	}, nil
}

// Silence unused: f.Resource.ID and helpers may be added later as
// strategies grow.
var _ = func() bool { return false }()
