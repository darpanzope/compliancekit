package terraform

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/remediate/render"
)

func init() {
	register("tf-gcp-storage-pap",
		[]string{"gcp-storage-public-access-prevention"},
		renderGCPStoragePAP)
	register("tf-gcp-storage-ubla",
		[]string{"gcp-storage-uniform-bucket-level-access"},
		renderGCPStorageUBLA)
	register("tf-gcp-storage-versioning",
		[]string{"gcp-storage-versioning"},
		renderGCPStorageVersioning)
	register("tf-gcp-storage-logging",
		[]string{"gcp-storage-logging"},
		renderGCPStorageLogging)
	register("tf-gcp-sql-no-public-ip",
		[]string{"gcp-sql-no-public-ip"},
		renderGCPSQLNoPublic)
	register("tf-gcp-sql-deletion-protection",
		[]string{"gcp-sql-deletion-protection"},
		renderGCPSQLDeletionProtection)
	register("tf-gcp-sql-automated-backups",
		[]string{"gcp-sql-automated-backups"},
		renderGCPSQLBackups)
	register("tf-gcp-compute-shielded-vm",
		[]string{"gcp-compute-shielded-vm"},
		renderGCPComputeShieldedVM)
	register("tf-gcp-bigquery-default-cmek",
		[]string{"gcp-bigquery-default-cmek"},
		renderGCPBigQueryCMEK)
	register("tf-gcp-kms-rotation",
		[]string{"gcp-kms-key-rotation"},
		renderGCPKMSRotation)
	register("tf-gcp-iam-no-primitive-manual",
		[]string{"gcp-iam-no-primitive-roles"},
		renderGCPIAMPrimitiveManual)
}

func renderGCPStoragePAP(f core.Finding) (remediate.Snippet, error) {
	bucket := f.Resource.Name
	if bucket == "" {
		bucket = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "google_storage_bucket", tfIdent(bucket))
	b.Attr("# NOTE: append public_access_prevention to existing google_storage_bucket", "")
	b.Attr("name", bucket)
	b.Attr("location", "US")
	b.Attr("public_access_prevention", "enforced")
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("gcloud storage buckets describe gs://%s --format='value(publicAccessPrevention)'", bucket),
		Notes:      "Enforced PAP refuses every IAM binding granting allUsers / allAuthenticatedUsers, even retroactively. Pairs with UBLA below; both belong on every production bucket.",
		Refs: []string{
			"https://cloud.google.com/storage/docs/public-access-prevention",
		},
	}, nil
}

func renderGCPStorageUBLA(f core.Finding) (remediate.Snippet, error) {
	bucket := f.Resource.Name
	if bucket == "" {
		bucket = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "google_storage_bucket", tfIdent(bucket))
	b.Attr("# NOTE: enable UBLA on existing google_storage_bucket", "")
	b.Attr("name", bucket)
	b.Attr("location", "US")
	b.Attr("uniform_bucket_level_access", true)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("gcloud storage buckets describe gs://%s --format='value(iamConfiguration.uniformBucketLevelAccess.enabled)'", bucket),
		Notes:      "UBLA disables per-object ACLs and enforces IAM-only access control. Migrate any existing per-object ACLs to bucket-scoped IAM bindings before enabling — UBLA cannot be reverted for 90 days after enablement.",
		Refs: []string{
			"https://cloud.google.com/storage/docs/uniform-bucket-level-access",
		},
	}, nil
}

func renderGCPStorageVersioning(f core.Finding) (remediate.Snippet, error) {
	bucket := f.Resource.Name
	if bucket == "" {
		bucket = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "google_storage_bucket", tfIdent(bucket))
	b.Attr("# NOTE: enable versioning on existing google_storage_bucket", "")
	b.Attr("name", bucket)
	b.Attr("location", "US")
	ver := b.SubBlock("versioning")
	ver.Attr("enabled", true)
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("gcloud storage buckets describe gs://%s --format='value(versioning.enabled)'", bucket),
		Notes:      "Versioning preserves overwrites and deletes. Plan a lifecycle rule (lifecycle { ... action.type = \"Delete\" condition.num_newer_versions = N }) to cap storage growth.",
		Refs: []string{
			"https://cloud.google.com/storage/docs/object-versioning",
		},
	}, nil
}

func renderGCPStorageLogging(f core.Finding) (remediate.Snippet, error) {
	bucket := f.Resource.Name
	if bucket == "" {
		bucket = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "google_storage_bucket", tfIdent(bucket))
	b.Attr("# NOTE: enable usage logging on existing google_storage_bucket", "")
	b.Attr("name", bucket)
	b.Attr("location", "US")
	log := b.SubBlock("logging")
	log.RawAttr("log_bucket", "google_storage_bucket.access_logs.name")
	log.Attr("log_object_prefix", fmt.Sprintf("gcs/%s/", bucket))
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		Notes:      "Requires a separate google_storage_bucket.access_logs target with the cloud-storage-analytics@google.com service principal as Writer (see linked guide).",
		Refs: []string{
			"https://cloud.google.com/storage/docs/access-logs",
		},
	}, nil
}

func renderGCPSQLNoPublic(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "google_sql_database_instance", tfIdent(name))
	b.Attr("# NOTE: disable public IP on existing google_sql_database_instance", "")
	b.Attr("name", name)
	settings := b.SubBlock("settings")
	ip := settings.SubBlock("ip_configuration")
	ip.Attr("ipv4_enabled", false)
	ip.RawAttr("private_network", "google_compute_network.private.id")
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("gcloud sql instances describe %s --format='value(settings.ipConfiguration.ipv4Enabled)'", render.ShellQuote(name)),
		Notes:      "Disables the public IP and requires a VPC. Consumers outside the VPC must use Cloud SQL Auth Proxy or a private connection — verify before applying.",
		Refs: []string{
			"https://cloud.google.com/sql/docs/mysql/configure-private-ip",
		},
	}, nil
}

func renderGCPSQLDeletionProtection(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "google_sql_database_instance", tfIdent(name))
	b.Attr("# NOTE: enable deletion protection on existing google_sql_database_instance", "")
	b.Attr("name", name)
	b.Attr("deletion_protection", true)
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("gcloud sql instances describe %s --format='value(settings.deletionProtectionEnabled)'", render.ShellQuote(name)),
		Notes:      "Prevents accidental `gcloud sql instances delete` and `terraform destroy` from removing the database. Drop back to false when you intend to delete intentionally.",
		Refs: []string{
			"https://cloud.google.com/sql/docs/mysql/deletion-protection",
		},
	}, nil
}

func renderGCPSQLBackups(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "google_sql_database_instance", tfIdent(name))
	b.Attr("# NOTE: enable automated backups on existing google_sql_database_instance", "")
	b.Attr("name", name)
	settings := b.SubBlock("settings")
	backup := settings.SubBlock("backup_configuration")
	backup.Attr("enabled", true)
	backup.Attr("start_time", "03:00")
	backup.Attr("point_in_time_recovery_enabled", true)
	backup.Attr("backup_retention_settings", map[string]string{
		"retained_backups": "7",
		"retention_unit":   "COUNT",
	})
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("gcloud sql instances describe %s --format='value(settings.backupConfiguration.enabled)'", render.ShellQuote(name)),
		Notes:      "Daily backups at 03:00 UTC with PITR (transaction log) for the past 7 days. Raise retained_backups for stricter RPO requirements.",
		Refs: []string{
			"https://cloud.google.com/sql/docs/mysql/backup-recovery/backups",
		},
	}, nil
}

func renderGCPComputeShieldedVM(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "google_compute_instance", tfIdent(name))
	b.Attr("# NOTE: append shielded_instance_config to existing google_compute_instance", "")
	b.Attr("name", name)
	si := b.SubBlock("shielded_instance_config")
	si.Attr("enable_secure_boot", true)
	si.Attr("enable_vtpm", true)
	si.Attr("enable_integrity_monitoring", true)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("gcloud compute instances describe %s --format='value(shieldedInstanceConfig)'", render.ShellQuote(name)),
		Notes:      "Requires a Shielded-VM-compatible image (Container-Optimized OS, recent Ubuntu, RHEL) and Secure Boot-compatible disks. Custom unsigned kernels will fail to boot under Secure Boot.",
		Refs: []string{
			"https://cloud.google.com/compute/shielded-vm/docs/modifying-shielded-vm",
		},
	}, nil
}

func renderGCPBigQueryCMEK(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "google_bigquery_dataset", tfIdent(name))
	b.Attr("# NOTE: set default_encryption_configuration on existing google_bigquery_dataset", "")
	b.Attr("dataset_id", name)
	enc := b.SubBlock("default_encryption_configuration")
	enc.RawAttr("kms_key_name", "google_kms_crypto_key.bq.id")
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		Notes:      "Requires a separately-defined google_kms_crypto_key (referenced as google_kms_crypto_key.bq) plus IAM binding granting bigquery-encryption@system.gserviceaccount.com the cloudkms.cryptoKeyEncrypterDecrypter role on the key.",
		Refs: []string{
			"https://cloud.google.com/bigquery/docs/customer-managed-encryption",
		},
	}, nil
}

func renderGCPKMSRotation(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "google_kms_crypto_key", tfIdent(name))
	b.Attr("# NOTE: set rotation_period on existing google_kms_crypto_key", "")
	b.Attr("name", name)
	b.Attr("rotation_period", "7776000s")
	b.Attr("purpose", "ENCRYPT_DECRYPT")
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("gcloud kms keys describe %s --format='value(rotationPeriod)'", render.ShellQuote(name)),
		Notes:      "7776000 seconds = 90 days, the CIS GCP Foundations recommendation. Asymmetric keys can't rotate automatically; leave as-is and document manual rotation.",
		Refs: []string{
			"https://cloud.google.com/kms/docs/key-rotation",
		},
	}, nil
}

func renderGCPIAMPrimitiveManual(f core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk:       remediate.RiskManual,
		Idempotent: false,
		Content:    "# Manual remediation required — see Notes.\n",
		Notes: fmt.Sprintf(
			"Finding %q reports a primitive role (roles/owner, roles/editor, roles/viewer) at the project level. Replace each binding with the least-privilege predefined role for the principal's actual access need; primitive→predefined cannot be done blindly because it depends on what the principal does. Map the principal's API call history (via Cloud Audit Logs) to the matching predefined roles, draft a replacement, apply with `gcloud projects set-iam-policy`, and watch for permission-denied errors over the next 24h.",
			f.CheckID),
		Refs: []string{
			"https://cloud.google.com/iam/docs/understanding-roles#basic",
		},
	}, nil
}
