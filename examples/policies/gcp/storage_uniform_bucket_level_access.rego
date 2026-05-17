package compliancekit.gcp.storage.ubla

# Rego twin of internal/checks/gcp/storage.go § uniform-bucket-level-access.
# Flags any GCS bucket where UBLA is not enabled.

metadata := {
	"id": "rego-gcp-storage-uniform-bucket-level-access",
	"title": "GCS buckets must enable Uniform Bucket-Level Access (Rego)",
	"description": "Rego reimplementation of gcp-storage-uniform-bucket-level-access. UBLA disables per-object ACLs and enforces IAM-only access control.",
	"severity": "medium",
	"provider": "gcp",
	"service": "storage",
	"resource_type": "gcp.storage.bucket",
	"remediation": "gcloud storage buckets update gs://NAME --uniform-bucket-level-access",
	"frameworks": {
		"soc2": ["CC6.1"],
		"iso27001": ["A.5.15"],
		"cis-v8": ["3.3"],
	},
	"tags": ["storage", "iam"],
}

findings := [f |
	r := input.resources[_]
	r.type == "gcp.storage.bucket"
	compliancekit.attr_bool(r, "uniform_bucket_level_access") == false
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("bucket %q: uniform_bucket_level_access disabled", [r.name]),
	}
]
