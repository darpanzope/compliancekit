package compliancekit.gcp.storage.pap

# Rego twin of internal/checks/gcp/storage.go § public-access-prevention.
# Flags any GCS bucket where publicAccessPrevention is not "enforced".

metadata := {
	"id": "rego-gcp-storage-public-access-prevention",
	"title": "GCS buckets must have public-access-prevention enforced (Rego)",
	"description": "Rego reimplementation of gcp-storage-public-access-prevention. Enforced PAP refuses every IAM binding granting allUsers / allAuthenticatedUsers, even retroactively.",
	"severity": "high",
	"provider": "gcp",
	"service": "storage",
	"resource_type": "gcp.storage.bucket",
	"remediation": "gcloud storage buckets update gs://NAME --public-access-prevention",
	"frameworks": {
		"soc2": ["CC6.1"],
		"iso27001": ["A.8.3"],
		"cis-v8": ["3.3"],
	},
	"tags": ["storage", "public-access"],
}

findings := [f |
	r := input.resources[_]
	r.type == "gcp.storage.bucket"
	compliancekit.attr_str(r, "public_access_prevention") != "enforced"
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("bucket %q: public_access_prevention=%q (want \"enforced\")", [r.name, compliancekit.attr_str(r, "public_access_prevention")]),
	}
]
