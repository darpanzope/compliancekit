package compliancekit.gcp.sql.deletion_protection

# Rego twin of internal/checks/gcp/sql.go § deletion-protection.
# Flags any Cloud SQL instance without deletion protection enabled.

metadata := {
	"id": "rego-gcp-sql-deletion-protection",
	"title": "Cloud SQL instances must have deletion protection enabled (Rego)",
	"description": "Rego reimplementation of gcp-sql-deletion-protection. Prevents accidental delete of production databases via gcloud or Terraform.",
	"severity": "high",
	"provider": "gcp",
	"service": "sql",
	"resource_type": "gcp.sql.instance",
	"remediation": "gcloud sql instances patch NAME --deletion-protection",
	"frameworks": {
		"soc2": ["CC7.5"],
		"iso27001": ["A.8.13"],
		"cis-v8": ["11.1"],
	},
	"tags": ["sql", "data-loss-prevention"],
}

findings := [f |
	r := input.resources[_]
	r.type == "gcp.sql.instance"
	compliancekit.attr_bool(r, "deletion_protection_enabled") == false
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("instance %q: deletion_protection disabled", [r.name]),
	}
]
