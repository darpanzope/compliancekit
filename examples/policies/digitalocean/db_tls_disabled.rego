package compliancekit.do.db.tls_disabled

# Rego twin of internal/checks/digitalocean/databases.go § tls-disabled.
# Flags any managed-database cluster where TLS enforcement is off.

metadata := {
	"id": "rego-do-db-tls-disabled",
	"title": "Managed database clusters must enforce TLS (Rego)",
	"description": "Rego reimplementation of do-db-tls-disabled. Connections without TLS leak credentials and query content to anyone on the network path.",
	"severity": "high",
	"provider": "digitalocean",
	"service": "databases",
	"resource_type": "digitalocean.database",
	"remediation": "Update every connection string to require sslmode=require / sslMode=REQUIRED.",
	"frameworks": {
		"soc2": ["CC6.7"],
		"iso27001": ["A.8.24"],
		"cis-v8": ["3.10"],
	},
	"tags": ["database", "encryption-in-transit"],
}

findings := [f |
	r := input.resources[_]
	r.type == "digitalocean.database"
	compliancekit.attr_bool(r, "tls_enforced") == false
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("cluster %q: TLS not enforced", [r.name]),
	}
]
