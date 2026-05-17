package compliancekit.do.spaces.public_acl

# Rego twin of internal/checks/digitalocean/spaces.go § public-acl.
# Flags any Spaces bucket whose ACL is public-read.

metadata := {
	"id": "rego-do-spaces-public-acl",
	"title": "DO Spaces buckets must not have public-read ACL (Rego)",
	"description": "Rego reimplementation of do-spaces-public-acl. Public-read ACL exposes every object to the internet. Public asset delivery should use a CDN with signed URLs over an explicitly-public bucket.",
	"severity": "high",
	"provider": "digitalocean",
	"service": "spaces",
	"resource_type": "digitalocean.spaces_bucket",
	"remediation": "aws s3api put-bucket-acl --bucket NAME --acl private --endpoint-url https://REGION.digitaloceanspaces.com",
	"frameworks": {
		"soc2": ["CC6.1"],
		"iso27001": ["A.8.3"],
		"cis-v8": ["3.3"],
	},
	"tags": ["spaces", "data-exposure", "public-access"],
}

findings := [f |
	r := input.resources[_]
	r.type == "digitalocean.spaces_bucket"
	compliancekit.attr_str(r, "acl") == "public-read"
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("bucket %q: ACL is public-read", [r.name]),
	}
]
