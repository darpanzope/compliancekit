package compliancekit.test.sample

# Sample policy used by internal/policy/policy_test.go. Demonstrates
# the canonical shape every shipped Rego check follows.

metadata := {
	"id": "test-sample-bucket-public",
	"title": "Sample policy: buckets must not be public",
	"description": "Fixture policy used by the policy package's unit tests. Flags every resource of type test.bucket whose attributes.public=true.",
	"severity": "high",
	"provider": "test",
	"service": "bucket",
	"resource_type": "test.bucket",
	"rationale": "public buckets leak data",
	"remediation": "set attributes.public=false",
	"frameworks": {
		"soc2": ["CC6.1"],
	},
	"tags": ["test", "sample"],
}

findings := [f |
	r := input.resources[_]
	r.type == "test.bucket"
	r.attributes.public == true
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("bucket %q is public", [r.name]),
	}
]
