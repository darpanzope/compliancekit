package compliancekit.test.builtins

# Exercises every compliancekit-provided built-in so the test suite
# proves they're registered and behave per spec.

metadata := {
	"id": "test-builtins-coverage",
	"title": "Built-in coverage fixture",
	"description": "Flags every resource that triggers any compliancekit built-in. Used by policy.builtins_test.go.",
	"severity": "medium",
	"provider": "test",
}

findings := array.concat(tag_findings, attr_findings)

tag_findings := [f |
	r := input.resources[_]
	compliancekit.has_tag(r, "prod")
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": "has prod tag",
	}
]

attr_findings := [f |
	r := input.resources[_]
	compliancekit.attr_bool(r, "public") == true
	sev := compliancekit.cvss_band(8.4)
	enc := compliancekit.attr_str(r, "encryption")
	f := {
		"resource_id": r.id,
		"status": "fail",
		"severity": sev,
		"message": sprintf("public + encryption=%q", [enc]),
	}
]
