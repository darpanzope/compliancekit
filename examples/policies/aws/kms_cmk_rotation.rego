package compliancekit.aws.kms.cmk_rotation

# Rego twin of internal/checks/aws/kms.go § CheckKMSCMKRotation.
# Flags any aws.kms.key (customer-managed, symmetric) where annual
# key rotation is not enabled.

metadata := {
	"id": "rego-aws-kms-cmk-rotation",
	"title": "Customer-managed KMS keys must have annual rotation enabled (Rego)",
	"description": "Rego reimplementation of aws-kms-cmk-rotation. Customer-managed CMKs should rotate yearly per CIS AWS Foundations 3.8.",
	"severity": "medium",
	"provider": "aws",
	"service": "kms",
	"resource_type": "aws.kms.key",
	"remediation": "aws kms enable-key-rotation --key-id KEY_ID",
	"frameworks": {
		"soc2": ["CC6.1"],
		"iso27001": ["A.8.24"],
		"cis-v8": ["3.11"],
	},
	"tags": ["kms", "encryption", "key-rotation"],
}

findings := [f |
	r := input.resources[_]
	r.type == "aws.kms.key"
	# Only customer-managed, symmetric keys need rotation.
	r.attributes.key_manager == "CUSTOMER"
	r.attributes.key_spec == "SYMMETRIC_DEFAULT"
	compliancekit.attr_bool(r, "rotation_enabled") == false
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("key %q: rotation not enabled", [r.name]),
	}
]
