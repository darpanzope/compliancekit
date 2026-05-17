package compliancekit.aws.iam.password_policy

# Rego twin of internal/checks/aws/iam.go § CheckIAMPasswordPolicy.
# Flags the AWS account's IAM password policy if any of the CIS
# AWS Foundations 1.8-1.14 requirements is not met.

metadata := {
	"id": "rego-aws-iam-password-policy",
	"title": "AWS IAM password policy must meet CIS minimums (Rego)",
	"description": "Rego reimplementation of aws-iam-password-policy. Minimum length 14, all four character classes required, max age 90 days, reuse-prevention 24.",
	"severity": "medium",
	"provider": "aws",
	"service": "iam",
	"resource_type": "aws.account",
	"remediation": "aws iam update-account-password-policy with the required flags",
	"frameworks": {
		"soc2": ["CC6.1"],
		"iso27001": ["A.8.5"],
		"cis-v8": ["5.2"],
	},
	"tags": ["iam", "password-policy"],
}

# The account anchor carries the password policy as a nested object.
# Each violation is its own finding so the operator sees which
# specific dimension failed.
findings := array.concat(
	array.concat(length_violations, classes_violations),
	array.concat(age_violations, reuse_violations),
)

length_violations := [f |
	r := input.resources[_]
	r.type == "aws.account"
	r.attributes.password_policy.minimum_password_length < 14
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("account %q: minimum_password_length < 14", [r.name]),
	}
]

classes_violations := [f |
	r := input.resources[_]
	r.type == "aws.account"
	some cls in ["require_uppercase", "require_lowercase", "require_numbers", "require_symbols"]
	r.attributes.password_policy[cls] != true
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("account %q: %s not enforced", [r.name, cls]),
	}
]

age_violations := [f |
	r := input.resources[_]
	r.type == "aws.account"
	r.attributes.password_policy.max_password_age > 90
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("account %q: max_password_age > 90", [r.name]),
	}
]

reuse_violations := [f |
	r := input.resources[_]
	r.type == "aws.account"
	r.attributes.password_policy.password_reuse_prevention < 24
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("account %q: password_reuse_prevention < 24", [r.name]),
	}
]
