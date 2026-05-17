package compliancekit.aws.s3.public_access_block

# Rego twin of internal/checks/aws/s3.go § CheckS3PublicAccessBlock.
# Flags any aws.s3.bucket where the S3 Public Access Block is not
# fully enabled (CIS AWS Foundations 2.1.1).

metadata := {
	"id": "rego-aws-s3-public-access-block",
	"title": "S3 buckets must have Block Public Access fully enabled (Rego)",
	"description": "Rego reimplementation of aws-s3-public-access-block. Requires all four PAB flags (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) to be true on every S3 bucket. Demonstrates the pattern for parity testing.",
	"severity": "critical",
	"provider": "aws",
	"service": "s3",
	"resource_type": "aws.s3.bucket",
	"remediation": "aws s3api put-public-access-block --bucket NAME --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
	"frameworks": {
		"soc2": ["CC6.1", "CC6.6"],
		"iso27001": ["A.8.3", "A.8.20"],
		"cis-v8": ["3.3", "3.11"],
	},
	"tags": ["s3", "data-exposure", "public-access"],
}

findings := array.concat(missing_pab, missing_flags)

# Buckets with no public_access_block attribute at all → error.
missing_pab := [f |
	r := input.resources[_]
	r.type == "aws.s3.bucket"
	not r.attributes.public_access_block
	f := {
		"resource_id": r.id,
		"status": "error",
		"message": sprintf("bucket %q: public_access_block attribute missing", [r.name]),
	}
]

# Buckets with PAB present but one or more flag false → fail.
missing_flags := [f |
	r := input.resources[_]
	r.type == "aws.s3.bucket"
	pab := r.attributes.public_access_block
	pab.configured == true
	some flag in ["block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"]
	pab[flag] != true
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("bucket %q: PAB flag %q is not true", [r.name, flag]),
	}
]
