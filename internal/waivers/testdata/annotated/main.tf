# Example Terraform module exercising in-code waiver annotations.

resource "aws_s3_bucket" "public_cdn" {
  bucket = "acme-public-cdn"
  acl    = "public-read"

  # compliancekit:waive aws-s3-no-public-acls aws.s3.bucket.public-cdn reason="public CDN bucket; CloudFront serves at the edge with signed URLs" approver=security@acme.com expires=2099-12-31
}

resource "aws_iam_user" "automation" {
  name = "ci-automation"

  // compliancekit:waive aws-iam-no-user-managed-policies aws.iam.user.ci-automation
}
