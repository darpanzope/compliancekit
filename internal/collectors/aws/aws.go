// Package aws is the AWS Collector.
//
// At v0.7 it fetches the resources needed by the 30 highest-leverage
// AWS checks (IAM / EC2 / S3 / RDS / CloudTrail / KMS / Config /
// GuardDuty) and emits typed compliancekit.Resource values into the engine's
// ResourceGraph.
//
// Per ARCHITECTURE.md and DECISIONS.md ADR-007 we are explicitly NOT
// pursuing Prowler-parity. The bar is "30 checks that map cleanly to
// the three shipping frameworks (SOC 2, ISO 27001, CIS v8) and that
// land the most operational value per check." Inspector / Macie /
// Security Hub *ingest* lands at v0.13 alongside OCSF; EKS lands at
// v0.11 with the K8s arc; multi-account AWS Organizations traversal
// lands at v1.2 with multi-tenant.
//
// Authentication follows the standard AWS SDK chain so an operator
// never has to learn a new auth surface:
//
//   - AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars
//   - AWS_PROFILE (~/.aws/credentials)
//   - AWS_ROLE_ARN (assume-role for cross-account)
//   - IMDSv2 instance role (when running on EC2)
//   - GitHub Actions OIDC federation
//
// All five are SDK defaults; the collector does not add custom
// credential providers.
//
// Per-region clients are pooled. The default scope is "all regions
// the credential can see"; an explicit `--regions` filter narrows.
package aws
