// Package gcp is the Google Cloud Platform Collector.
//
// At v0.8 it fetches the resources needed by the 25 highest-leverage
// GCP checks (IAM / Compute Engine / GCS / Cloud SQL / Cloud Logging
// / KMS / BigQuery) and emits typed compliancekit.Resource values into the
// engine's ResourceGraph.
//
// Per ADR-007 the GCP provider builds on the cloud-common abstractions
// established for AWS at v0.7. The same account/region attribution
// surface applies; for GCP the "account" is the project ID and the
// "region" is the location (multi-regional / regional / zonal).
//
// Authentication uses the standard Application Default Credentials
// (ADC) chain so an operator never has to learn a new auth surface:
//
//   - GOOGLE_APPLICATION_CREDENTIALS pointing at a service-account
//     JSON
//   - gcloud user credentials at ~/.config/gcloud/application_default_credentials.json
//   - GCE metadata server (when running on a GCE VM)
//   - Workload Identity Federation (when running in GitHub Actions
//     with the right setup)
//
// Multi-project scans are explicit: cfg.Providers.GCP.Projects lists
// the project IDs in scope. Empty defaults to the credential's
// default project (one project). Full organization-level traversal
// lands at v1.2 with multi-tenant.
package gcp
