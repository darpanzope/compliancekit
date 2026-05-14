// Package gcp holds the GCP check implementations.
//
// Per ARCHITECTURE.md and DECISIONS.md ADR-007, v0.8 ships 25 checks
// across 7 GCP services (IAM, Compute, GCS, Cloud SQL, Logging, KMS,
// BigQuery). The CIS GCP Foundations Benchmark v2.0 is the source of
// truth for the CIS mappings.
package gcp

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	"github.com/darpanzope/compliancekit/internal/core"
)

// ========================================================================
// IAM checks
// ========================================================================

// primitiveRoles is the set of GCP "primitive" (over-broad) IAM
// roles. CIS GCP 1.4 / 1.8 prescribe these not be granted at
// project level.
var primitiveRoles = map[string]bool{
	"roles/owner":  true,
	"roles/editor": true,
	"roles/viewer": true,
}

// CheckNoPrimitiveRoles forbids primitive roles at project IAM
// policy. CIS GCP 1.4 + 1.8.
var CheckNoPrimitiveRoles = core.Check{
	ID:           "gcp-iam-no-primitive-roles",
	Title:        "GCP project IAM must not grant primitive roles (Owner/Editor/Viewer)",
	Severity:     core.SeverityHigh,
	Provider:     "gcp",
	Service:      "iam",
	ResourceType: gcpcol.IAMPolicyType,
	Description: "Primitive GCP roles (Owner, Editor, Viewer) grant access to " +
		"every API in the project, defeating least-privilege. CIS GCP " +
		"Foundations Benchmark 1.4 (no service account user impersonation " +
		"escalation) and 1.8 (separation of duties) prescribe using " +
		"predefined or custom roles scoped to the actual job instead.",
	Remediation: "List who has primitive roles: 'gcloud projects " +
		"get-iam-policy <project> --flatten=bindings --filter=\"bindings.role:roles/(owner|editor|viewer)\"'. " +
		"For each member, identify the specific actions they need and " +
		"replace with a predefined role (e.g. roles/storage.objectAdmin) " +
		"or a custom role.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"5.4", "6.7"},
	},
	Tags:    []string{"iam", "least-privilege", "primitive-roles"},
	Scanner: "iam.NoPrimitiveRoles",
}

func NoPrimitiveRoles(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(gcpcol.IAMPolicyType) {
		bindings, _ := p.Attributes["bindings"].([]map[string]any)
		violators := map[string][]string{} // role -> members
		for _, b := range bindings {
			role, _ := b["role"].(string)
			if !primitiveRoles[role] {
				continue
			}
			members, _ := b["members"].([]string)
			if len(members) > 0 {
				violators[role] = members
			}
		}
		f := core.Finding{
			CheckID:  CheckNoPrimitiveRoles.ID,
			Severity: CheckNoPrimitiveRoles.Severity,
			Resource: p.Ref(),
			Tags:     CheckNoPrimitiveRoles.Tags,
		}
		if len(violators) == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("project %q: no primitive role bindings", p.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("project %q: primitive role bindings present (%s)",
				p.Name, summarizeBindings(violators))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func summarizeBindings(m map[string][]string) string {
	parts := make([]string, 0, len(m))
	for role, members := range m {
		parts = append(parts, fmt.Sprintf("%s: %d members", role, len(members)))
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// CheckNoBroadTokenCreator forbids granting roles/iam.serviceAccountTokenCreator
// or roles/iam.serviceAccountUser at the project level. These let
// the holder impersonate any SA in the project -- CIS GCP 1.6
// (separation of duties for SA management).
var CheckNoBroadTokenCreator = core.Check{
	ID:           "gcp-iam-no-broad-token-creator",
	Title:        "GCP project must not grant broad service-account impersonation",
	Severity:     core.SeverityHigh,
	Provider:     "gcp",
	Service:      "iam",
	ResourceType: gcpcol.IAMPolicyType,
	Description: "Project-level grants of roles/iam.serviceAccountTokenCreator " +
		"or roles/iam.serviceAccountUser let the holder mint short-lived " +
		"tokens for ANY service account in the project (or impersonate it " +
		"via gcloud --impersonate-service-account). Scoping these grants to " +
		"specific service-account resources (not the project) is the CIS " +
		"GCP 1.6 separation-of-duties baseline.",
	Remediation: "Replace project-level grants with per-SA grants: " +
		"'gcloud iam service-accounts add-iam-policy-binding <sa-email> " +
		"--member=<principal> --role=roles/iam.serviceAccountTokenCreator'. " +
		"Then remove the project-level binding via " +
		"'gcloud projects remove-iam-policy-binding ...'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"5.4", "6.7"},
	},
	Tags:    []string{"iam", "service-account", "impersonation"},
	Scanner: "iam.NoBroadTokenCreator",
}

var dangerousProjectRoles = map[string]bool{
	"roles/iam.serviceAccountTokenCreator": true,
	"roles/iam.serviceAccountUser":         true,
}

func NoBroadTokenCreator(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(gcpcol.IAMPolicyType) {
		bindings, _ := p.Attributes["bindings"].([]map[string]any)
		violators := map[string][]string{}
		for _, b := range bindings {
			role, _ := b["role"].(string)
			if !dangerousProjectRoles[role] {
				continue
			}
			members, _ := b["members"].([]string)
			if len(members) > 0 {
				violators[role] = members
			}
		}
		f := core.Finding{
			CheckID:  CheckNoBroadTokenCreator.ID,
			Severity: CheckNoBroadTokenCreator.Severity,
			Resource: p.Ref(),
			Tags:     CheckNoBroadTokenCreator.Tags,
		}
		if len(violators) == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("project %q: no project-level SA impersonation grants", p.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("project %q: project-level SA impersonation grants present (%s)",
				p.Name, summarizeBindings(violators))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckCloudAuditLogging requires audit log configuration for all
// services with ALL three log types (admin/read/write). CIS GCP 2.1.
var CheckCloudAuditLogging = core.Check{
	ID:           "gcp-iam-cloudaudit-logging",
	Title:        "GCP project audit logging must cover admin/read/write activity for allServices",
	Severity:     core.SeverityMedium,
	Provider:     "gcp",
	Service:      "iam",
	ResourceType: gcpcol.IAMPolicyType,
	Description: "Cloud Audit Logs are GCP's API-level change record. CIS " +
		"GCP Foundations 2.1 prescribes a project-level audit config for " +
		"'allServices' with ADMIN_READ, DATA_READ, DATA_WRITE all enabled. " +
		"Without it, post-incident forensics has only partial coverage of " +
		"who-did-what-when.",
	Remediation: "Add the audit config via Cloud Console (IAM & Admin -> " +
		"Audit Logs -> Default audit logs configuration) or set " +
		"auditConfigs in your Terraform / Deployment Manager templates: " +
		"`auditConfigs: [{ service: 'allServices', auditLogConfigs: " +
		"[{ logType: ADMIN_READ }, { logType: DATA_READ }, { logType: DATA_WRITE }] }]`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2", "CC7.3"},
		"iso27001": {"A.8.15", "A.8.16"},
		"cis-v8":   {"8.5", "8.10"},
	},
	Tags:    []string{"iam", "audit-logging"},
	Scanner: "iam.CloudAuditLogging",
}

var requiredLogTypes = []string{"ADMIN_READ", "DATA_READ", "DATA_WRITE"}

func CloudAuditLogging(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(gcpcol.IAMPolicyType) {
		configs, _ := p.Attributes["audit_configs"].([]map[string]any)
		var allServicesConfig map[string]any
		for _, ac := range configs {
			if svc, _ := ac["service"].(string); svc == "allServices" {
				allServicesConfig = ac
				break
			}
		}
		f := core.Finding{
			CheckID:  CheckCloudAuditLogging.ID,
			Severity: CheckCloudAuditLogging.Severity,
			Resource: p.Ref(),
			Tags:     CheckCloudAuditLogging.Tags,
		}
		if allServicesConfig == nil {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("project %q: no audit config for allServices", p.Name)
			findings = append(findings, f)
			continue
		}
		present := map[string]bool{}
		entries, _ := allServicesConfig["audit_log_configs"].([]map[string]any)
		for _, e := range entries {
			if t, _ := e["log_type"].(string); t != "" {
				present[t] = true
			}
		}
		missing := []string{}
		for _, t := range requiredLogTypes {
			if !present[t] {
				missing = append(missing, t)
			}
		}
		if len(missing) == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("project %q: audit log types ADMIN_READ/DATA_READ/DATA_WRITE all configured", p.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("project %q: audit config missing log types: %s",
				p.Name, strings.Join(missing, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ========================================================================
// Per-service-account checks
// ========================================================================

// saKeyMaxAge is the threshold for the SA-key-age check. CIS GCP 1.7.
const saKeyMaxAge = 90 * 24 * time.Hour

// CheckSAKeyAge requires user-managed SA keys to be rotated every
// 90 days. CIS GCP 1.7.
var CheckSAKeyAge = core.Check{
	ID:           "gcp-iam-sa-key-age",
	Title:        "GCP service-account user-managed keys must be rotated within 90 days",
	Severity:     core.SeverityHigh,
	Provider:     "gcp",
	Service:      "iam",
	ResourceType: gcpcol.ServiceAccountType,
	Description: "User-managed service-account keys are long-lived static " +
		"credentials -- the GCP equivalent of an AWS access key. CIS GCP " +
		"1.7 prescribes 90-day rotation to cap the exposure window of any " +
		"leaked key. (System-managed keys, which Google rotates " +
		"automatically, are out of scope for this check.)",
	Remediation: "Rotate via 'gcloud iam service-accounts keys create new-key.json " +
		"--iam-account=<sa-email>', deploy the new key everywhere it's " +
		"needed, then 'gcloud iam service-accounts keys delete <old-key-id>'. " +
		"Better: switch to Workload Identity Federation and remove the " +
		"need for long-lived keys altogether.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.2", "A.8.5"},
		"cis-v8":   {"5.4"},
	},
	Tags:    []string{"iam", "service-account", "credentials", "rotation"},
	Scanner: "iam.SAKeyAge",
}

func SAKeyAge(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	now := time.Now().UTC()
	for _, sa := range g.ByType(gcpcol.ServiceAccountType) {
		keys, _ := sa.Attributes["keys"].([]map[string]any)
		var oldest time.Duration
		violators := []string{}
		for _, k := range keys {
			if t, _ := k["key_type"].(string); t != "USER_MANAGED" {
				continue
			}
			created, _ := k["valid_after_time"].(time.Time)
			if created.IsZero() {
				continue
			}
			age := now.Sub(created)
			if age > oldest {
				oldest = age
			}
			if age > saKeyMaxAge {
				name, _ := k["name"].(string)
				violators = append(violators, fmt.Sprintf("%s (%d days)", lastPathSegment(name), int(age.Hours()/24)))
			}
		}
		f := core.Finding{
			CheckID:  CheckSAKeyAge.ID,
			Severity: CheckSAKeyAge.Severity,
			Resource: sa.Ref(),
			Tags:     CheckSAKeyAge.Tags,
		}
		switch {
		case oldest == 0:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("SA %q: no user-managed keys", sa.Name)
		case len(violators) == 0:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("SA %q: oldest user-managed key is %d days", sa.Name, int(oldest.Hours()/24))
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("SA %q: stale user-managed keys: %s", sa.Name, strings.Join(violators, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func lastPathSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// CheckNoUserManagedSAKeys forbids user-managed SA keys entirely.
// Workload Identity Federation + short-lived tokens replace the
// use case in nearly every modern setup; long-lived keys are the
// canonical credential-leak path. CIS GCP 1.4.
var CheckNoUserManagedSAKeys = core.Check{
	ID:           "gcp-iam-no-user-managed-sa-keys",
	Title:        "GCP service accounts should not have user-managed keys",
	Severity:     core.SeverityMedium,
	Provider:     "gcp",
	Service:      "iam",
	ResourceType: gcpcol.ServiceAccountType,
	Description: "User-managed service-account keys are the GCP analog " +
		"of long-lived AWS access keys -- the canonical credential-leak " +
		"path. Workload Identity Federation (for GitHub Actions, GitLab " +
		"CI, AWS-running workloads), GCE metadata server (for GCE VMs), " +
		"and GKE Workload Identity (for GKE pods) cover the legitimate " +
		"use cases with short-lived tokens. CIS GCP 1.4 prescribes no " +
		"user-managed keys.",
	Remediation: "Migrate to Workload Identity Federation: " +
		"https://cloud.google.com/iam/docs/workload-identity-federation . " +
		"Once the WIF provider + service-account binding is in place, " +
		"delete the user-managed keys: 'gcloud iam service-accounts keys " +
		"list --iam-account=<sa-email>' then 'gcloud iam service-accounts " +
		"keys delete <key-id> --iam-account=<sa-email>'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.5"},
		"cis-v8":   {"5.4"},
	},
	Tags:    []string{"iam", "service-account", "credentials"},
	Scanner: "iam.NoUserManagedSAKeys",
}

func NoUserManagedSAKeys(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, sa := range g.ByType(gcpcol.ServiceAccountType) {
		count, _ := sa.Attributes["user_managed_key_count"].(int)
		f := core.Finding{
			CheckID:  CheckNoUserManagedSAKeys.ID,
			Severity: CheckNoUserManagedSAKeys.Severity,
			Resource: sa.Ref(),
			Tags:     CheckNoUserManagedSAKeys.Tags,
		}
		if count == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("SA %q: no user-managed keys", sa.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("SA %q: %d user-managed key(s) present", sa.Name, count)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckNoDefaultSAInUse flags the default Compute / App Engine
// service accounts as a finding when they exist with broad project
// roles. CIS GCP 1.5 prescribes against using them; replacing them
// with purpose-built SAs is the correct fix.
var CheckNoDefaultSAInUse = core.Check{
	ID:           "gcp-iam-no-default-sa-in-use",
	Title:        "GCP default Compute / App Engine service accounts must not be used",
	Severity:     core.SeverityMedium,
	Provider:     "gcp",
	Service:      "iam",
	ResourceType: gcpcol.ServiceAccountType,
	Description: "The default Compute Engine service account " +
		"(<project-number>-compute@developer.gserviceaccount.com) and " +
		"App Engine default service account " +
		"(<project-id>@appspot.gserviceaccount.com) carry the Editor role " +
		"on the project by default, which is over-broad. Workloads " +
		"running as these SAs inherit those permissions. CIS GCP 1.5 " +
		"prescribes replacing them with purpose-built SAs scoped to the " +
		"actual job.",
	Remediation: "Create a purpose-built SA: 'gcloud iam service-accounts " +
		"create my-workload --display-name=\"My Workload\"', grant the " +
		"specific roles it needs, then redeploy the workload with " +
		"--service-account=my-workload@<project>.iam.gserviceaccount.com.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"5.4", "6.7"},
	},
	Tags:    []string{"iam", "service-account", "default-sa"},
	Scanner: "iam.NoDefaultSAInUse",
}

func NoDefaultSAInUse(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, sa := range g.ByType(gcpcol.ServiceAccountType) {
		isDefault, _ := sa.Attributes["is_default"].(bool)
		disabled, _ := sa.Attributes["disabled"].(bool)
		f := core.Finding{
			CheckID:  CheckNoDefaultSAInUse.ID,
			Severity: CheckNoDefaultSAInUse.Severity,
			Resource: sa.Ref(),
			Tags:     CheckNoDefaultSAInUse.Tags,
		}
		switch {
		case !isDefault:
			// Purpose-built SAs pass by definition.
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("SA %q: purpose-built (not a default)", sa.Name)
		case disabled:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("SA %q: default but disabled (skip)", sa.Name)
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("SA %q: default GCP service account is active (replace with a purpose-built SA)", sa.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckNoPrimitiveRoles, NoPrimitiveRoles)
	core.Register(CheckNoBroadTokenCreator, NoBroadTokenCreator)
	core.Register(CheckCloudAuditLogging, CloudAuditLogging)
	core.Register(CheckSAKeyAge, SAKeyAge)
	core.Register(CheckNoUserManagedSAKeys, NoUserManagedSAKeys)
	core.Register(CheckNoDefaultSAInUse, NoDefaultSAInUse)
}
