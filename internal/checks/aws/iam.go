// Package aws holds the AWS check implementations.
//
// Each check is a compliancekit.Check metadata value plus a compliancekit.CheckFunc
// that queries the ResourceGraph (which the AWS collector populated)
// and emits Findings.
//
// Per ARCHITECTURE.md and DECISIONS.md ADR-007, v0.7 ships the 30
// highest-leverage checks across IAM / EC2 / S3 / RDS / CloudTrail /
// KMS / Config / GuardDuty. The CIS AWS Foundations Benchmark v3.0
// is the source of truth for the CIS mappings.
package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// ========================================================================
// Account-level checks (anchored on the aws.account singleton)
// ========================================================================

// CheckRootAccessKey requires the AWS root account to have NO access
// keys. CIS AWS Foundations Benchmark 1.4. Critical: a leaked root
// key compromises everything below it.
var CheckRootAccessKey = compliancekit.Check{
	ID:           "aws-iam-root-access-key",
	Title:        "AWS root account must have no access keys",
	Severity:     compliancekit.SeverityCritical,
	Provider:     "aws",
	Service:      "iam",
	ResourceType: awscol.AccountType,
	Description: "The AWS root account has un-revokable permissions across " +
		"every service. Access keys for root cannot be scoped, cannot be " +
		"rotated to a least-privilege subset, and leak the entire account " +
		"on disclosure. CIS AWS Foundations Benchmark 1.4 prescribes that " +
		"no access keys exist for root.",
	Remediation: "Sign in as root, navigate to IAM -> My security credentials -> " +
		"Access keys, and delete every key. Use IAM users + roles for any " +
		"programmatic access instead.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.2", "A.8.5"},
		"cis-v8":   {"5.4", "6.5"},
	},
	Tags:    []string{"iam", "root", "credentials"},
	Scanner: "iam.RootAccessKey",
}

func RootAccessKey(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, acct := range g.ByType(awscol.AccountType) {
		present, _ := acct.Attributes["root_has_access_keys"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckRootAccessKey.ID,
			Severity: CheckRootAccessKey.Severity,
			Resource: acct.Ref(),
			Tags:     CheckRootAccessKey.Tags,
		}
		if present {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("account %q: root access keys present", acct.Name)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("account %q: no root access keys", acct.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckRootMFA requires MFA on the root account. CIS 1.5. High.
var CheckRootMFA = compliancekit.Check{
	ID:           "aws-iam-root-mfa",
	Title:        "AWS root account must have MFA enabled",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "aws",
	Service:      "iam",
	ResourceType: awscol.AccountType,
	Description: "MFA on the root account is the single most effective " +
		"control against root-account takeover. Without MFA, root reduces " +
		"to a password the attacker only needs to phish once. CIS AWS " +
		"Foundations Benchmark 1.5.",
	Remediation: "Sign in as root, navigate to IAM -> My security credentials " +
		"-> Multi-factor authentication, and activate a virtual or hardware " +
		"MFA device. Prefer a hardware key (YubiKey) for production accounts.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.5"},
		"cis-v8":   {"6.3", "6.5"},
	},
	Tags:    []string{"iam", "root", "mfa"},
	Scanner: "iam.RootMFA",
}

func RootMFA(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, acct := range g.ByType(awscol.AccountType) {
		enabled, _ := acct.Attributes["root_mfa_enabled"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckRootMFA.ID,
			Severity: CheckRootMFA.Severity,
			Resource: acct.Ref(),
			Tags:     CheckRootMFA.Tags,
		}
		if enabled {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("account %q: root MFA enabled", acct.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("account %q: root MFA not enabled", acct.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckPasswordPolicy requires a password policy that meets CIS
// thresholds (length >= 14, requires all character classes, etc.).
// CIS 1.8.
var CheckPasswordPolicy = compliancekit.Check{
	ID:           "aws-iam-password-policy",
	Title:        "AWS account must enforce a strong password policy",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "aws",
	Service:      "iam",
	ResourceType: awscol.AccountType,
	Description: "A strong password policy raises the cost of brute-force " +
		"and credential-stuffing attacks. The AWS account password policy " +
		"applies to IAM users with console access. CIS AWS Foundations " +
		"Benchmark 1.8 prescribes minimum length 14, requires lowercase / " +
		"uppercase / numbers / symbols, reuse prevention >= 24, max age " +
		"<= 90 days.",
	Remediation: "Sign in to IAM, navigate to Account settings -> Password " +
		"policy, and set: minimum length 14, require all character classes, " +
		"prevent reuse of last 24, expire after 90 days, allow users to " +
		"change own password.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.5"},
		"cis-v8":   {"5.2", "6.3"},
	},
	Tags:    []string{"iam", "password-policy"},
	Scanner: "iam.PasswordPolicy",
}

func PasswordPolicy(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, acct := range g.ByType(awscol.AccountType) {
		raw, present := acct.Attributes["password_policy"]
		f := compliancekit.Finding{
			CheckID:  CheckPasswordPolicy.ID,
			Severity: CheckPasswordPolicy.Severity,
			Resource: acct.Ref(),
			Tags:     CheckPasswordPolicy.Tags,
		}
		if !present || raw == nil {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("account %q: no password policy configured", acct.Name)
			findings = append(findings, f)
			continue
		}
		policy, ok := raw.(map[string]any)
		if !ok {
			f.Status = compliancekit.StatusError
			f.Message = fmt.Sprintf("account %q: password_policy attribute has unexpected shape", acct.Name)
			findings = append(findings, f)
			continue
		}
		failures := evaluatePasswordPolicy(policy)
		if len(failures) == 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("account %q: password policy meets CIS thresholds", acct.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("account %q: password policy weak: %s",
				acct.Name, strings.Join(failures, "; "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// evaluatePasswordPolicy returns the list of CIS thresholds the
// policy fails to meet. Empty result = compliant.
func evaluatePasswordPolicy(p map[string]any) []string {
	out := []string{}
	if n, _ := p["minimum_password_length"].(int); n < 14 {
		out = append(out, fmt.Sprintf("minimum_password_length=%d (want >= 14)", n))
	}
	for _, key := range []string{
		"require_symbols", "require_numbers",
		"require_uppercase_characters", "require_lowercase_characters",
	} {
		if b, _ := p[key].(bool); !b {
			out = append(out, fmt.Sprintf("%s=false (want true)", key))
		}
	}
	if expire, _ := p["expire_passwords"].(bool); !expire {
		out = append(out, "expire_passwords=false (want true)")
	} else if age, _ := p["max_password_age"].(int); age == 0 || age > 90 {
		out = append(out, fmt.Sprintf("max_password_age=%d (want > 0 and <= 90)", age))
	}
	if reuse, _ := p["password_reuse_prevention"].(int); reuse < 24 {
		out = append(out, fmt.Sprintf("password_reuse_prevention=%d (want >= 24)", reuse))
	}
	return out
}

// ========================================================================
// Per-user checks (anchored on aws.iam.user resources)
// ========================================================================

// accessKeyMaxAge is the threshold for the access-key-age check.
// CIS 1.14 prescribes 90 days.
const accessKeyMaxAge = 90 * 24 * time.Hour

// CheckAccessKeyAge requires every IAM user's active access keys to
// be younger than accessKeyMaxAge. CIS 1.14. High.
var CheckAccessKeyAge = compliancekit.Check{
	ID:           "aws-iam-access-key-age",
	Title:        "IAM user access keys must be rotated within 90 days",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "aws",
	Service:      "iam",
	ResourceType: awscol.IAMUserType,
	Description: "Long-lived access keys are the source of the majority of " +
		"AWS breaches in the public record. Rotating them every 90 days " +
		"limits the blast radius of an undetected disclosure. CIS AWS " +
		"Foundations Benchmark 1.14.",
	Remediation: "Run 'aws iam list-access-keys --user-name <name>' to find " +
		"the key, create a replacement, deploy it everywhere, then deactivate " +
		"the old key (aws iam update-access-key --status Inactive) before " +
		"deleting it. Consider rotating to short-lived STS credentials via " +
		"role assumption instead of long-lived keys.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.2", "A.8.5"},
		"cis-v8":   {"5.4"},
	},
	Tags:    []string{"iam", "credentials", "rotation"},
	Scanner: "iam.AccessKeyAge",
}

func AccessKeyAge(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	now := time.Now().UTC()
	for _, u := range g.ByType(awscol.IAMUserType) {
		keys, _ := u.Attributes["access_keys"].([]map[string]any)
		oldest := time.Duration(0)
		violators := []string{}
		for _, k := range keys {
			status, _ := k["status"].(string)
			if status != "Active" {
				continue
			}
			created, _ := k["created_at"].(time.Time)
			if created.IsZero() {
				continue
			}
			age := now.Sub(created)
			if age > oldest {
				oldest = age
			}
			if age > accessKeyMaxAge {
				violators = append(violators, fmt.Sprintf("%s (%d days)",
					k["access_key_id"], int(age.Hours()/24)))
			}
		}
		f := compliancekit.Finding{
			CheckID:  CheckAccessKeyAge.ID,
			Severity: CheckAccessKeyAge.Severity,
			Resource: u.Ref(),
			Tags:     CheckAccessKeyAge.Tags,
		}
		switch {
		case oldest == 0:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("user %q: no active access keys", u.Name)
		case len(violators) == 0:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("user %q: oldest active key is %d days old",
				u.Name, int(oldest.Hours()/24))
		default:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("user %q: stale access keys: %s",
				u.Name, strings.Join(violators, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// unusedUserThreshold is the inactivity threshold for the
// unused-users check. CIS 1.13 prescribes 90 days.
const unusedUserThreshold = 90 * 24 * time.Hour

// CheckUnusedUsers flags IAM users with no console activity for 90+ days.
var CheckUnusedUsers = compliancekit.Check{
	ID:           "aws-iam-unused-users",
	Title:        "IAM users inactive for 90 days must be removed",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "aws",
	Service:      "iam",
	ResourceType: awscol.IAMUserType,
	Description: "Dormant IAM users are an attack surface with no business " +
		"benefit. CIS AWS Foundations Benchmark 1.13 prescribes removing " +
		"users with no activity for 90 days. Consider quarterly access " +
		"reviews to flag candidates for removal.",
	Remediation: "Confirm with the user's manager that the account is no " +
		"longer needed, then delete it: " +
		"'aws iam delete-user --user-name <name>' after deleting access " +
		"keys, MFA devices, and policies attached to that user.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.16", "A.8.2"},
		"cis-v8":   {"5.3", "6.2"},
	},
	Tags:    []string{"iam", "lifecycle", "least-privilege"},
	Scanner: "iam.UnusedUsers",
}

func UnusedUsers(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	now := time.Now().UTC()
	for _, u := range g.ByType(awscol.IAMUserType) {
		f := compliancekit.Finding{
			CheckID:  CheckUnusedUsers.ID,
			Severity: CheckUnusedUsers.Severity,
			Resource: u.Ref(),
			Tags:     CheckUnusedUsers.Tags,
		}
		lastSeen := mostRecentActivity(u, now)
		if lastSeen.IsZero() {
			// Never used. If the user is younger than the threshold,
			// pass (still in onboarding window); otherwise fail.
			created, _ := u.Attributes["created_at"].(time.Time)
			if now.Sub(created) <= unusedUserThreshold {
				f.Status = compliancekit.StatusPass
				f.Message = fmt.Sprintf("user %q: new (no activity yet, within onboarding window)", u.Name)
			} else {
				f.Status = compliancekit.StatusFail
				f.Message = fmt.Sprintf("user %q: never used since creation %d days ago",
					u.Name, int(now.Sub(created).Hours()/24))
			}
			findings = append(findings, f)
			continue
		}
		idle := now.Sub(lastSeen)
		if idle > unusedUserThreshold {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("user %q: idle for %d days", u.Name, int(idle.Hours()/24))
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("user %q: active within last %d days", u.Name, int(idle.Hours()/24))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// mostRecentActivity returns the most recent of: password last used,
// any active access key creation timestamp. The credential report
// has finer-grained per-key last-used, but our collector doesn't
// fetch that yet -- creation date is a conservative proxy.
func mostRecentActivity(u compliancekit.Resource, now time.Time) time.Time {
	out := time.Time{}
	if t, _ := u.Attributes["password_last_used"].(time.Time); !t.IsZero() {
		out = t
	}
	keys, _ := u.Attributes["access_keys"].([]map[string]any)
	for _, k := range keys {
		if status, _ := k["status"].(string); status != "Active" {
			continue
		}
		if t, _ := k["created_at"].(time.Time); !t.IsZero() && t.After(out) {
			out = t
		}
	}
	// Ignore future timestamps (clock skew); treat them as "now."
	if out.After(now) {
		out = now
	}
	return out
}

// CheckNoUserManagedPolicies enforces "policies attach to groups
// and roles, not users." Direct user-attached policies are an
// audit nightmare because permissions scatter across user accounts
// instead of consolidating in groups/roles. CIS 1.16.
var CheckNoUserManagedPolicies = compliancekit.Check{
	ID:           "aws-iam-no-user-managed-policies",
	Title:        "IAM policies must attach to groups or roles, not users",
	Severity:     compliancekit.SeverityLow,
	Provider:     "aws",
	Service:      "iam",
	ResourceType: awscol.IAMUserType,
	Description: "Attaching managed policies directly to IAM users scatters " +
		"permission management across user accounts; group / role attachments " +
		"consolidate it. CIS AWS Foundations Benchmark 1.16 prescribes no " +
		"direct user-managed-policy attachments. (Inline policies on users " +
		"are covered by a separate check.)",
	Remediation: "Move the policy to an IAM group: " +
		"'aws iam create-group --group-name <name>', " +
		"'aws iam attach-group-policy', then " +
		"'aws iam add-user-to-group --user-name <user> --group-name <group>', " +
		"finally 'aws iam detach-user-policy --user-name <user> --policy-arn <arn>'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"5.4", "6.7"},
	},
	Tags:    []string{"iam", "least-privilege", "governance"},
	Scanner: "iam.NoUserManagedPolicies",
}

func NoUserManagedPolicies(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, u := range g.ByType(awscol.IAMUserType) {
		attached, _ := u.Attributes["attached_managed_policies"].([]string)
		f := compliancekit.Finding{
			CheckID:  CheckNoUserManagedPolicies.ID,
			Severity: CheckNoUserManagedPolicies.Severity,
			Resource: u.Ref(),
			Tags:     CheckNoUserManagedPolicies.Tags,
		}
		if len(attached) == 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("user %q: no managed policies attached directly", u.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("user %q: %d managed policies attached directly: %s",
				u.Name, len(attached), strings.Join(shortenARNs(attached), ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// shortenARNs trims policy ARNs to the trailing policy name for
// readability in finding messages. "arn:aws:iam::aws:policy/AdministratorAccess"
// -> "AdministratorAccess".
func shortenARNs(arns []string) []string {
	out := make([]string, len(arns))
	for i, a := range arns {
		if idx := strings.LastIndex(a, "/"); idx >= 0 {
			out[i] = a[idx+1:]
		} else {
			out[i] = a
		}
	}
	return out
}

func init() {
	compliancekit.Register(CheckRootAccessKey, RootAccessKey)
	compliancekit.Register(CheckRootMFA, RootMFA)
	compliancekit.Register(CheckPasswordPolicy, PasswordPolicy)
	compliancekit.Register(CheckAccessKeyAge, AccessKeyAge)
	compliancekit.Register(CheckUnusedUsers, UnusedUsers)
	compliancekit.Register(CheckNoUserManagedPolicies, NoUserManagedPolicies)
	// v0.22 phase 4 — ConsoleUserMFA + NoStarInlinePolicies moved to
	// iam_policies.go.
}
