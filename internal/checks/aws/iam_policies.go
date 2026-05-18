package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.22 phase 4 — User-policy hygiene IAM checks split out of iam.go.

var CheckConsoleUserMFA = compliancekit.Check{
	ID:           "aws-iam-console-user-mfa",
	Title:        "IAM users with console access must have MFA enabled",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "aws",
	Service:      "iam",
	ResourceType: awscol.IAMUserType,
	Description: "Console-enabled IAM users without MFA are the most common " +
		"AWS breach vector after leaked access keys. The password reduces " +
		"to a single factor an attacker only needs to phish once. CIS AWS " +
		"Foundations Benchmark 1.10.",
	Remediation: "Have the user sign in and enable MFA at IAM -> Users -> " +
		"Security credentials -> Multi-factor authentication. Enforce " +
		"organisationally via an IAM policy with 'aws:MultiFactorAuthPresent: " +
		"true' on the actions that matter.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.5"},
		"cis-v8":   {"6.3", "6.5"},
	},
	Tags:    []string{"iam", "mfa", "console"},
	Scanner: "iam.ConsoleUserMFA",
}

func ConsoleUserMFA(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, u := range g.ByType(awscol.IAMUserType) {
		console, _ := u.Attributes["has_console_access"].(bool)
		mfa, _ := u.Attributes["console_mfa_enabled"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckConsoleUserMFA.ID,
			Severity: CheckConsoleUserMFA.Severity,
			Resource: u.Ref(),
			Tags:     CheckConsoleUserMFA.Tags,
		}
		switch {
		case !console:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("user %q: no console access (skip)", u.Name)
		case mfa:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("user %q: console access + MFA enabled", u.Name)
		default:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("user %q: console access without MFA", u.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckNoStarInlinePolicies forbids inline policies that grant
// `*:*` (full administrative privilege). Inline policies on
// individual users are an audit nightmare; ones that grant blanket
// access make the user equivalent to root.
var CheckNoStarInlinePolicies = compliancekit.Check{
	ID:           "aws-iam-no-star-inline-policies",
	Title:        "IAM inline policies must not grant `*:*` permissions",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "aws",
	Service:      "iam",
	ResourceType: awscol.IAMUserType,
	Description: "An inline policy with Action='*' and Resource='*' grants " +
		"the user the equivalent of root on the account. Such policies are " +
		"a common shortcut during incident response that gets forgotten. " +
		"CIS AWS Foundations Benchmark 1.17 (full-administrative privileges).",
	Remediation: "Replace the inline policy with a least-privilege managed " +
		"policy and attach it via group/role: " +
		"'aws iam delete-user-policy --user-name <user> --policy-name <name>', " +
		"then create a scoped policy with only the actions the user actually " +
		"needs.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"5.4", "6.7"},
	},
	Tags:    []string{"iam", "least-privilege", "audit-risk"},
	Scanner: "iam.NoStarInlinePolicies",
}

func NoStarInlinePolicies(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, u := range g.ByType(awscol.IAMUserType) {
		inline, _ := u.Attributes["inline_policies"].([]map[string]any)
		violators := []string{}
		for _, p := range inline {
			doc, _ := p["document"].(string)
			if doc == "" {
				continue
			}
			if hasStarStar(doc) {
				name, _ := p["name"].(string)
				violators = append(violators, name)
			}
		}
		f := compliancekit.Finding{
			CheckID:  CheckNoStarInlinePolicies.ID,
			Severity: CheckNoStarInlinePolicies.Severity,
			Resource: u.Ref(),
			Tags:     CheckNoStarInlinePolicies.Tags,
		}
		if len(violators) == 0 {
			f.Status = compliancekit.StatusPass
			if len(inline) == 0 {
				f.Message = fmt.Sprintf("user %q: no inline policies", u.Name)
			} else {
				f.Message = fmt.Sprintf("user %q: %d inline policies, none with *:*", u.Name, len(inline))
			}
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("user %q: inline policies with *:*: %s",
				u.Name, strings.Join(violators, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// hasStarStar decodes a JSON-encoded IAM policy document and reports
// whether any Statement has Effect=Allow + Action='*' + Resource='*'.
// Tolerant of the SDK's quirky encoding (URL-escaped doc bodies)
// and of single-string-vs-array shapes for Action / Resource.
func hasStarStar(doc string) bool {
	// IAM policy documents are URL-escaped JSON when fetched via
	// GetUserPolicy. Decode if needed.
	if decoded, err := url.QueryUnescape(doc); err == nil && strings.Contains(decoded, "Statement") {
		doc = decoded
	}
	var parsed struct {
		Statement []struct {
			Effect   string
			Action   any
			Resource any
		}
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return false
	}
	for _, s := range parsed.Statement {
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		if matchesStar(s.Action) && matchesStar(s.Resource) {
			return true
		}
	}
	return false
}

func matchesStar(v any) bool {
	switch x := v.(type) {
	case string:
		return x == "*"
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok && s == "*" {
				return true
			}
		}
	}
	return false
}
func init() {
	compliancekit.Register(CheckConsoleUserMFA, ConsoleUserMFA)
	compliancekit.Register(CheckNoStarInlinePolicies, NoStarInlinePolicies)
}
