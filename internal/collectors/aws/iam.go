package aws

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// IAMUserType is the resource type for per-user IAM resources.
// Account-level IAM facts (root key, root MFA, password policy) go
// onto the singleton aws.account resource so account-level checks
// have a single anchor to read from.
const IAMUserType = "aws.iam.user"

// iamClient is the subset of *iam.Client we use. Defining an
// interface keeps the unit tests free of any real-SDK dependency.
type iamClient interface {
	GetAccountSummary(ctx context.Context, in *iam.GetAccountSummaryInput, opts ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
	GetAccountPasswordPolicy(ctx context.Context, in *iam.GetAccountPasswordPolicyInput, opts ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
	ListUsers(ctx context.Context, in *iam.ListUsersInput, opts ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListAccessKeys(ctx context.Context, in *iam.ListAccessKeysInput, opts ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	GetLoginProfile(ctx context.Context, in *iam.GetLoginProfileInput, opts ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error)
	ListMFADevices(ctx context.Context, in *iam.ListMFADevicesInput, opts ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
	ListAttachedUserPolicies(ctx context.Context, in *iam.ListAttachedUserPoliciesInput, opts ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListUserPolicies(ctx context.Context, in *iam.ListUserPoliciesInput, opts ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	GetUserPolicy(ctx context.Context, in *iam.GetUserPolicyInput, opts ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error)
}

// collectIAM fetches IAM data and (a) enriches the singleton
// aws.account resource with account-level facts and (b) emits one
// aws.iam.user resource per IAM user. account is passed by pointer
// because the caller already owns the singleton from phase 1's
// accountResource() builder.
//
// Errors from the per-user calls do not abort the whole IAM
// collection -- a user we can't fully introspect produces a partial
// resource (the checks treat missing fields as "unknown"). Errors
// from the account-summary / password-policy calls DO abort because
// without them the account-level checks have no input.
func (c *Collector) collectIAM(ctx context.Context, account *compliancekit.Resource, out []compliancekit.Resource) ([]compliancekit.Resource, error) {
	return c.collectIAMWithClient(ctx, iam.NewFromConfig(c.cfg), account, out)
}

func (c *Collector) collectIAMWithClient(ctx context.Context, client iamClient, account *compliancekit.Resource, out []compliancekit.Resource) ([]compliancekit.Resource, error) {
	if err := c.enrichAccountWithIAM(ctx, client, account); err != nil {
		return nil, err
	}
	return c.collectIAMUsers(ctx, client, out)
}

// enrichAccountWithIAM writes IAM account-level facts onto the
// singleton aws.account resource. Three facts:
//
//   - root_has_access_keys (bool, from AccountSummary)
//   - root_mfa_enabled     (bool, from AccountSummary)
//   - password_policy      (map of the GetAccountPasswordPolicy
//     fields the v0.7 password-policy check
//     reads; nil if no policy is set on the
//     account)
func (c *Collector) enrichAccountWithIAM(ctx context.Context, client iamClient, account *compliancekit.Resource) error {
	sum, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return fmt.Errorf("aws: iam.GetAccountSummary: %w", err)
	}
	// AccountSummary's SummaryMap values are int32 -- 1 means present,
	// 0 means absent for the boolean-ish keys.
	if account.Attributes == nil {
		account.Attributes = map[string]any{}
	}
	account.Attributes["root_has_access_keys"] = sum.SummaryMap["AccountAccessKeysPresent"] == 1
	account.Attributes["root_mfa_enabled"] = sum.SummaryMap["AccountMFAEnabled"] == 1
	account.Attributes["account_signing_certificates_present"] = sum.SummaryMap["AccountSigningCertificatesPresent"] == 1

	policy, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		// NoSuchEntity means the account has no policy at all --
		// a finding in its own right, not an error.
		if isAWSError(err, "NoSuchEntity") {
			account.Attributes["password_policy"] = nil
			return nil
		}
		return fmt.Errorf("aws: iam.GetAccountPasswordPolicy: %w", err)
	}
	if policy.PasswordPolicy != nil {
		account.Attributes["password_policy"] = passwordPolicyMap(*policy.PasswordPolicy)
	}
	return nil
}

// passwordPolicyMap projects iamtypes.PasswordPolicy onto a
// map[string]any so the check code can read fields without
// pulling iamtypes into the checks package.
func passwordPolicyMap(p iamtypes.PasswordPolicy) map[string]any {
	out := map[string]any{
		"minimum_password_length":        int(awssdk.ToInt32(p.MinimumPasswordLength)),
		"require_symbols":                p.RequireSymbols,
		"require_numbers":                p.RequireNumbers,
		"require_uppercase_characters":   p.RequireUppercaseCharacters,
		"require_lowercase_characters":   p.RequireLowercaseCharacters,
		"allow_users_to_change_password": p.AllowUsersToChangePassword,
		"expire_passwords":               p.ExpirePasswords,
		"max_password_age":               int(awssdk.ToInt32(p.MaxPasswordAge)),
		"password_reuse_prevention":      int(awssdk.ToInt32(p.PasswordReusePrevention)),
		"hard_expiry":                    awssdk.ToBool(p.HardExpiry),
	}
	return out
}

// collectIAMUsers emits one aws.iam.user resource per user. Each
// resource carries access keys, console-access info, MFA status,
// attached managed policies, and inline policies inline so the
// per-check code reads from a single struct.
func (c *Collector) collectIAMUsers(ctx context.Context, client iamClient, out []compliancekit.Resource) ([]compliancekit.Resource, error) {
	users, err := listAllUsers(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("aws: iam.ListUsers: %w", err)
	}
	for _, u := range users {
		r, err := c.buildIAMUserResource(ctx, client, u)
		if err != nil {
			// Per-user error: emit a partial resource rather than
			// aborting the whole IAM collection. The checks treat
			// missing fields as "unknown".
			r.Attributes["collect_error"] = err.Error()
		}
		out = append(out, r)
	}
	return out, nil
}

func listAllUsers(ctx context.Context, client iamClient) ([]iamtypes.User, error) {
	var out []iamtypes.User
	var marker *string
	for {
		page, err := client.ListUsers(ctx, &iam.ListUsersInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Users...)
		if !page.IsTruncated {
			break
		}
		marker = page.Marker
	}
	return out, nil
}

func (c *Collector) buildIAMUserResource(ctx context.Context, client iamClient, u iamtypes.User) (compliancekit.Resource, error) {
	userName := awssdk.ToString(u.UserName)
	arn := awssdk.ToString(u.Arn)
	r := compliancekit.Resource{
		ID:       fmt.Sprintf("aws.iam.user.%s", url.PathEscape(arn)),
		Type:     IAMUserType,
		Name:     userName,
		Provider: providerName,
		Attributes: map[string]any{
			"user_name":           userName,
			"arn":                 arn,
			"created_at":          awssdk.ToTime(u.CreateDate),
			"password_last_used":  awssdk.ToTime(u.PasswordLastUsed),
			"has_console_access":  false,
			"console_mfa_enabled": false,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: c.accountID,
		// IAM users are region-agnostic.
	})

	// Access keys.
	keys, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: u.UserName})
	if err != nil {
		return r, fmt.Errorf("list access keys: %w", err)
	}
	accessKeys := []map[string]any{}
	for _, k := range keys.AccessKeyMetadata {
		entry := map[string]any{
			"access_key_id": awssdk.ToString(k.AccessKeyId),
			"status":        string(k.Status),
			"created_at":    awssdk.ToTime(k.CreateDate),
		}
		accessKeys = append(accessKeys, entry)
	}
	r.Attributes["access_keys"] = accessKeys

	// Login profile (console access).
	if _, err := client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{UserName: u.UserName}); err == nil {
		r.Attributes["has_console_access"] = true
	} else if !isAWSError(err, "NoSuchEntity") {
		return r, fmt.Errorf("get login profile: %w", err)
	}

	// MFA devices.
	mfa, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: u.UserName})
	if err != nil {
		return r, fmt.Errorf("list mfa devices: %w", err)
	}
	r.Attributes["console_mfa_enabled"] = len(mfa.MFADevices) > 0

	// Attached managed policies.
	attached, err := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: u.UserName})
	if err != nil {
		return r, fmt.Errorf("list attached user policies: %w", err)
	}
	attachedARNs := []string{}
	for _, p := range attached.AttachedPolicies {
		attachedARNs = append(attachedARNs, awssdk.ToString(p.PolicyArn))
	}
	r.Attributes["attached_managed_policies"] = attachedARNs

	// Inline policies (names + documents).
	inlineNames, err := client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: u.UserName})
	if err != nil {
		return r, fmt.Errorf("list inline user policies: %w", err)
	}
	inlinePolicies := []map[string]any{}
	for _, name := range inlineNames.PolicyNames {
		doc, err := client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
			UserName:   u.UserName,
			PolicyName: awssdk.String(name),
		})
		if err != nil {
			return r, fmt.Errorf("get user policy %q: %w", name, err)
		}
		inlinePolicies = append(inlinePolicies, map[string]any{
			"name":     name,
			"document": awssdk.ToString(doc.PolicyDocument),
		})
	}
	r.Attributes["inline_policies"] = inlinePolicies

	return r, nil
}

// isAWSError reports whether err is an SDK API error with the given
// short code (e.g. "NoSuchEntity"). Used to distinguish "the resource
// doesn't exist" (a finding) from "the call failed" (a collect error).
func isAWSError(err error, code string) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == code
	}
	// Some older SDK error paths wrap differently; try string match
	// as a fallback. Cheap, occasionally noisy.
	return strings.Contains(err.Error(), code)
}

// unused now; placeholder for the per-user "last activity" lookup
// the unused-users check might want at a finer grain than
// PasswordLastUsed alone.
var _ = time.Time{}
