package gcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	iamadmin "cloud.google.com/go/iam/admin/apiv1"
	iamadminpb "cloud.google.com/go/iam/admin/apiv1/adminpb"
	iampb "cloud.google.com/go/iam/apiv1/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

const (
	// IAMPolicyType is the resource type emitted per project for
	// the project-level IAM policy.
	IAMPolicyType = "gcp.iam.policy"

	// ServiceAccountType is the resource type emitted for each
	// IAM service account in a project.
	ServiceAccountType = "gcp.iam.service_account"
)

// clientOption returns the option.ClientOption used by every GCP
// service client so they share the loaded credentials.
func (c *Collector) clientOption() option.ClientOption {
	return option.WithCredentials(c.creds)
}

// collectIAM enumerates the IAM policy and service accounts for
// each project. Emits one gcp.iam.policy resource per project and
// one gcp.iam.service_account per SA.
//
// Errors from GetIamPolicy or ListServiceAccounts abort that
// project's IAM collection but not the entire scan; the caller
// emits a per-project error placeholder and continues. Per-SA
// key-listing errors land as a collect_error_keys attribute on the
// SA resource.
func (c *Collector) collectIAM(ctx context.Context, out []compliancekit.Resource) []compliancekit.Resource {
	for _, projectID := range c.projects {
		updated, err := c.collectIAMForProject(ctx, projectID, out)
		if err != nil {
			out = append(out, c.projectErrorResource(projectID, "iam", err))
			continue
		}
		out = updated
	}
	return out
}

func (c *Collector) collectIAMForProject(ctx context.Context, projectID string, out []compliancekit.Resource) ([]compliancekit.Resource, error) {
	projClient, err := resourcemanager.NewProjectsClient(ctx, c.clientOption())
	if err != nil {
		return out, fmt.Errorf("new projects client: %w", err)
	}
	defer func() { _ = projClient.Close() }()

	policy, err := projClient.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
		Resource: fmt.Sprintf("projects/%s", projectID),
	})
	if err != nil {
		return out, fmt.Errorf("get iam policy: %w", err)
	}
	out = append(out, c.iamPolicyResource(projectID, policy))

	adminClient, err := iamadmin.NewIamClient(ctx, c.clientOption())
	if err != nil {
		return out, fmt.Errorf("new iam admin client: %w", err)
	}
	defer func() { _ = adminClient.Close() }()

	it := adminClient.ListServiceAccounts(ctx, &iamadminpb.ListServiceAccountsRequest{
		Name: fmt.Sprintf("projects/%s", projectID),
	})
	for {
		sa, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return out, fmt.Errorf("list service accounts: %w", err)
		}
		out = append(out, c.serviceAccountResource(ctx, adminClient, projectID, sa))
	}
	return out, nil
}

// iamPolicyResource projects the IAM Policy onto a compliancekit.Resource.
// Bindings + audit configs land as map slices so check code reads
// them without importing iampb.
func (c *Collector) iamPolicyResource(projectID string, policy *iampb.Policy) compliancekit.Resource {
	bindings := []map[string]any{}
	for _, b := range policy.Bindings {
		bindings = append(bindings, map[string]any{
			"role":    b.Role,
			"members": append([]string(nil), b.Members...),
		})
	}
	auditConfigs := []map[string]any{}
	for _, ac := range policy.AuditConfigs {
		entries := []map[string]any{}
		for _, alc := range ac.AuditLogConfigs {
			entries = append(entries, map[string]any{
				"log_type":         alc.LogType.String(),
				"exempted_members": append([]string(nil), alc.ExemptedMembers...),
			})
		}
		auditConfigs = append(auditConfigs, map[string]any{
			"service":           ac.Service,
			"audit_log_configs": entries,
		})
	}
	r := compliancekit.Resource{
		ID:       fmt.Sprintf("gcp.iam.policy.%s", projectID),
		Type:     IAMPolicyType,
		Name:     projectID,
		Provider: providerName,
		Attributes: map[string]any{
			"project_id":    projectID,
			"bindings":      bindings,
			"audit_configs": auditConfigs,
			"binding_count": len(bindings),
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: projectID})
	return r
}

func (c *Collector) serviceAccountResource(ctx context.Context, client *iamadmin.IamClient, projectID string, sa *iamadminpb.ServiceAccount) compliancekit.Resource {
	email := sa.Email
	r := compliancekit.Resource{
		ID:       fmt.Sprintf("gcp.iam.service_account.%s", email),
		Type:     ServiceAccountType,
		Name:     email,
		Provider: providerName,
		Attributes: map[string]any{
			"email":        email,
			"display_name": sa.DisplayName,
			"unique_id":    sa.UniqueId,
			"disabled":     sa.Disabled,
			"is_default":   isDefaultSA(email),
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: projectID})

	keysResp, err := client.ListServiceAccountKeys(ctx, &iamadminpb.ListServiceAccountKeysRequest{
		Name: sa.Name,
	})
	if err != nil {
		r.Attributes["collect_error_keys"] = err.Error()
		r.Attributes["keys"] = []map[string]any{}
		return r
	}
	keys := []map[string]any{}
	userManaged := 0
	for _, k := range keysResp.Keys {
		entry := map[string]any{
			"name":              k.Name,
			"key_type":          k.KeyType.String(),
			"key_algorithm":     k.KeyAlgorithm.String(),
			"valid_after_time":  pbTime(k.ValidAfterTime),
			"valid_before_time": pbTime(k.ValidBeforeTime),
		}
		keys = append(keys, entry)
		if k.KeyType == iamadminpb.ListServiceAccountKeysRequest_USER_MANAGED {
			userManaged++
		}
	}
	r.Attributes["keys"] = keys
	r.Attributes["user_managed_key_count"] = userManaged
	return r
}

// isDefaultSA recognizes the two GCP default service accounts that
// CIS GCP 1.5 flags: the Compute Engine default
// (<project-number>-compute@developer.gserviceaccount.com) and
// the App Engine default (<project-id>@appspot.gserviceaccount.com).
func isDefaultSA(email string) bool {
	return strings.HasSuffix(email, "-compute@developer.gserviceaccount.com") ||
		strings.HasSuffix(email, "@appspot.gserviceaccount.com")
}

// projectErrorResource emits a placeholder when a per-project
// collect fails outright. Lets the scan continue with findings
// from other projects while still surfacing the failure.
func (c *Collector) projectErrorResource(projectID, service string, err error) compliancekit.Resource {
	r := compliancekit.Resource{
		ID:       fmt.Sprintf("gcp.%s.error.%s", service, projectID),
		Type:     "gcp.collect_error",
		Name:     fmt.Sprintf("%s/%s", service, projectID),
		Provider: providerName,
		Attributes: map[string]any{
			"service": service,
			"error":   err.Error(),
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: projectID})
	return r
}

// pbTime converts a protobuf Timestamp to a Go time.Time. Returns
// the zero value when nil so check code reads "unknown" as zero.
func pbTime(t *timestamppb.Timestamp) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.AsTime()
}
