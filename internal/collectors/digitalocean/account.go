package digitalocean

import (
	"context"
	"fmt"

	"github.com/digitalocean/godo"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// AccountType is the singleton account/team anchor resource. Every
// scan emits exactly one of these. Cross-cutting account-level
// checks (MFA enforcement, billing alerts, etc.) attach findings
// here; the resource also carries the team UUID that
// cloudcommon.Stamp puts on every per-resource entry as
// account_id.
const AccountType = "digitalocean.account"

// fetchAccount loads the Account record and converts it to the
// anchor resource. Stored on the Collector so subsequent
// per-service collectors can read the team UUID without
// re-issuing the API call.
func (c *Collector) fetchAccount(ctx context.Context) (godo.Account, core.Resource, error) {
	resp, _, err := c.client.Account.Get(ctx)
	if err != nil {
		return godo.Account{}, core.Resource{}, fmt.Errorf("account: %w", err)
	}
	if resp == nil {
		return godo.Account{}, core.Resource{}, fmt.Errorf("account: nil response")
	}
	return *resp, accountToResource(*resp), nil
}

func accountToResource(a godo.Account) core.Resource {
	teamUUID := ""
	teamName := ""
	if a.Team != nil {
		teamUUID = a.Team.UUID
		teamName = a.Team.Name
	}
	r := core.Resource{
		ID:       fmt.Sprintf("%s.%s", AccountType, a.UUID),
		Type:     AccountType,
		Name:     a.Email,
		Provider: providerName,
		Attributes: map[string]any{
			"uuid":              a.UUID,
			"email":             a.Email,
			"email_verified":    a.EmailVerified,
			"status":            a.Status,
			"status_message":    a.StatusMessage,
			"droplet_limit":     a.DropletLimit,
			"floating_ip_limit": a.FloatingIPLimit,
			"reserved_ip_limit": a.ReservedIPLimit,
			"volume_limit":      a.VolumeLimit,
			"team_uuid":         teamUUID,
			"team_name":         teamName,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: stampAccountID(a),
	})
	return r
}

// stampAccountID picks the team UUID when present (multi-user
// orgs), falling back to the account UUID (solo-developer
// accounts). Same identity rule the evidence pack writer uses.
func stampAccountID(a godo.Account) string {
	if a.Team != nil && a.Team.UUID != "" {
		return a.Team.UUID
	}
	return a.UUID
}
