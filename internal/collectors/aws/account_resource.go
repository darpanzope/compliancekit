package aws

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// AccountType is the resource type emitted for the synthetic AWS
// account resource. One per scan. Holds account-scoped facts that
// account-level checks (e.g. password-policy, MFA on root) read.
const AccountType = "aws.account"

// accountResource builds the singleton account resource. Carries the
// resolved account ID and the list of regions in scope as
// attributes; account-level check scanners read from here.
//
// The Resource.Region is left empty because the account itself is
// region-agnostic. Per-region resources stamp their own Region via
// cloudcommon.Stamp.
func (c *Collector) accountResource(regions []string) compliancekit.Resource {
	r := compliancekit.Resource{
		ID:       fmt.Sprintf("aws.account.%s", c.accountID),
		Type:     AccountType,
		Name:     c.accountID,
		Provider: providerName,
		Attributes: map[string]any{
			"regions": regions,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: c.accountID,
		// Region empty: account is region-agnostic.
	})
	return r
}
