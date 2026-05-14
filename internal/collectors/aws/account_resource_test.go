package aws

import (
	"testing"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
)

func TestAccountResource_StampedWithAccountID(t *testing.T) {
	c := &Collector{accountID: "123456789012"}
	r := c.accountResource([]string{"us-east-1", "us-west-2"})

	if r.Type != AccountType {
		t.Errorf("type: %q", r.Type)
	}
	if r.Provider != "aws" {
		t.Errorf("provider: %q", r.Provider)
	}
	if r.Name != "123456789012" {
		t.Errorf("name: %q", r.Name)
	}
	if r.Region != "" {
		t.Errorf("region: %q (account should be region-agnostic)", r.Region)
	}

	coord := cloudcommon.CoordOf(r)
	if coord.AccountID != "123456789012" {
		t.Errorf("coord account: %+v", coord)
	}

	regions, ok := r.Attributes["regions"].([]string)
	if !ok || len(regions) != 2 {
		t.Errorf("regions attribute: %+v", r.Attributes["regions"])
	}
}
