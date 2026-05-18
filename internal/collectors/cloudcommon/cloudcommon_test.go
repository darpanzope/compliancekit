package cloudcommon

import (
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func TestStamp_SetsBothFields(t *testing.T) {
	r := compliancekit.Resource{ID: "test", Type: "test"}
	Stamp(&r, ResourceCoord{AccountID: "123456789012", Region: "us-east-1"})

	if r.Region != "us-east-1" {
		t.Errorf("Resource.Region = %q, want us-east-1", r.Region)
	}
	if got := r.Attributes[AttrAccountID]; got != "123456789012" {
		t.Errorf("account_id attribute = %v, want 123456789012", got)
	}
	if got := r.Attributes[AttrRegion]; got != "us-east-1" {
		t.Errorf("region attribute = %v, want us-east-1", got)
	}
}

func TestStamp_EmptyValuesSkipped(t *testing.T) {
	r := compliancekit.Resource{
		ID:         "test",
		Type:       "test",
		Region:     "preset",
		Attributes: map[string]any{AttrRegion: "preset"},
	}
	// Empty account_id should not clobber; empty region should not clobber.
	Stamp(&r, ResourceCoord{})
	if r.Region != "preset" {
		t.Errorf("empty Stamp clobbered Region: %q", r.Region)
	}
	if _, ok := r.Attributes[AttrAccountID]; ok {
		t.Errorf("empty Stamp wrote AttrAccountID")
	}
}

func TestStamp_Idempotent(t *testing.T) {
	r := compliancekit.Resource{ID: "test", Type: "test"}
	coord := ResourceCoord{AccountID: "acct", Region: "rgn"}
	Stamp(&r, coord)
	first := r
	Stamp(&r, coord)
	if r.Region != first.Region || r.Attributes[AttrAccountID] != first.Attributes[AttrAccountID] {
		t.Error("Stamp not idempotent")
	}
}

func TestCoordOf_ReadsBothFields(t *testing.T) {
	r := compliancekit.Resource{
		ID:     "test",
		Type:   "test",
		Region: "us-west-2",
		Attributes: map[string]any{
			AttrAccountID: "999888777666",
			AttrRegion:    "us-west-2",
		},
	}
	got := CoordOf(r)
	if got.AccountID != "999888777666" || got.Region != "us-west-2" {
		t.Errorf("CoordOf = %+v", got)
	}
}

func TestCoordOf_FallsBackToAttrRegion(t *testing.T) {
	// Resource without typed Region field but with attribute.
	r := compliancekit.Resource{
		ID:         "test",
		Type:       "test",
		Attributes: map[string]any{AttrRegion: "eu-west-1"},
	}
	got := CoordOf(r)
	if got.Region != "eu-west-1" {
		t.Errorf("CoordOf.Region = %q, want eu-west-1 (read from attr)", got.Region)
	}
}

func TestCoordOf_ZeroValueOnAbsence(t *testing.T) {
	r := compliancekit.Resource{ID: "test", Type: "test"}
	got := CoordOf(r)
	if got.AccountID != "" || got.Region != "" {
		t.Errorf("CoordOf on bare resource = %+v, want zero", got)
	}
}
