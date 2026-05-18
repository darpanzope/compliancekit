package aws

import (
	"context"
	"testing"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkAccount() compliancekit.Resource {
	return compliancekit.Resource{ID: "aws.account.x", Type: awscol.AccountType, Name: "x", Provider: "aws"}
}

func mkTrail(name string, logging, multi, validation bool) compliancekit.Resource {
	return compliancekit.Resource{
		ID: "aws.cloudtrail.trail." + name, Type: awscol.CloudTrailType, Name: name, Provider: "aws",
		Attributes: map[string]any{
			"is_logging":                  logging,
			"is_multi_region":             multi,
			"log_file_validation_enabled": validation,
		},
	}
}

func TestCloudTrailEnabled(t *testing.T) {
	t.Run("no trails", func(t *testing.T) {
		g := newGraphWith(mkAccount())
		findings, _ := CloudTrailEnabled(context.Background(), g)
		if findings[0].Status != compliancekit.StatusFail {
			t.Errorf("got %v", findings[0].Status)
		}
	})
	t.Run("at least one logging", func(t *testing.T) {
		g := newGraphWith(mkAccount(), mkTrail("t1", true, true, true))
		findings, _ := CloudTrailEnabled(context.Background(), g)
		if findings[0].Status != compliancekit.StatusPass {
			t.Errorf("got %v", findings[0].Status)
		}
	})
}

func TestCloudTrailMultiRegion(t *testing.T) {
	t.Run("only single region logging", func(t *testing.T) {
		g := newGraphWith(mkAccount(), mkTrail("t1", true, false, true))
		findings, _ := CloudTrailMultiRegion(context.Background(), g)
		if findings[0].Status != compliancekit.StatusFail {
			t.Errorf("got %v", findings[0].Status)
		}
	})
	t.Run("multi-region logging", func(t *testing.T) {
		g := newGraphWith(mkAccount(), mkTrail("t1", true, true, true))
		findings, _ := CloudTrailMultiRegion(context.Background(), g)
		if findings[0].Status != compliancekit.StatusPass {
			t.Errorf("got %v", findings[0].Status)
		}
	})
}

func TestCloudTrailLogFileValidation(t *testing.T) {
	g := newGraphWith(mkTrail("good", true, true, true), mkTrail("bad", true, true, false))
	findings, _ := CloudTrailLogFileValidation(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "bad" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
