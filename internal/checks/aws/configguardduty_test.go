package aws

import (
	"context"
	"testing"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkConfigRegion(name string, on, channel bool) compliancekit.Resource {
	return compliancekit.Resource{
		ID: "aws.config.region." + name, Type: awscol.ConfigRegionType, Name: name, Provider: "aws",
		Attributes: map[string]any{
			"recorder_on":      on,
			"delivery_channel": channel,
		},
	}
}

func mkGD(name string, enabled bool) compliancekit.Resource {
	return compliancekit.Resource{
		ID: "aws.guardduty.region." + name, Type: awscol.GuardDutyRegionType, Name: name, Provider: "aws",
		Attributes: map[string]any{
			"detector_enabled": enabled,
		},
	}
}

func TestConfigRecorderOn(t *testing.T) {
	g := newGraphWith(mkConfigRegion("us-east-1", true, true), mkConfigRegion("us-west-2", false, true))
	findings, _ := ConfigRecorderOn(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "us-west-2" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestConfigDeliveryChannel(t *testing.T) {
	g := newGraphWith(mkConfigRegion("us-east-1", true, true), mkConfigRegion("us-west-2", true, false))
	findings, _ := ConfigDeliveryChannel(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "us-west-2" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestGuardDutyEnabled(t *testing.T) {
	g := newGraphWith(mkGD("us-east-1", true), mkGD("us-west-2", false))
	findings, _ := GuardDutyEnabled(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "us-west-2" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
