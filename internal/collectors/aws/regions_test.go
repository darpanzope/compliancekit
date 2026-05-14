package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type fakeEC2Regions struct {
	regions []string
	err     error
}

func (f *fakeEC2Regions) DescribeRegions(ctx context.Context, in *ec2.DescribeRegionsInput, opts ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := &ec2.DescribeRegionsOutput{}
	for _, r := range f.regions {
		name := r
		out.Regions = append(out.Regions, ec2types.Region{RegionName: &name})
	}
	return out, nil
}

func TestResolveRegions_NoFilter_ReturnsAll(t *testing.T) {
	c := &fakeEC2Regions{regions: []string{"us-east-1", "us-west-2", "eu-west-1"}}
	got, err := resolveRegionsWithClient(context.Background(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Sorted output.
	want := []string{"eu-west-1", "us-east-1", "us-west-2"}
	if len(got) != len(want) {
		t.Fatalf("got %d regions, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestResolveRegions_FilterIntersection(t *testing.T) {
	c := &fakeEC2Regions{regions: []string{"us-east-1", "us-west-2", "eu-west-1"}}
	got, err := resolveRegionsWithClient(context.Background(), c, []string{"us-east-1", "ap-south-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "us-east-1" {
		t.Errorf("got %+v, want only us-east-1", got)
	}
}

func TestResolveRegions_DescribeError(t *testing.T) {
	c := &fakeEC2Regions{err: errors.New("denied")}
	_, err := resolveRegionsWithClient(context.Background(), c, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResolveRegions_EmptyResultWithFilter(t *testing.T) {
	c := &fakeEC2Regions{regions: []string{"us-east-1"}}
	got, err := resolveRegionsWithClient(context.Background(), c, []string{"nowhere"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %d, want 0", len(got))
	}
}

func TestSortedKeys(t *testing.T) {
	in := map[string]bool{"z": true, "a": true, "m": true}
	got := sortedKeys(in)
	if len(got) != 3 || got[0] != "a" || got[1] != "m" || got[2] != "z" {
		t.Errorf("not sorted: %+v", got)
	}
}

var _ = awssdk.Bool // import retention
