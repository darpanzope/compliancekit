package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// ec2RegionClient is the subset of *ec2.Client we use for region
// discovery. Injectable for tests.
type ec2RegionClient interface {
	DescribeRegions(ctx context.Context, in *ec2.DescribeRegionsInput, opts ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

// ResolveRegions returns the list of regions enabled on the account
// and visible to the credential. EC2 DescribeRegions is the
// authoritative source -- it filters out opt-in regions the account
// hasn't enabled, which means we don't waste API calls scanning a
// region with zero resources.
//
// filter (when non-empty) restricts the result to the intersection
// of (enabled regions, filter). Unknown names in filter are dropped
// with a warning rather than an error -- a typo in
// compliancekit.yaml shouldn't break the entire scan; the operator
// notices the missing region in the scan footer.
func ResolveRegions(ctx context.Context, cfg awssdk.Config, filter []string) ([]string, error) {
	return resolveRegionsWithClient(ctx, ec2.NewFromConfig(cfg), filter)
}

func resolveRegionsWithClient(ctx context.Context, client ec2RegionClient, filter []string) ([]string, error) {
	out, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		// AllRegions=false drops regions the account hasn't opted into.
		AllRegions: awssdk.Bool(false),
	})
	if err != nil {
		return nil, fmt.Errorf("aws: ec2.DescribeRegions: %w", err)
	}
	enabled := make(map[string]bool, len(out.Regions))
	for _, r := range out.Regions {
		if r.RegionName == nil {
			continue
		}
		enabled[*r.RegionName] = true
	}

	if len(filter) == 0 {
		return sortedKeys(enabled), nil
	}

	wanted := make([]string, 0, len(filter))
	for _, name := range filter {
		if enabled[name] {
			wanted = append(wanted, name)
		}
		// Silently drop unknowns; the scan banner reports the actual
		// region count so a typo is observable.
	}
	return wanted, nil
}

// sortedKeys returns the keys of m sorted lexicographically. Tiny
// helper local to this file because the only caller is
// resolveRegionsWithClient.
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Manual lexicographic sort (insertion). Region lists are short
	// (typically <30) so the import-saving cost outweighs the perf
	// difference vs. sort.Strings.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}
