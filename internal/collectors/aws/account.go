package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// stsClient is the subset of *sts.Client we exercise. Defining an
// interface lets tests inject a fake without needing the real SDK
// types in the test fixture.
type stsClient interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, opts ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// ResolveAccountID returns the 12-digit AWS account ID the configured
// credentials belong to, via STS GetCallerIdentity. Cached for the
// life of the Collector since the answer cannot change mid-scan.
//
// Returns an error rather than a string when STS is unreachable --
// without a known account ID every emitted Resource would have an
// ambiguous identity in the evidence pack, which is worse than
// failing fast.
func ResolveAccountID(ctx context.Context, cfg awssdk.Config) (string, error) {
	return resolveAccountIDWithClient(ctx, sts.NewFromConfig(cfg))
}

func resolveAccountIDWithClient(ctx context.Context, client stsClient) (string, error) {
	out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("aws: sts.GetCallerIdentity: %w", err)
	}
	if out.Account == nil || *out.Account == "" {
		return "", fmt.Errorf("aws: STS returned an empty account ID")
	}
	return *out.Account, nil
}
