package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
)

// LoadConfig wires the standard SDK credential chain plus the
// adaptive rate-limit retryer, returning an aws.Config the
// per-service clients are built from.
//
// region defaults to the operator's configured AWS_REGION (or the
// profile default) when empty. Callers that scan multiple regions
// build one config per region; passing "" here is fine for the
// account-scoped (region-agnostic) clients (IAM, STS).
//
// Retries:
//
// AWS SDK v2's adaptive retry mode includes a token-bucket rate
// limiter sensitive to client-side throttling. For a 50-account
// fleet scan that hits IAM hundreds of times this is the difference
// between a 30s scan and one that ends in throttle backoff
// purgatory. We set MaxAttempts=5 (SDK default is 3) because
// compliance scans are batch jobs that can afford to wait.
func LoadConfig(ctx context.Context, region string) (awssdk.Config, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRetryer(func() awssdk.Retryer {
			return retry.NewAdaptiveMode(func(o *retry.AdaptiveModeOptions) {
				o.StandardOptions = append(o.StandardOptions, func(so *retry.StandardOptions) {
					so.MaxAttempts = 5
				})
			})
		}),
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return awssdk.Config{}, fmt.Errorf("aws: load default config: %w", err)
	}
	return cfg, nil
}
