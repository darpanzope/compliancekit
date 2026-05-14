package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/darpanzope/compliancekit/internal/core"
)

const providerName = "aws"

// Collector fetches resources from an AWS account.
//
// Construct via New for production. The zero value is not usable.
type Collector struct {
	// regions is the explicit region scope. Empty means "all regions
	// the credential can see at scan time," resolved by Collect().
	regions []string

	// cfg is the loaded SDK config. The account-scoped clients (IAM,
	// STS) use this directly; per-region clients (EC2, S3, etc.) are
	// built from a region-specific clone in collectInRegion().
	cfg awssdk.Config

	// accountID is resolved once at Collect() start via STS.
	accountID string
}

// Options configures a Collector at construction time. All fields
// are optional; zero values produce the "auto-detect everything"
// behavior.
type Options struct {
	// Regions narrows the per-region scan. Empty means "all enabled
	// regions visible to the credential."
	Regions []string

	// CfgOverride lets tests inject a pre-built aws.Config (with a
	// custom endpoint resolver pointing at httptest servers, say).
	// Production callers pass nil.
	CfgOverride *awssdk.Config
}

// New constructs an AWS Collector. The SDK config is loaded
// eagerly so credential / region errors surface at construction
// rather than at first scan, which is friendlier for `doctor`.
func New(ctx context.Context, opts Options) (*Collector, error) {
	var cfg awssdk.Config
	if opts.CfgOverride != nil {
		cfg = *opts.CfgOverride
	} else {
		// Use the first region from the filter (if set) as the
		// default; account-scoped APIs ignore it, and a per-region
		// clone supersedes it for the rest.
		defaultRegion := ""
		if len(opts.Regions) > 0 {
			defaultRegion = opts.Regions[0]
		}
		c, err := LoadConfig(ctx, defaultRegion)
		if err != nil {
			return nil, err
		}
		cfg = c
	}
	return &Collector{
		regions: opts.Regions,
		cfg:     cfg,
	}, nil
}

// Name implements core.Collector. Stable across versions; the
// evidence pack groups findings by this string.
func (c *Collector) Name() string { return providerName }

// Collect implements core.Collector. The v0.7-phase-1 implementation
// resolves the account ID and the region scope, then returns an
// empty resource slice -- per-service collectors land in phases 2-10
// and each one appends to the returned slice via a service-specific
// helper.
//
// The shape of the per-service plug-in is:
//
//	out, err := c.collectIAM(ctx, out)
//	if err != nil { return nil, err }
//	for _, region := range regions {
//	    out, err = c.collectEC2(ctx, region, out)
//	    ...
//	}
//
// At phase 1 the body is just the resolution; the slice is empty.
// This is intentional -- the foundation commit is testable on its
// own without needing every service to be done first.
func (c *Collector) Collect(ctx context.Context) ([]core.Resource, error) {
	accountID, err := ResolveAccountID(ctx, c.cfg)
	if err != nil {
		return nil, err
	}
	c.accountID = accountID

	regions, err := ResolveRegions(ctx, c.cfg, c.regions)
	if err != nil {
		return nil, err
	}
	if len(regions) == 0 {
		return nil, fmt.Errorf("aws: no regions resolved (credential cannot see any region)")
	}

	// The account resource anchors account-scoped checks
	// (password-policy, root-MFA, etc.). Per-service collectors
	// either enrich this resource with their account-level facts
	// (IAM) or append per-resource entries (S3 buckets, EC2
	// instances, etc.).
	account := c.accountResource(regions)
	out := []core.Resource{}

	// IAM is account-scoped, not region-scoped, so it runs once
	// regardless of the region scope.
	updated, err := c.collectIAM(ctx, &account, out)
	if err != nil {
		return nil, err
	}
	out = updated

	out = append(out, account)
	return out, nil
}

// AccountID returns the resolved account ID. Empty before the first
// Collect() call. Public so tests and the doctor command can read it.
func (c *Collector) AccountID() string { return c.accountID }
