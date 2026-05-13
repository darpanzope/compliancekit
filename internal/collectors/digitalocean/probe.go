package digitalocean

import (
	"context"
	"time"

	"github.com/digitalocean/godo"
)

// Probe verifies DigitalOcean API connectivity by fetching the
// authenticated account record. Returns the round-trip duration and
// any error.
//
// Used by `compliancekit doctor` to confirm DO_API_TOKEN works against
// the real API before any scan runs. Probe makes one HTTPS call to
// api.digitalocean.com; nothing is written or mutated on the account.
func Probe(ctx context.Context, token string) (time.Duration, error) {
	return probe(ctx, godo.NewFromToken(token))
}

// probe is the testable inner helper. Tests inject a godo.Client whose
// BaseURL points at an httptest.NewServer.
func probe(ctx context.Context, client *godo.Client) (time.Duration, error) {
	start := time.Now()
	_, _, err := client.Account.Get(ctx)
	return time.Since(start), err
}
