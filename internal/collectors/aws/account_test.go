package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type fakeSTS struct {
	account string
	err     error
}

func (f *fakeSTS) GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, opts ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.account == "" {
		return &sts.GetCallerIdentityOutput{}, nil // simulates empty Account
	}
	a := f.account
	return &sts.GetCallerIdentityOutput{Account: &a}, nil
}

func TestResolveAccountID_Success(t *testing.T) {
	got, err := resolveAccountIDWithClient(context.Background(), &fakeSTS{account: "123456789012"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "123456789012" {
		t.Errorf("got %q, want 123456789012", got)
	}
}

func TestResolveAccountID_STSError(t *testing.T) {
	_, err := resolveAccountIDWithClient(context.Background(), &fakeSTS{err: errors.New("unauthorized")})
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("expected wrapped STS error, got %v", err)
	}
}

func TestResolveAccountID_EmptyAccount(t *testing.T) {
	_, err := resolveAccountIDWithClient(context.Background(), &fakeSTS{account: ""})
	if err == nil || !strings.Contains(err.Error(), "empty account") {
		t.Errorf("expected empty-account error, got %v", err)
	}
}

// Smoke-test that LoadConfig returns without panic. It will use
// whatever credentials happen to be available in the test env (or
// none) -- we don't assert on the result, just on the contract.
func TestLoadConfig_ContractStable(t *testing.T) {
	cfg, err := LoadConfig(context.Background(), "us-east-1")
	if err != nil {
		// Without credentials this is allowed to fail.
		t.Logf("LoadConfig returned %v (expected without credentials)", err)
		return
	}
	if cfg.Region != "us-east-1" {
		t.Errorf("region: got %q, want us-east-1", cfg.Region)
	}
	_ = awssdk.Config{} // import retention
}
