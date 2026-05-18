package auth

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestMain lowers bcryptCost for tests so `make test` (which runs
// with -race -timeout=60s) finishes well inside the budget. Cost 4
// is the bcrypt MinCost; password verification is still
// constant-time + correctly typed, but each hash takes microseconds
// instead of ~250ms. Production callers continue to use cost 12 via
// the package-default var.
func TestMain(m *testing.M) {
	bcryptCost = bcrypt.MinCost
	m.Run()
}
