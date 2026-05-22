package ui

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestYAMLRoundtrip seeds a provider + a disabled check + a tailored
// framework control, exports them as YAML, parses the bytes back into
// the typed shape, applies them to a fresh DB, and verifies the second
// export matches the first byte-for-byte. The phase 7 DoD.
func TestYAMLRoundtrip(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)

	// Seed: provider row with config (config_json non-empty makes
	// loadProviderRows mark it Configured=true), disabled check, and a
	// tailoring row.
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO providers (id, enabled, config_json, created_at, updated_at)
		 VALUES (?, 1, ?, ?, ?)`,
		"aws", `{"region":"us-east-1","services":["ec2","s3"]}`,
		time.Now().UTC().Format(time.RFC3339),
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO checks_state (check_id, enabled, updated_at) VALUES (?, 0, ?)`,
		"aws.iam.user.mfa-enabled", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed checks_state: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO framework_tailoring (framework_id, control_id, included, justification, updated_at)
		 VALUES (?, ?, 0, ?, ?)`,
		"cis-aws-3", "1.1.1", "intentional",
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed tailoring: %v", err)
	}

	first, err := u.renderGeneratedYAML(ctx)
	if err != nil {
		t.Fatalf("first export: %v", err)
	}
	if !strings.Contains(first, "providers:") {
		t.Fatalf("first export missing providers block: %s", first)
	}

	// Wipe + apply.
	if _, err := st.DB().ExecContext(ctx, `UPDATE providers SET enabled=0, config_json='{}'`); err != nil {
		t.Fatalf("wipe providers: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `DELETE FROM checks_state`); err != nil {
		t.Fatalf("wipe checks_state: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `DELETE FROM framework_tailoring`); err != nil {
		t.Fatalf("wipe tailoring: %v", err)
	}

	cfg, err := parseGeneratedConfig(first)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := u.applyGeneratedConfig(ctx, cfg); err != nil {
		t.Fatalf("apply: %v", err)
	}

	second, err := u.renderGeneratedYAML(ctx)
	if err != nil {
		t.Fatalf("second export: %v", err)
	}
	if first != second {
		t.Errorf("export/import not stable\n--- first:\n%s\n--- second:\n%s", first, second)
	}
}
