package gcp

import (
	"context"
	"strings"
	"testing"

	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkCryptoKey(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID:         "gcp.kms.crypto_key." + name,
		Type:       gcpcol.KMSCryptoKeyType,
		Name:       name,
		Provider:   "gcp",
		Attributes: attrs,
	}
}

func TestKMSKeyRotation(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		want  compliancekit.Status
		skip  bool
	}{
		{
			"non-encrypt-decrypt-skipped",
			map[string]any{"is_encrypt_decrypt": false, "has_rotation_schedule": false},
			compliancekit.StatusPass, true, // want unused when skip=true
		},
		{
			"no-schedule",
			map[string]any{"is_encrypt_decrypt": true, "has_rotation_schedule": false, "rotation_period_days": 0},
			compliancekit.StatusFail, false,
		},
		{
			"too-long",
			map[string]any{"is_encrypt_decrypt": true, "has_rotation_schedule": true, "rotation_period_days": 180},
			compliancekit.StatusFail, false,
		},
		{
			"at-max",
			map[string]any{"is_encrypt_decrypt": true, "has_rotation_schedule": true, "rotation_period_days": 90},
			compliancekit.StatusPass, false,
		},
		{
			"frequent",
			map[string]any{"is_encrypt_decrypt": true, "has_rotation_schedule": true, "rotation_period_days": 30},
			compliancekit.StatusPass, false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraphWith(mkCryptoKey(c.name, c.attrs))
			findings, _ := KMSKeyRotation(context.Background(), g)
			if c.skip {
				if len(findings) != 0 {
					t.Fatalf("expected key to be skipped, got %d findings", len(findings))
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestKMSAdminUserSeparation(t *testing.T) {
	cases := []struct {
		name     string
		bindings []map[string]any
		want     compliancekit.Status
		wantSub  string
	}{
		{
			"no-overlap",
			[]map[string]any{
				{"role": "roles/cloudkms.admin", "members": []string{"user:admin@x.com"}},
				{"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter", "members": []string{"serviceAccount:app@p.iam.gserviceaccount.com"}},
			},
			compliancekit.StatusPass, "",
		},
		{
			"same-principal-both-roles",
			[]map[string]any{
				{"role": "roles/cloudkms.admin", "members": []string{"user:dev@x.com", "user:admin@x.com"}},
				{"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter", "members": []string{"user:dev@x.com"}},
			},
			compliancekit.StatusFail, "user:dev@x.com",
		},
		{
			"only-admin",
			[]map[string]any{
				{"role": "roles/cloudkms.admin", "members": []string{"user:admin@x.com"}},
			},
			compliancekit.StatusPass, "",
		},
		{
			"encrypter-only",
			[]map[string]any{
				{"role": "roles/cloudkms.cryptoKeyEncrypter", "members": []string{"serviceAccount:enc@p.iam.gserviceaccount.com"}},
			},
			compliancekit.StatusPass, "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraphWith(mkCryptoKey(c.name, map[string]any{"iam_bindings": c.bindings}))
			findings, _ := KMSAdminUserSeparation(context.Background(), g)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
			if c.wantSub != "" && !strings.Contains(findings[0].Message, c.wantSub) {
				t.Errorf("message %q should contain %q", findings[0].Message, c.wantSub)
			}
		})
	}
}
