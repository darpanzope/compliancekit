package aws

import (
	"context"
	"testing"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkKey(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID: "aws.kms.key." + name, Type: awscol.KMSKeyType, Name: name, Provider: "aws",
		Attributes: attrs,
	}
}

func TestKMSCMKRotation(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		want  compliancekit.Status
	}{
		{"rotation on", map[string]any{"rotation_enabled": true}, compliancekit.StatusPass},
		{"rotation off", map[string]any{"rotation_enabled": false}, compliancekit.StatusFail},
		{"not applicable", map[string]any{"rotation_enabled": nil}, compliancekit.StatusSkip},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraphWith(mkKey("k", c.attrs))
			findings, _ := KMSCMKRotation(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestKMSNoPendingDeletion(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		want  compliancekit.Status
	}{
		{"customer pending", map[string]any{"key_manager": "CUSTOMER", "key_state": "PendingDeletion"}, compliancekit.StatusFail},
		{"customer enabled", map[string]any{"key_manager": "CUSTOMER", "key_state": "Enabled"}, compliancekit.StatusPass},
		{"aws-managed skipped", map[string]any{"key_manager": "AWS", "key_state": "PendingDeletion"}, compliancekit.StatusSkip},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraphWith(mkKey("k", c.attrs))
			findings, _ := KMSNoPendingDeletion(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}
