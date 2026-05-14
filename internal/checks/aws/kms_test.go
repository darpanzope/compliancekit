package aws

import (
	"context"
	"testing"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/internal/core"
)

func mkKey(name string, attrs map[string]any) core.Resource {
	return core.Resource{
		ID: "aws.kms.key." + name, Type: awscol.KMSKeyType, Name: name, Provider: "aws",
		Attributes: attrs,
	}
}

func TestKMSCMKRotation(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		want  core.Status
	}{
		{"rotation on", map[string]any{"rotation_enabled": true}, core.StatusPass},
		{"rotation off", map[string]any{"rotation_enabled": false}, core.StatusFail},
		{"not applicable", map[string]any{"rotation_enabled": nil}, core.StatusSkip},
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
		want  core.Status
	}{
		{"customer pending", map[string]any{"key_manager": "CUSTOMER", "key_state": "PendingDeletion"}, core.StatusFail},
		{"customer enabled", map[string]any{"key_manager": "CUSTOMER", "key_state": "Enabled"}, core.StatusPass},
		{"aws-managed skipped", map[string]any{"key_manager": "AWS", "key_state": "PendingDeletion"}, core.StatusSkip},
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
