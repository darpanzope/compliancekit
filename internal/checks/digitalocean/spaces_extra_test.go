package digitalocean

import (
	"context"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.19 phase 2 — tests for the 10 Spaces-depth checks. Real-data
// cases exercise the boolean attributes the v0.19 collector extension
// surfaces; manual-verify cases assert StatusError + a dashboard URL
// in the message.

func TestSpacesLifecycleNoExpiration(t *testing.T) {
	cases := []struct {
		name   string
		attrs  map[string]any
		want   compliancekit.Status
		expect string // substring expected in message; "" to skip
	}{
		{"no lifecycle → skip", map[string]any{"lifecycle_configured": false}, "", ""},
		{"has expiration", map[string]any{"lifecycle_configured": true, "lifecycle_has_expiration": true}, compliancekit.StatusPass, "has expiration"},
		{"missing expiration", map[string]any{"lifecycle_configured": true, "lifecycle_has_expiration": false}, compliancekit.StatusFail, "no expiration"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkBucket("b", c.attrs))
			findings, _ := SpacesLifecycleNoExpiration(context.Background(), g)
			if c.want == "" {
				if len(findings) != 0 {
					t.Errorf("expected no finding, got %d", len(findings))
				}
				return
			}
			if findings[0].Status != c.want {
				t.Errorf("status=%v, want %v", findings[0].Status, c.want)
			}
			if c.expect != "" && !strings.Contains(findings[0].Message, c.expect) {
				t.Errorf("message %q missing %q", findings[0].Message, c.expect)
			}
		})
	}
}

func TestSpacesLifecycleNoMPUAbort(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		want  compliancekit.Status
	}{
		{"no lifecycle", map[string]any{"lifecycle_configured": false}, ""},
		{"has mpu abort", map[string]any{"lifecycle_configured": true, "lifecycle_has_mpu_abort": true}, compliancekit.StatusPass},
		{"missing mpu abort", map[string]any{"lifecycle_configured": true, "lifecycle_has_mpu_abort": false}, compliancekit.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkBucket("b", c.attrs))
			findings, _ := SpacesLifecycleNoMPUAbort(context.Background(), g)
			if c.want == "" {
				if len(findings) != 0 {
					t.Errorf("expected no finding, got %d", len(findings))
				}
				return
			}
			if findings[0].Status != c.want {
				t.Errorf("status=%v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestSpacesLoggingSelfTarget(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		want  compliancekit.Status
	}{
		{"logging off", map[string]any{"logging_enabled": false}, ""},
		{"target=source", map[string]any{"logging_enabled": true, "logging_target_bucket": "b"}, compliancekit.StatusFail},
		{"target≠source", map[string]any{"logging_enabled": true, "logging_target_bucket": "audit"}, compliancekit.StatusPass},
		{"missing target", map[string]any{"logging_enabled": true}, compliancekit.StatusError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkBucket("b", c.attrs))
			findings, _ := SpacesLoggingSelfTarget(context.Background(), g)
			if c.want == "" {
				if len(findings) != 0 {
					t.Errorf("expected no finding, got %d", len(findings))
				}
				return
			}
			if findings[0].Status != c.want {
				t.Errorf("status=%v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestSpacesPolicyRequired(t *testing.T) {
	g := newAccountGraph(
		mkBucket("with", map[string]any{"policy_configured": true}),
		mkBucket("without", map[string]any{"policy_configured": false}),
	)
	findings, _ := SpacesPolicyRequired(context.Background(), g)
	byName := map[string]compliancekit.Status{}
	for _, f := range findings {
		byName[f.Resource.Name] = f.Status
	}
	if byName["with"] != compliancekit.StatusPass || byName["without"] != compliancekit.StatusFail {
		t.Errorf("statuses wrong: %+v", byName)
	}
}

func TestSpacesVersioningRequiresLifecycle(t *testing.T) {
	g := newAccountGraph(
		mkBucket("no-vers", map[string]any{"versioning_enabled": false}),
		mkBucket("vers-no-lifecycle", map[string]any{"versioning_enabled": true, "lifecycle_configured": false}),
		mkBucket("vers-and-lifecycle", map[string]any{"versioning_enabled": true, "lifecycle_configured": true}),
	)
	findings, _ := SpacesVersioningRequiresLifecycle(context.Background(), g)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (versioning-only ones), got %d", len(findings))
	}
	byName := map[string]compliancekit.Status{}
	for _, f := range findings {
		byName[f.Resource.Name] = f.Status
	}
	if byName["vers-no-lifecycle"] != compliancekit.StatusFail {
		t.Errorf("vers-no-lifecycle should fail, got %v", byName["vers-no-lifecycle"])
	}
	if byName["vers-and-lifecycle"] != compliancekit.StatusPass {
		t.Errorf("vers-and-lifecycle should pass, got %v", byName["vers-and-lifecycle"])
	}
}

func TestSpacesAuditPairing(t *testing.T) {
	cases := []struct {
		name string
		enc  bool
		log  bool
		want compliancekit.Status
	}{
		{"both off", false, false, compliancekit.StatusFail},
		{"enc on log off", true, false, compliancekit.StatusFail},
		{"enc off log on", false, true, compliancekit.StatusFail},
		{"both on", true, true, compliancekit.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkBucket("b", map[string]any{
				"encryption_configured": c.enc,
				"logging_enabled":       c.log,
			}))
			findings, _ := SpacesAuditPairing(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestSpacesManualVerifyChecks(t *testing.T) {
	g := newAccountGraph(mkBucket("b", nil))
	cases := []struct {
		name    string
		fn      func(context.Context, *compliancekit.ResourceGraph) ([]compliancekit.Finding, error)
		urlPart string
	}{
		{"object-lock", SpacesObjectLockAppLayer, "s3-compatibility"},
		{"replication", SpacesReplicationViaExternalSync, "digitalocean.com"},
		{"mfa-delete", SpacesMFADeleteViaTeamIAM, "digitalocean.com"},
		{"key-rotation", SpacesEncryptionKeyRotation, "trust"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings, _ := c.fn(context.Background(), g)
			if findings[0].Status != compliancekit.StatusError {
				t.Errorf("status=%v, want StatusError", findings[0].Status)
			}
			if !strings.Contains(findings[0].Message, c.urlPart) {
				t.Errorf("message %q missing URL hint %q", findings[0].Message, c.urlPart)
			}
		})
	}
}
