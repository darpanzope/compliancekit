package aws

import (
	"context"
	"testing"
	"time"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/internal/core"
)

func newAccountGraph(attrs map[string]any) *core.ResourceGraph {
	g := core.NewResourceGraph()
	g.Add(core.Resource{
		ID:         "aws.account.123456789012",
		Type:       awscol.AccountType,
		Name:       "123456789012",
		Provider:   "aws",
		Attributes: attrs,
	})
	return g
}

func newUserGraph(attrs map[string]any) *core.ResourceGraph {
	g := core.NewResourceGraph()
	g.Add(core.Resource{
		ID:         "aws.iam.user.alice",
		Type:       awscol.IAMUserType,
		Name:       "alice",
		Provider:   "aws",
		Attributes: attrs,
	})
	return g
}

// ============ root access key ============

func TestRootAccessKey_Fail(t *testing.T) {
	g := newAccountGraph(map[string]any{"root_has_access_keys": true})
	findings, err := RootAccessKey(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Status != core.StatusFail {
		t.Errorf("expected one Fail finding, got %+v", findings)
	}
}

func TestRootAccessKey_Pass(t *testing.T) {
	g := newAccountGraph(map[string]any{"root_has_access_keys": false})
	findings, _ := RootAccessKey(context.Background(), g)
	if len(findings) != 1 || findings[0].Status != core.StatusPass {
		t.Errorf("expected Pass, got %+v", findings)
	}
}

// ============ root MFA ============

func TestRootMFA(t *testing.T) {
	cases := []struct {
		name  string
		enabl bool
		want  core.Status
	}{
		{"enabled", true, core.StatusPass},
		{"disabled", false, core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(map[string]any{"root_mfa_enabled": c.enabl})
			findings, _ := RootMFA(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

// ============ password policy ============

func TestPasswordPolicy_None(t *testing.T) {
	g := newAccountGraph(map[string]any{"password_policy": nil})
	findings, _ := PasswordPolicy(context.Background(), g)
	if findings[0].Status != core.StatusFail {
		t.Errorf("expected fail with no policy, got %v", findings[0].Status)
	}
}

func TestPasswordPolicy_CompliantMeetsAll(t *testing.T) {
	g := newAccountGraph(map[string]any{
		"password_policy": map[string]any{
			"minimum_password_length":      14,
			"require_symbols":              true,
			"require_numbers":              true,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"expire_passwords":             true,
			"max_password_age":             90,
			"password_reuse_prevention":    24,
		},
	})
	findings, _ := PasswordPolicy(context.Background(), g)
	if findings[0].Status != core.StatusPass {
		t.Errorf("expected Pass, got %v: %s", findings[0].Status, findings[0].Message)
	}
}

func TestPasswordPolicy_WeakLength(t *testing.T) {
	g := newAccountGraph(map[string]any{
		"password_policy": map[string]any{
			"minimum_password_length":      8,
			"require_symbols":              true,
			"require_numbers":              true,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"expire_passwords":             true,
			"max_password_age":             90,
			"password_reuse_prevention":    24,
		},
	})
	findings, _ := PasswordPolicy(context.Background(), g)
	if findings[0].Status != core.StatusFail {
		t.Errorf("expected fail on weak length, got %v", findings[0].Status)
	}
}

// ============ access key age ============

func TestAccessKeyAge_Old(t *testing.T) {
	old := time.Now().Add(-120 * 24 * time.Hour)
	g := newUserGraph(map[string]any{
		"access_keys": []map[string]any{
			{"access_key_id": "AKIAOLD", "status": "Active", "created_at": old},
		},
	})
	findings, _ := AccessKeyAge(context.Background(), g)
	if findings[0].Status != core.StatusFail {
		t.Errorf("expected fail on old key, got %v: %s", findings[0].Status, findings[0].Message)
	}
}

func TestAccessKeyAge_Fresh(t *testing.T) {
	fresh := time.Now().Add(-10 * 24 * time.Hour)
	g := newUserGraph(map[string]any{
		"access_keys": []map[string]any{
			{"access_key_id": "AKIAFRESH", "status": "Active", "created_at": fresh},
		},
	})
	findings, _ := AccessKeyAge(context.Background(), g)
	if findings[0].Status != core.StatusPass {
		t.Errorf("expected pass on fresh key, got %v", findings[0].Status)
	}
}

func TestAccessKeyAge_InactiveIgnored(t *testing.T) {
	old := time.Now().Add(-365 * 24 * time.Hour)
	g := newUserGraph(map[string]any{
		"access_keys": []map[string]any{
			{"access_key_id": "AKIAOLD", "status": "Inactive", "created_at": old},
		},
	})
	findings, _ := AccessKeyAge(context.Background(), g)
	if findings[0].Status != core.StatusPass {
		t.Errorf("inactive keys should be ignored, got %v", findings[0].Status)
	}
}

// ============ unused users ============

func TestUnusedUsers_RecentlyActive(t *testing.T) {
	g := newUserGraph(map[string]any{
		"created_at":         time.Now().Add(-365 * 24 * time.Hour),
		"password_last_used": time.Now().Add(-3 * 24 * time.Hour),
		"access_keys":        []map[string]any{},
	})
	findings, _ := UnusedUsers(context.Background(), g)
	if findings[0].Status != core.StatusPass {
		t.Errorf("expected pass for recently active, got %v", findings[0].Status)
	}
}

func TestUnusedUsers_LongIdle(t *testing.T) {
	g := newUserGraph(map[string]any{
		"created_at":         time.Now().Add(-365 * 24 * time.Hour),
		"password_last_used": time.Now().Add(-180 * 24 * time.Hour),
		"access_keys":        []map[string]any{},
	})
	findings, _ := UnusedUsers(context.Background(), g)
	if findings[0].Status != core.StatusFail {
		t.Errorf("expected fail for long idle, got %v: %s", findings[0].Status, findings[0].Message)
	}
}

func TestUnusedUsers_NeverUsedWithinOnboarding(t *testing.T) {
	g := newUserGraph(map[string]any{
		"created_at":  time.Now().Add(-7 * 24 * time.Hour),
		"access_keys": []map[string]any{},
	})
	findings, _ := UnusedUsers(context.Background(), g)
	if findings[0].Status != core.StatusPass {
		t.Errorf("expected pass for new user in onboarding, got %v", findings[0].Status)
	}
}

// ============ no user managed policies ============

func TestNoUserManagedPolicies(t *testing.T) {
	t.Run("none attached", func(t *testing.T) {
		g := newUserGraph(map[string]any{"attached_managed_policies": []string{}})
		findings, _ := NoUserManagedPolicies(context.Background(), g)
		if findings[0].Status != core.StatusPass {
			t.Errorf("got %v", findings[0].Status)
		}
	})
	t.Run("policy attached", func(t *testing.T) {
		g := newUserGraph(map[string]any{
			"attached_managed_policies": []string{"arn:aws:iam::aws:policy/AdministratorAccess"},
		})
		findings, _ := NoUserManagedPolicies(context.Background(), g)
		if findings[0].Status != core.StatusFail {
			t.Errorf("got %v: %s", findings[0].Status, findings[0].Message)
		}
	})
}

// ============ console user MFA ============

func TestConsoleUserMFA(t *testing.T) {
	cases := []struct {
		name    string
		console bool
		mfa     bool
		want    core.Status
	}{
		{"no console", false, false, core.StatusPass},
		{"console+mfa", true, true, core.StatusPass},
		{"console no mfa", true, false, core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newUserGraph(map[string]any{
				"has_console_access":  c.console,
				"console_mfa_enabled": c.mfa,
			})
			findings, _ := ConsoleUserMFA(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

// ============ no star inline policies ============

func TestNoStarInlinePolicies(t *testing.T) {
	t.Run("no inline", func(t *testing.T) {
		g := newUserGraph(map[string]any{"inline_policies": []map[string]any{}})
		findings, _ := NoStarInlinePolicies(context.Background(), g)
		if findings[0].Status != core.StatusPass {
			t.Errorf("got %v", findings[0].Status)
		}
	})

	t.Run("scoped inline", func(t *testing.T) {
		scoped := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`
		g := newUserGraph(map[string]any{
			"inline_policies": []map[string]any{{"name": "scoped", "document": scoped}},
		})
		findings, _ := NoStarInlinePolicies(context.Background(), g)
		if findings[0].Status != core.StatusPass {
			t.Errorf("expected pass on scoped policy, got %v: %s", findings[0].Status, findings[0].Message)
		}
	})

	t.Run("star star inline", func(t *testing.T) {
		bad := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
		g := newUserGraph(map[string]any{
			"inline_policies": []map[string]any{{"name": "bad", "document": bad}},
		})
		findings, _ := NoStarInlinePolicies(context.Background(), g)
		if findings[0].Status != core.StatusFail {
			t.Errorf("expected fail on *:* policy, got %v", findings[0].Status)
		}
	})

	t.Run("star action in array", func(t *testing.T) {
		bad := `{"Statement":[{"Effect":"Allow","Action":["s3:Get*","*"],"Resource":"*"}]}`
		g := newUserGraph(map[string]any{
			"inline_policies": []map[string]any{{"name": "bad", "document": bad}},
		})
		findings, _ := NoStarInlinePolicies(context.Background(), g)
		if findings[0].Status != core.StatusFail {
			t.Errorf("expected fail on array-form *:*, got %v", findings[0].Status)
		}
	})

	t.Run("deny star-star ignored", func(t *testing.T) {
		// A Deny with *:* is not the same problem (deny is restrictive).
		deny := `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`
		g := newUserGraph(map[string]any{
			"inline_policies": []map[string]any{{"name": "deny-all", "document": deny}},
		})
		findings, _ := NoStarInlinePolicies(context.Background(), g)
		if findings[0].Status != core.StatusPass {
			t.Errorf("Deny-*:* should pass, got %v: %s", findings[0].Status, findings[0].Message)
		}
	})
}
