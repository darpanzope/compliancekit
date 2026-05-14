package gcp

import (
	"context"
	"testing"
	"time"

	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	"github.com/darpanzope/compliancekit/internal/core"
)

func newGraphWith(resources ...core.Resource) *core.ResourceGraph {
	g := core.NewResourceGraph()
	for _, r := range resources {
		g.Add(r)
	}
	return g
}

func mkPolicy(name string, bindings []map[string]any, auditConfigs []map[string]any) core.Resource {
	return core.Resource{
		ID:       "gcp.iam.policy." + name,
		Type:     gcpcol.IAMPolicyType,
		Name:     name,
		Provider: "gcp",
		Attributes: map[string]any{
			"bindings":      bindings,
			"audit_configs": auditConfigs,
		},
	}
}

func mkSA(email string, isDefault, disabled bool, userKeyCount int, keys []map[string]any) core.Resource {
	return core.Resource{
		ID:       "gcp.iam.service_account." + email,
		Type:     gcpcol.ServiceAccountType,
		Name:     email,
		Provider: "gcp",
		Attributes: map[string]any{
			"is_default":             isDefault,
			"disabled":               disabled,
			"user_managed_key_count": userKeyCount,
			"keys":                   keys,
		},
	}
}

// ============ NoPrimitiveRoles ============

func TestNoPrimitiveRoles(t *testing.T) {
	t.Run("clean", func(t *testing.T) {
		policy := mkPolicy("p1", []map[string]any{
			{"role": "roles/storage.objectAdmin", "members": []string{"user:alice@x.com"}},
		}, nil)
		findings, _ := NoPrimitiveRoles(context.Background(), newGraphWith(policy))
		if findings[0].Status != core.StatusPass {
			t.Errorf("got %v", findings[0].Status)
		}
	})
	t.Run("editor present", func(t *testing.T) {
		policy := mkPolicy("p1", []map[string]any{
			{"role": "roles/editor", "members": []string{"user:bob@x.com"}},
		}, nil)
		findings, _ := NoPrimitiveRoles(context.Background(), newGraphWith(policy))
		if findings[0].Status != core.StatusFail {
			t.Errorf("got %v: %s", findings[0].Status, findings[0].Message)
		}
	})
}

// ============ NoBroadTokenCreator ============

func TestNoBroadTokenCreator(t *testing.T) {
	t.Run("clean", func(t *testing.T) {
		policy := mkPolicy("p1", []map[string]any{
			{"role": "roles/viewer", "members": []string{"user:alice@x.com"}},
		}, nil)
		findings, _ := NoBroadTokenCreator(context.Background(), newGraphWith(policy))
		if findings[0].Status != core.StatusPass {
			t.Errorf("got %v", findings[0].Status)
		}
	})
	t.Run("token creator at project", func(t *testing.T) {
		policy := mkPolicy("p1", []map[string]any{
			{"role": "roles/iam.serviceAccountTokenCreator", "members": []string{"user:bob@x.com"}},
		}, nil)
		findings, _ := NoBroadTokenCreator(context.Background(), newGraphWith(policy))
		if findings[0].Status != core.StatusFail {
			t.Errorf("got %v", findings[0].Status)
		}
	})
}

// ============ CloudAuditLogging ============

func TestCloudAuditLogging(t *testing.T) {
	t.Run("no config", func(t *testing.T) {
		policy := mkPolicy("p1", nil, nil)
		findings, _ := CloudAuditLogging(context.Background(), newGraphWith(policy))
		if findings[0].Status != core.StatusFail {
			t.Errorf("got %v", findings[0].Status)
		}
	})
	t.Run("missing one type", func(t *testing.T) {
		policy := mkPolicy("p1", nil, []map[string]any{
			{"service": "allServices", "audit_log_configs": []map[string]any{
				{"log_type": "ADMIN_READ"},
				{"log_type": "DATA_READ"},
			}},
		})
		findings, _ := CloudAuditLogging(context.Background(), newGraphWith(policy))
		if findings[0].Status != core.StatusFail {
			t.Errorf("got %v: %s", findings[0].Status, findings[0].Message)
		}
	})
	t.Run("all three", func(t *testing.T) {
		policy := mkPolicy("p1", nil, []map[string]any{
			{"service": "allServices", "audit_log_configs": []map[string]any{
				{"log_type": "ADMIN_READ"},
				{"log_type": "DATA_READ"},
				{"log_type": "DATA_WRITE"},
			}},
		})
		findings, _ := CloudAuditLogging(context.Background(), newGraphWith(policy))
		if findings[0].Status != core.StatusPass {
			t.Errorf("got %v: %s", findings[0].Status, findings[0].Message)
		}
	})
}

// ============ SAKeyAge ============

func TestSAKeyAge(t *testing.T) {
	now := time.Now().UTC()
	t.Run("no keys", func(t *testing.T) {
		sa := mkSA("svc@x.iam.gserviceaccount.com", false, false, 0, nil)
		findings, _ := SAKeyAge(context.Background(), newGraphWith(sa))
		if findings[0].Status != core.StatusPass {
			t.Errorf("got %v", findings[0].Status)
		}
	})
	t.Run("fresh user-managed key", func(t *testing.T) {
		sa := mkSA("svc@x.iam.gserviceaccount.com", false, false, 1, []map[string]any{
			{"key_type": "USER_MANAGED", "valid_after_time": now.Add(-10 * 24 * time.Hour), "name": "p/k/foo"},
		})
		findings, _ := SAKeyAge(context.Background(), newGraphWith(sa))
		if findings[0].Status != core.StatusPass {
			t.Errorf("got %v: %s", findings[0].Status, findings[0].Message)
		}
	})
	t.Run("stale user-managed key", func(t *testing.T) {
		sa := mkSA("svc@x.iam.gserviceaccount.com", false, false, 1, []map[string]any{
			{"key_type": "USER_MANAGED", "valid_after_time": now.Add(-180 * 24 * time.Hour), "name": "p/k/bar"},
		})
		findings, _ := SAKeyAge(context.Background(), newGraphWith(sa))
		if findings[0].Status != core.StatusFail {
			t.Errorf("got %v: %s", findings[0].Status, findings[0].Message)
		}
	})
	t.Run("system-managed key ignored", func(t *testing.T) {
		sa := mkSA("svc@x.iam.gserviceaccount.com", false, false, 0, []map[string]any{
			{"key_type": "SYSTEM_MANAGED", "valid_after_time": now.Add(-1000 * 24 * time.Hour), "name": "p/k/sys"},
		})
		findings, _ := SAKeyAge(context.Background(), newGraphWith(sa))
		if findings[0].Status != core.StatusPass {
			t.Errorf("got %v", findings[0].Status)
		}
	})
}

// ============ NoUserManagedSAKeys ============

func TestNoUserManagedSAKeys(t *testing.T) {
	t.Run("no user-managed keys", func(t *testing.T) {
		sa := mkSA("svc@x.iam.gserviceaccount.com", false, false, 0, nil)
		findings, _ := NoUserManagedSAKeys(context.Background(), newGraphWith(sa))
		if findings[0].Status != core.StatusPass {
			t.Errorf("got %v", findings[0].Status)
		}
	})
	t.Run("one user-managed key", func(t *testing.T) {
		sa := mkSA("svc@x.iam.gserviceaccount.com", false, false, 1, nil)
		findings, _ := NoUserManagedSAKeys(context.Background(), newGraphWith(sa))
		if findings[0].Status != core.StatusFail {
			t.Errorf("got %v", findings[0].Status)
		}
	})
}

// ============ NoDefaultSAInUse ============

func TestNoDefaultSAInUse(t *testing.T) {
	t.Run("custom SA passes", func(t *testing.T) {
		sa := mkSA("svc@x.iam.gserviceaccount.com", false, false, 0, nil)
		findings, _ := NoDefaultSAInUse(context.Background(), newGraphWith(sa))
		if findings[0].Status != core.StatusPass {
			t.Errorf("got %v", findings[0].Status)
		}
	})
	t.Run("default compute SA fails when active", func(t *testing.T) {
		sa := mkSA("123-compute@developer.gserviceaccount.com", true, false, 0, nil)
		findings, _ := NoDefaultSAInUse(context.Background(), newGraphWith(sa))
		if findings[0].Status != core.StatusFail {
			t.Errorf("got %v: %s", findings[0].Status, findings[0].Message)
		}
	})
	t.Run("default SA disabled passes", func(t *testing.T) {
		sa := mkSA("123-compute@developer.gserviceaccount.com", true, true, 0, nil)
		findings, _ := NoDefaultSAInUse(context.Background(), newGraphWith(sa))
		if findings[0].Status != core.StatusPass {
			t.Errorf("got %v", findings[0].Status)
		}
	})
}
