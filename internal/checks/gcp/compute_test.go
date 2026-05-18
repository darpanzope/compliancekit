package gcp

import (
	"context"
	"testing"

	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkNet(name string, isDefault bool) compliancekit.Resource {
	return compliancekit.Resource{
		ID: "gcp.compute.network." + name, Type: gcpcol.ComputeNetworkType, Name: name, Provider: "gcp",
		Attributes: map[string]any{"is_default": isDefault},
	}
}

func mkFW(name string, direction string, disabled, openToAny bool, allowed []map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID: "gcp.compute.firewall." + name, Type: gcpcol.ComputeFirewallType, Name: name, Provider: "gcp",
		Attributes: map[string]any{
			"direction":   direction,
			"disabled":    disabled,
			"open_to_any": openToAny,
			"allowed":     allowed,
		},
	}
}

func mkProjectMD(name string, osLogin bool) compliancekit.Resource {
	return compliancekit.Resource{
		ID: "gcp.compute.project_metadata." + name, Type: gcpcol.ComputeProjectType, Name: name, Provider: "gcp",
		Attributes: map[string]any{"os_login_enabled": osLogin},
	}
}

func mkInstance(name string, status string, sb, vtpm, im bool, sas []map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID: "gcp.compute.instance." + name, Type: gcpcol.ComputeInstanceType, Name: name, Provider: "gcp",
		Attributes: map[string]any{
			"status":                        status,
			"shielded_secure_boot":          sb,
			"shielded_vtpm":                 vtpm,
			"shielded_integrity_monitoring": im,
			"service_accounts":              sas,
		},
	}
}

func TestNoDefaultNetwork(t *testing.T) {
	g := newGraphWith(mkNet("default", true), mkNet("custom-vpc", false))
	findings, _ := NoDefaultNetwork(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "default" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestNoSSHFromAny(t *testing.T) {
	type tc struct {
		name string
		fw   compliancekit.Resource
		want compliancekit.Status
	}
	tcs := []tc{
		{"egress passes", mkFW("egress-22", "EGRESS", false, true, []map[string]any{
			{"protocol": "tcp", "ports": []string{"22"}},
		}), compliancekit.StatusPass},
		{"disabled passes", mkFW("disabled", "INGRESS", true, true, []map[string]any{
			{"protocol": "tcp", "ports": []string{"22"}},
		}), compliancekit.StatusPass},
		{"not open to any passes", mkFW("scoped", "INGRESS", false, false, []map[string]any{
			{"protocol": "tcp", "ports": []string{"22"}},
		}), compliancekit.StatusPass},
		{"open ssh fails", mkFW("ssh-open", "INGRESS", false, true, []map[string]any{
			{"protocol": "tcp", "ports": []string{"22"}},
		}), compliancekit.StatusFail},
		{"open all-tcp empty fails", mkFW("all-tcp", "INGRESS", false, true, []map[string]any{
			{"protocol": "tcp", "ports": []string{}},
		}), compliancekit.StatusFail},
		{"range covers 22 fails", mkFW("range", "INGRESS", false, true, []map[string]any{
			{"protocol": "tcp", "ports": []string{"20-30"}},
		}), compliancekit.StatusFail},
		{"open http only passes", mkFW("http", "INGRESS", false, true, []map[string]any{
			{"protocol": "tcp", "ports": []string{"80", "443"}},
		}), compliancekit.StatusPass},
	}
	for _, c := range tcs {
		t.Run(c.name, func(t *testing.T) {
			findings, _ := NoSSHFromAny(context.Background(), newGraphWith(c.fw))
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestOSLoginEnabled(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		findings, _ := OSLoginEnabled(context.Background(), newGraphWith(mkProjectMD("p1", true)))
		if findings[0].Status != compliancekit.StatusPass {
			t.Errorf("got %v", findings[0].Status)
		}
	})
	t.Run("disabled", func(t *testing.T) {
		findings, _ := OSLoginEnabled(context.Background(), newGraphWith(mkProjectMD("p1", false)))
		if findings[0].Status != compliancekit.StatusFail {
			t.Errorf("got %v", findings[0].Status)
		}
	})
}

func TestShieldedVM(t *testing.T) {
	cases := []struct {
		name           string
		status         string
		sb, vtpm, im   bool
		expectedCount  int
		expectedStatus compliancekit.Status
	}{
		{"running all on", "RUNNING", true, true, true, 1, compliancekit.StatusPass},
		{"running partial", "RUNNING", true, false, true, 1, compliancekit.StatusFail},
		{"running none", "RUNNING", false, false, false, 1, compliancekit.StatusFail},
		{"stopped skipped", "STOPPED", false, false, false, 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inst := mkInstance("inst1", c.status, c.sb, c.vtpm, c.im, nil)
			findings, _ := ShieldedVM(context.Background(), newGraphWith(inst))
			if len(findings) != c.expectedCount {
				t.Fatalf("got %d findings, want %d", len(findings), c.expectedCount)
			}
			if c.expectedCount > 0 && findings[0].Status != c.expectedStatus {
				t.Errorf("got %v, want %v", findings[0].Status, c.expectedStatus)
			}
		})
	}
}

func TestNoBroadScopes(t *testing.T) {
	t.Run("no sa passes", func(t *testing.T) {
		inst := mkInstance("inst1", "RUNNING", true, true, true, []map[string]any{})
		findings, _ := NoBroadScopes(context.Background(), newGraphWith(inst))
		if findings[0].Status != compliancekit.StatusPass {
			t.Errorf("got %v", findings[0].Status)
		}
	})
	t.Run("scoped passes", func(t *testing.T) {
		inst := mkInstance("inst1", "RUNNING", true, true, true, []map[string]any{
			{"email": "sa@x.iam.gserviceaccount.com", "scopes": []string{"https://www.googleapis.com/auth/logging.write"}},
		})
		findings, _ := NoBroadScopes(context.Background(), newGraphWith(inst))
		if findings[0].Status != compliancekit.StatusPass {
			t.Errorf("got %v", findings[0].Status)
		}
	})
	t.Run("cloud-platform fails", func(t *testing.T) {
		inst := mkInstance("inst1", "RUNNING", true, true, true, []map[string]any{
			{"email": "sa@x.iam.gserviceaccount.com", "scopes": []string{"https://www.googleapis.com/auth/cloud-platform"}},
		})
		findings, _ := NoBroadScopes(context.Background(), newGraphWith(inst))
		if findings[0].Status != compliancekit.StatusFail {
			t.Errorf("got %v", findings[0].Status)
		}
	})
}
