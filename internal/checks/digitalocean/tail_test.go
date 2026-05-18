package digitalocean

import (
	"context"
	"testing"
	"time"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkCDN(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{ID: "digitalocean.cdn." + name, Type: docol.CDNType, Name: name, Provider: "digitalocean", Attributes: attrs}
}

func mkRIP(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{ID: "digitalocean.reserved_ip." + name, Type: docol.ReservedIPType, Name: name, Provider: "digitalocean", Attributes: attrs}
}

func mkSSH(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{ID: "digitalocean.ssh_key." + name, Type: docol.SSHKeyType, Name: name, Provider: "digitalocean", Attributes: attrs}
}

func mkImg(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{ID: "digitalocean.image." + name, Type: docol.ImageType, Name: name, Provider: "digitalocean", Attributes: attrs}
}

func mkAlert(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{ID: "digitalocean.alert_policy." + name, Type: docol.AlertPolicyType, Name: name, Provider: "digitalocean", Attributes: attrs}
}

func mkProj(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{ID: "digitalocean.project." + name, Type: docol.ProjectType, Name: name, Provider: "digitalocean", Attributes: attrs}
}

func TestCDNHasCustomDomain(t *testing.T) {
	g := newAccountGraph(
		mkCDN("on", map[string]any{"has_custom_domain": true}),
		mkCDN("off", map[string]any{"has_custom_domain": false}),
	)
	f, _ := CDNHasCustomDomain(context.Background(), g)
	if f[0].Status != compliancekit.StatusPass || f[1].Status != compliancekit.StatusFail {
		t.Errorf("got %v / %v", f[0].Status, f[1].Status)
	}
}

func TestCDNHasCustomCert(t *testing.T) {
	g := newAccountGraph(
		mkCDN("withcert", map[string]any{"has_custom_domain": true, "has_custom_cert": true}),
		mkCDN("nocert", map[string]any{"has_custom_domain": true, "has_custom_cert": false}),
		mkCDN("nodomain", map[string]any{"has_custom_domain": false}),
	)
	f, _ := CDNHasCustomCert(context.Background(), g)
	if len(f) != 2 {
		t.Fatalf("want 2 (no-domain skipped), got %d", len(f))
	}
}

func TestReservedIPOrphan(t *testing.T) {
	g := newAccountGraph(
		mkRIP("attached", map[string]any{"attached": true}),
		mkRIP("orphan", map[string]any{"attached": false}),
	)
	f, _ := ReservedIPOrphan(context.Background(), g)
	if f[0].Status != compliancekit.StatusPass || f[1].Status != compliancekit.StatusFail {
		t.Errorf("got %v / %v", f[0].Status, f[1].Status)
	}
}

func TestReservedIPInProject(t *testing.T) {
	g := newAccountGraph(
		mkRIP("in", map[string]any{"project_id": "p-1"}),
		mkRIP("none", map[string]any{"project_id": ""}),
	)
	f, _ := ReservedIPInProject(context.Background(), g)
	if f[0].Status != compliancekit.StatusPass || f[1].Status != compliancekit.StatusFail {
		t.Errorf("got %v / %v", f[0].Status, f[1].Status)
	}
}

func TestSSHKeyAlgorithm(t *testing.T) {
	g := newAccountGraph(
		mkSSH("ed25519", map[string]any{"algorithm": "ssh-ed25519", "is_weak_algo": false}),
		mkSSH("rsa-weak", map[string]any{"algorithm": "ssh-rsa", "is_weak_algo": true}),
	)
	f, _ := SSHKeyAlgorithm(context.Background(), g)
	if f[0].Status != compliancekit.StatusPass || f[1].Status != compliancekit.StatusFail {
		t.Errorf("got %v / %v", f[0].Status, f[1].Status)
	}
}

func TestSSHKeyCount(t *testing.T) {
	// Build 25 keys; should fail
	resources := []compliancekit.Resource{mkAccount("a", map[string]any{})}
	for i := 0; i < 25; i++ {
		resources = append(resources, mkSSH("k"+string(rune('a'+i)), map[string]any{}))
	}
	g := newAccountGraph(resources...)
	f, _ := SSHKeyCount(context.Background(), g)
	if f[0].Status != compliancekit.StatusFail {
		t.Errorf("got %v, want fail", f[0].Status)
	}
}

func TestImageNotPublic(t *testing.T) {
	g := newAccountGraph(
		mkImg("private", map[string]any{"public": false}),
		mkImg("public", map[string]any{"public": true}),
	)
	f, _ := ImageNotPublic(context.Background(), g)
	if f[0].Status != compliancekit.StatusPass || f[1].Status != compliancekit.StatusFail {
		t.Errorf("got %v / %v", f[0].Status, f[1].Status)
	}
}

func TestImageAge(t *testing.T) {
	now := time.Now().UTC()
	g := newAccountGraph(
		mkImg("fresh", map[string]any{"created_at": now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)}),
		mkImg("old", map[string]any{"created_at": now.Add(-400 * 24 * time.Hour).Format(time.RFC3339)}),
	)
	f, _ := ImageAge(context.Background(), g)
	if f[0].Status != compliancekit.StatusPass || f[1].Status != compliancekit.StatusFail {
		t.Errorf("got %v / %v", f[0].Status, f[1].Status)
	}
}

func TestAccountHasAlerts(t *testing.T) {
	g := newAccountGraph(
		mkAccount("a", map[string]any{}),
		mkAlert("cpu", map[string]any{"enabled": true}),
	)
	f, _ := AccountHasAlerts(context.Background(), g)
	if f[0].Status != compliancekit.StatusPass {
		t.Errorf("got %v", f[0].Status)
	}
}

func TestAlertEnabled(t *testing.T) {
	g := newAccountGraph(
		mkAlert("on", map[string]any{"enabled": true}),
		mkAlert("off", map[string]any{"enabled": false}),
	)
	f, _ := AlertEnabled(context.Background(), g)
	if f[0].Status != compliancekit.StatusPass || f[1].Status != compliancekit.StatusFail {
		t.Errorf("got %v / %v", f[0].Status, f[1].Status)
	}
}

func TestProjectEnvironmentSet(t *testing.T) {
	g := newAccountGraph(
		mkProj("set", map[string]any{"environment": "Production"}),
		mkProj("unset", map[string]any{"environment": ""}),
	)
	f, _ := ProjectEnvironmentSet(context.Background(), g)
	if f[0].Status != compliancekit.StatusPass || f[1].Status != compliancekit.StatusFail {
		t.Errorf("got %v / %v", f[0].Status, f[1].Status)
	}
}

func TestProjectDefaultDescription(t *testing.T) {
	g := newAccountGraph(
		mkProj("described", map[string]any{"is_default": true, "description": "catch-all"}),
		mkProj("nondefault", map[string]any{"is_default": false, "description": ""}),
		mkProj("default-empty", map[string]any{"is_default": true, "description": ""}),
	)
	f, _ := ProjectDefaultDescription(context.Background(), g)
	// non-default projects are skipped
	if len(f) != 2 {
		t.Fatalf("got %d findings, want 2", len(f))
	}
}
