package linux

import (
	"context"
	"testing"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 11 — coverage for the distro-gated SELinux/AppArmor
// checks. Each runs only when the host's os_release falls in the
// matching family; non-family hosts get StatusSkip.

func hostWithMAC(name string, rel linuxcol.OSRelease, mac linuxcol.MACFacts) compliancekit.Resource {
	return compliancekit.Resource{
		ID:       "linux.host." + name,
		Type:     linuxcol.HostType,
		Name:     name,
		Provider: "linux",
		Attributes: map[string]any{
			"reachable":  true,
			"os_release": rel,
			"mac":        mac,
		},
	}
}

func TestSELinuxEnforcing(t *testing.T) {
	rhel := linuxcol.OSRelease{ID: "rhel", VersionID: "9"}
	ubuntu := linuxcol.OSRelease{ID: "ubuntu", VersionID: "22.04"}
	cases := []struct {
		name string
		host compliancekit.Resource
		want compliancekit.Status
	}{
		{"RHEL + enforcing → pass", hostWithMAC("rhel-good", rhel, linuxcol.MACFacts{SELinuxMode: "enforcing"}), compliancekit.StatusPass},
		{"RHEL + permissive → fail", hostWithMAC("rhel-bad", rhel, linuxcol.MACFacts{SELinuxMode: "permissive"}), compliancekit.StatusFail},
		{"RHEL + disabled → fail", hostWithMAC("rhel-off", rhel, linuxcol.MACFacts{SELinuxMode: "disabled"}), compliancekit.StatusFail},
		{"RHEL + getenforce empty → error", hostWithMAC("rhel-nooutput", rhel, linuxcol.MACFacts{SELinuxMode: ""}), compliancekit.StatusError},
		{"Ubuntu → skip (N/A)", hostWithMAC("ubuntu", ubuntu, linuxcol.MACFacts{}), compliancekit.StatusSkip},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraph(t, c.host)
			findings, err := SELinuxEnforcing(context.Background(), g)
			if err != nil {
				t.Fatalf("SELinuxEnforcing: %v", err)
			}
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v (msg=%q)", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestAppArmorActive(t *testing.T) {
	ubuntu := linuxcol.OSRelease{ID: "ubuntu", VersionID: "22.04"}
	rhel := linuxcol.OSRelease{ID: "rhel", VersionID: "9"}
	cases := []struct {
		name string
		host compliancekit.Resource
		want compliancekit.Status
	}{
		{"Ubuntu + active + profiles → pass", hostWithMAC("u-good", ubuntu, linuxcol.MACFacts{AppArmorActive: true, AppArmorProfiles: 12}), compliancekit.StatusPass},
		{"Ubuntu + active + zero profiles → fail", hostWithMAC("u-noprof", ubuntu, linuxcol.MACFacts{AppArmorActive: true, AppArmorProfiles: 0}), compliancekit.StatusFail},
		{"Ubuntu + inactive → fail", hostWithMAC("u-off", ubuntu, linuxcol.MACFacts{AppArmorActive: false, AppArmorProfiles: 5}), compliancekit.StatusFail},
		{"RHEL → skip (N/A)", hostWithMAC("rhel", rhel, linuxcol.MACFacts{}), compliancekit.StatusSkip},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraph(t, c.host)
			findings, err := AppArmorActive(context.Background(), g)
			if err != nil {
				t.Fatalf("AppArmorActive: %v", err)
			}
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v (msg=%q)", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}
