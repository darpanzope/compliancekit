package linux

import (
	"context"
	"strings"
	"testing"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.20 phase 1 — tests for the distro-allowlist check.

func distroHost(name string, attrs map[string]any) core.Resource {
	attrs["reachable"] = true
	return core.Resource{
		ID:         "linux.host." + name,
		Type:       linuxcol.HostType,
		Name:       name,
		Provider:   "linux",
		Attributes: attrs,
	}
}

func TestDistroSupported(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		want  core.Status
		hint  string
	}{
		{"ubuntu passes", map[string]any{"distro_id": "ubuntu", "distro_pretty_name": "Ubuntu 22.04"}, core.StatusPass, "ubuntu"},
		{"rhel passes", map[string]any{"distro_id": "rhel", "distro_pretty_name": "RHEL 9"}, core.StatusPass, "rhel"},
		{"alpine passes", map[string]any{"distro_id": "alpine", "distro_pretty_name": "Alpine 3.19"}, core.StatusPass, "alpine"},
		{"unsupported fails", map[string]any{"distro_id": "freebsd", "distro_pretty_name": "FreeBSD 14"}, core.StatusFail, "NOT on"},
		{"missing distro_id → error", map[string]any{"os_release_error": "ssh: timeout"}, core.StatusError, "os-release"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraph(t, distroHost("h", c.attrs))
			findings, _ := DistroSupported(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v", findings[0].Status, c.want)
			}
			if !strings.Contains(strings.ToLower(findings[0].Message), strings.ToLower(c.hint)) {
				t.Errorf("message %q missing %q", findings[0].Message, c.hint)
			}
		})
	}
}

func TestDistroSupported_Unreachable(t *testing.T) {
	unreach := core.Resource{
		ID: "linux.host.dead", Type: linuxcol.HostType, Name: "dead", Provider: "linux",
		Attributes: map[string]any{"reachable": false, "unreachable_reason": "dial: timeout"},
	}
	g := newGraph(t, unreach)
	findings, _ := DistroSupported(context.Background(), g)
	if findings[0].Status != core.StatusSkip {
		t.Errorf("status=%v want StatusSkip", findings[0].Status)
	}
}
