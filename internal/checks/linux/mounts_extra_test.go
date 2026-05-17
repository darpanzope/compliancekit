package linux

import (
	"context"
	"testing"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.20 phase 3 — tests for the mount-separate + mount-option check
// framework. One canonical pass/fail per shape covers every spec by
// induction; per-distro fixture coverage lands in Phase 11.

func mountsHost(name string, mounts []linuxcol.MountEntry) core.Resource {
	return core.Resource{
		ID:       "linux.host." + name,
		Type:     linuxcol.HostType,
		Name:     name,
		Provider: "linux",
		Attributes: map[string]any{
			"reachable": true,
			"mounts":    mounts,
		},
	}
}

func TestMountSeparate_PassFail(t *testing.T) {
	withTmp := []linuxcol.MountEntry{
		{Source: "tmpfs", Target: "/tmp", FSType: "tmpfs", Options: []string{"rw", "nodev"}},
		{Source: "/dev/sda1", Target: "/", FSType: "ext4", Options: []string{"rw"}},
	}
	withoutTmp := []linuxcol.MountEntry{
		{Source: "/dev/sda1", Target: "/", FSType: "ext4", Options: []string{"rw"}},
	}
	g := newGraph(t,
		mountsHost("good", withTmp),
		mountsHost("bad", withoutTmp),
	)
	fn, _ := core.Lookup("linux-mount-tmp-separate")
	findings, _ := fn(context.Background(), g)
	by := map[string]core.Status{}
	for _, f := range findings {
		by[f.Resource.Name] = f.Status
	}
	if by["good"] != core.StatusPass || by["bad"] != core.StatusFail {
		t.Errorf("statuses=%+v", by)
	}
}

func TestMountOption_PassFailSkip(t *testing.T) {
	withNoexec := []linuxcol.MountEntry{
		{Target: "/tmp", FSType: "tmpfs", Options: []string{"rw", "nodev", "nosuid", "noexec"}},
	}
	withoutNoexec := []linuxcol.MountEntry{
		{Target: "/tmp", FSType: "tmpfs", Options: []string{"rw"}},
	}
	noTmpMount := []linuxcol.MountEntry{
		{Target: "/", FSType: "ext4", Options: []string{"rw"}},
	}
	g := newGraph(t,
		mountsHost("pass", withNoexec),
		mountsHost("fail", withoutNoexec),
		mountsHost("skip", noTmpMount),
	)
	fn, _ := core.Lookup("linux-mount-tmp-noexec")
	findings, _ := fn(context.Background(), g)
	by := map[string]core.Status{}
	for _, f := range findings {
		by[f.Resource.Name] = f.Status
	}
	if by["pass"] != core.StatusPass || by["fail"] != core.StatusFail || by["skip"] != core.StatusSkip {
		t.Errorf("statuses=%+v", by)
	}
}

func TestMountChecks_ErrorWhenMountsAttrMissing(t *testing.T) {
	host := core.Resource{
		ID: "linux.host.h", Type: linuxcol.HostType, Name: "h", Provider: "linux",
		Attributes: map[string]any{"reachable": true},
	}
	g := newGraph(t, host)
	fn, _ := core.Lookup("linux-mount-tmp-separate")
	findings, _ := fn(context.Background(), g)
	if findings[0].Status != core.StatusError {
		t.Errorf("status=%v want StatusError when mounts attr missing", findings[0].Status)
	}
}

func TestMountSpecCoverage(t *testing.T) {
	if got := len(mountSeparateSpecs) + len(mountOptionSpecs); got != 15 {
		t.Errorf("v0.20 phase 3 expects 15 mount checks; got %d", got)
	}
}
