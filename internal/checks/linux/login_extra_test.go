package linux

import (
	"context"
	"testing"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

func loginHost(name string, ld linuxcol.LoginDefs) core.Resource {
	return core.Resource{
		ID: "linux.host." + name, Type: linuxcol.HostType, Name: name, Provider: "linux",
		Attributes: map[string]any{
			"reachable":  true,
			"login_defs": ld,
		},
	}
}

func TestPassMaxDays(t *testing.T) {
	cases := []struct {
		name string
		ld   linuxcol.LoginDefs
		want core.Status
	}{
		{"in range", linuxcol.LoginDefs{HasPassMaxDays: true, PassMaxDays: 90}, core.StatusPass},
		{"too long", linuxcol.LoginDefs{HasPassMaxDays: true, PassMaxDays: 400}, core.StatusFail},
		{"unset", linuxcol.LoginDefs{}, core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraph(t, loginHost("h", c.ld))
			findings, _ := PassMaxDays(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestEncryptMethod(t *testing.T) {
	cases := []struct {
		method string
		want   core.Status
	}{
		{"SHA512", core.StatusPass},
		{"YESCRYPT", core.StatusPass},
		{"MD5", core.StatusFail},
		{"", core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			g := newGraph(t, loginHost("h", linuxcol.LoginDefs{EncryptMethod: c.method}))
			findings, _ := EncryptMethod(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestUmaskCheck(t *testing.T) {
	cases := []struct {
		umask string
		want  core.Status
	}{
		{"027", core.StatusPass},
		{"077", core.StatusPass},
		{"022", core.StatusFail},
		{"000", core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.umask, func(t *testing.T) {
			g := newGraph(t, loginHost("h", linuxcol.LoginDefs{HasUmask: true, Umask: c.umask}))
			findings, _ := UmaskCheck(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v (umask=%s)", findings[0].Status, c.want, c.umask)
			}
		})
	}
}

func TestManualLoginChecks(t *testing.T) {
	host := core.Resource{
		ID: "linux.host.h", Type: linuxcol.HostType, Name: "h", Provider: "linux",
		Attributes: map[string]any{"reachable": true},
	}
	g := newGraph(t, host)
	for _, spec := range manualLoginChecks {
		t.Run(spec.id, func(t *testing.T) {
			fn, ok := core.Lookup(spec.id)
			if !ok {
				t.Fatalf("check %q not registered", spec.id)
			}
			findings, _ := fn(context.Background(), g)
			if findings[0].Status != core.StatusError {
				t.Errorf("status=%v want StatusError (manual-verify)", findings[0].Status)
			}
		})
	}
}
