package linux

import (
	"context"
	"testing"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func loginHost(name string, ld linuxcol.LoginDefs) compliancekit.Resource {
	return compliancekit.Resource{
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
		want compliancekit.Status
	}{
		{"in range", linuxcol.LoginDefs{HasPassMaxDays: true, PassMaxDays: 90}, compliancekit.StatusPass},
		{"too long", linuxcol.LoginDefs{HasPassMaxDays: true, PassMaxDays: 400}, compliancekit.StatusFail},
		{"unset", linuxcol.LoginDefs{}, compliancekit.StatusFail},
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

func TestPassMinDays(t *testing.T) {
	cases := []struct {
		name string
		ld   linuxcol.LoginDefs
		want compliancekit.Status
	}{
		{"7 days → pass", linuxcol.LoginDefs{HasPassMinDays: true, PassMinDays: 7}, compliancekit.StatusPass},
		{"1 day → pass (boundary)", linuxcol.LoginDefs{HasPassMinDays: true, PassMinDays: 1}, compliancekit.StatusPass},
		{"0 days → fail (must be ≥1)", linuxcol.LoginDefs{HasPassMinDays: true, PassMinDays: 0}, compliancekit.StatusFail},
		{"unset → fail", linuxcol.LoginDefs{}, compliancekit.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraph(t, loginHost("h", c.ld))
			findings, _ := PassMinDays(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestPassWarnAge(t *testing.T) {
	cases := []struct {
		name string
		ld   linuxcol.LoginDefs
		want compliancekit.Status
	}{
		{"14 days → pass", linuxcol.LoginDefs{HasPassWarnAge: true, PassWarnAge: 14}, compliancekit.StatusPass},
		{"7 days → pass (boundary)", linuxcol.LoginDefs{HasPassWarnAge: true, PassWarnAge: 7}, compliancekit.StatusPass},
		{"3 days → fail (must be ≥7)", linuxcol.LoginDefs{HasPassWarnAge: true, PassWarnAge: 3}, compliancekit.StatusFail},
		{"unset → fail", linuxcol.LoginDefs{}, compliancekit.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraph(t, loginHost("h", c.ld))
			findings, _ := PassWarnAge(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestLoginDefsUnreadable_AllReturnError(t *testing.T) {
	// Host without login_defs attr → every login-defs check should
	// surface StatusError so operators know data collection failed.
	host := compliancekit.Resource{
		ID: "linux.host.h", Type: linuxcol.HostType, Name: "h", Provider: "linux",
		Attributes: map[string]any{"reachable": true},
	}
	g := newGraph(t, host)
	for _, fn := range []compliancekit.CheckFunc{PassMaxDays, PassMinDays, PassWarnAge, EncryptMethod, UmaskCheck} {
		findings, _ := fn(context.Background(), g)
		if findings[0].Status != compliancekit.StatusError {
			t.Errorf("status=%v want StatusError when login_defs absent", findings[0].Status)
		}
	}
}

func TestEncryptMethod(t *testing.T) {
	cases := []struct {
		method string
		want   compliancekit.Status
	}{
		{"SHA512", compliancekit.StatusPass},
		{"YESCRYPT", compliancekit.StatusPass},
		{"MD5", compliancekit.StatusFail},
		{"", compliancekit.StatusFail},
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
		want  compliancekit.Status
	}{
		{"027", compliancekit.StatusPass},
		{"077", compliancekit.StatusPass},
		{"022", compliancekit.StatusFail},
		{"000", compliancekit.StatusFail},
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
	host := compliancekit.Resource{
		ID: "linux.host.h", Type: linuxcol.HostType, Name: "h", Provider: "linux",
		Attributes: map[string]any{"reachable": true},
	}
	g := newGraph(t, host)
	for _, spec := range manualLoginChecks {
		t.Run(spec.id, func(t *testing.T) {
			fn, ok := compliancekit.Lookup(spec.id)
			if !ok {
				t.Fatalf("check %q not registered", spec.id)
			}
			findings, _ := fn(context.Background(), g)
			if findings[0].Status != compliancekit.StatusError {
				t.Errorf("status=%v want StatusError (manual-verify)", findings[0].Status)
			}
		})
	}
}
