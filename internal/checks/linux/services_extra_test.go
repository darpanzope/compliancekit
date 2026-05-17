package linux

import (
	"context"
	"testing"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

func servicesHost(name string, svc linuxcol.ServiceFacts) core.Resource {
	return core.Resource{
		ID:       "linux.host." + name,
		Type:     linuxcol.HostType,
		Name:     name,
		Provider: "linux",
		Attributes: map[string]any{
			"reachable": true,
			"services":  svc,
		},
	}
}

func TestServiceMustRun_PassFail(t *testing.T) {
	good := linuxcol.ServiceFacts{Enabled: []string{"chronyd.service"}, Active: []string{"chronyd.service"}}
	bad := linuxcol.ServiceFacts{Enabled: []string{}, Active: []string{}}
	g := newGraph(t, servicesHost("good", good), servicesHost("bad", bad))
	fn, _ := core.Lookup("linux-service-time-sync-active")
	findings, _ := fn(context.Background(), g)
	by := map[string]core.Status{}
	for _, f := range findings {
		by[f.Resource.Name] = f.Status
	}
	if by["good"] != core.StatusPass || by["bad"] != core.StatusFail {
		t.Errorf("statuses=%+v", by)
	}
}

func TestServiceMustNotRun_PassFail(t *testing.T) {
	clean := linuxcol.ServiceFacts{Enabled: []string{}, Active: []string{}}
	dirty := linuxcol.ServiceFacts{Enabled: []string{"avahi-daemon.service"}, Active: []string{"avahi-daemon.service"}}
	g := newGraph(t, servicesHost("clean", clean), servicesHost("dirty", dirty))
	fn, _ := core.Lookup("linux-service-avahi-disabled")
	findings, _ := fn(context.Background(), g)
	by := map[string]core.Status{}
	for _, f := range findings {
		by[f.Resource.Name] = f.Status
	}
	if by["clean"] != core.StatusPass || by["dirty"] != core.StatusFail {
		t.Errorf("statuses=%+v", by)
	}
}

func TestServiceMustAbsent_PassFail(t *testing.T) {
	clean := linuxcol.ServiceFacts{}
	dirty := linuxcol.ServiceFacts{Enabled: []string{"telnetd.service"}}
	g := newGraph(t, servicesHost("clean", clean), servicesHost("dirty", dirty))
	fn, _ := core.Lookup("linux-service-telnet-absent")
	findings, _ := fn(context.Background(), g)
	by := map[string]core.Status{}
	for _, f := range findings {
		by[f.Resource.Name] = f.Status
	}
	if by["clean"] != core.StatusPass || by["dirty"] != core.StatusFail {
		t.Errorf("statuses=%+v", by)
	}
}

func TestService_SkipsWhenServicesAttrMissing(t *testing.T) {
	host := core.Resource{
		ID: "linux.host.h", Type: linuxcol.HostType, Name: "h", Provider: "linux",
		Attributes: map[string]any{"reachable": true},
	}
	g := newGraph(t, host)
	fn, _ := core.Lookup("linux-service-time-sync-active")
	findings, _ := fn(context.Background(), g)
	if findings[0].Status != core.StatusSkip {
		t.Errorf("status=%v want StatusSkip on non-systemd host", findings[0].Status)
	}
}

func TestServiceSpecsCoverage(t *testing.T) {
	total := len(serviceMustRunSpecs) + len(serviceMustNotRunSpecs) + len(serviceMustAbsentSpecs)
	if total != 10 {
		t.Errorf("v0.20 phase 4 expects 10 service checks; got %d", total)
	}
}
