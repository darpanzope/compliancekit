package digitalocean

import (
	"context"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.19 phase 3 — table tests for the 10 DNS-depth checks.

func TestDMARCParser(t *testing.T) {
	body := "v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:r@x.com; ruf=mailto:f@x.com"
	tags := parseDMARC(body)
	if tags["p"] != "quarantine" || tags["sp"] != "reject" || tags["pct"] != "50" {
		t.Errorf("parseDMARC=%+v", tags)
	}
	if tags["rua"] != "mailto:r@x.com" {
		t.Errorf("rua=%q", tags["rua"])
	}
}

func TestDomainDMARCPolicyStrict(t *testing.T) {
	cases := []struct {
		name  string
		dmarc string
		want  core.Status
	}{
		{"no dmarc", "", ""},
		{"p=none", "v=DMARC1; p=none", core.StatusFail},
		{"p=quarantine", "v=DMARC1; p=quarantine", core.StatusPass},
		{"p=reject", "v=DMARC1; p=reject", core.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			attrs := map[string]any{}
			if c.dmarc != "" {
				attrs["dmarc_records"] = []string{c.dmarc}
			}
			g := newAccountGraph(mkDomain("x.com", attrs))
			findings, _ := DomainDMARCPolicyStrict(context.Background(), g)
			if c.want == "" {
				if len(findings) != 0 {
					t.Errorf("expected no findings, got %d", len(findings))
				}
				return
			}
			if findings[0].Status != c.want {
				t.Errorf("status=%v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestDomainDMARCSubdomainPolicy(t *testing.T) {
	cases := []struct {
		name  string
		dmarc string
		want  core.Status
	}{
		{"sp set strict", "v=DMARC1; p=reject; sp=reject", core.StatusPass},
		{"sp=none", "v=DMARC1; p=reject; sp=none", core.StatusFail},
		{"sp absent", "v=DMARC1; p=reject", core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkDomain("x.com", map[string]any{"dmarc_records": []string{c.dmarc}}))
			findings, _ := DomainDMARCSubdomainPolicy(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestDomainDMARCPctFull(t *testing.T) {
	cases := []struct {
		name  string
		dmarc string
		want  core.Status
	}{
		{"pct omitted", "v=DMARC1; p=reject", core.StatusPass},
		{"pct=100", "v=DMARC1; p=reject; pct=100", core.StatusPass},
		{"pct=50", "v=DMARC1; p=reject; pct=50", core.StatusFail},
		{"pct=garbage", "v=DMARC1; p=reject; pct=abc", core.StatusError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkDomain("x.com", map[string]any{"dmarc_records": []string{c.dmarc}}))
			findings, _ := DomainDMARCPctFull(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestDomainDMARCReporting(t *testing.T) {
	g := newAccountGraph(mkDomain("x.com", map[string]any{
		"dmarc_records": []string{"v=DMARC1; p=reject; rua=mailto:r@x.com"},
	}))
	rua, _ := DomainDMARCRUAPresent(context.Background(), g)
	if rua[0].Status != core.StatusPass {
		t.Errorf("rua status=%v", rua[0].Status)
	}
	ruf, _ := DomainDMARCRUFPresent(context.Background(), g)
	if ruf[0].Status != core.StatusFail {
		t.Errorf("ruf missing should fail, got %v", ruf[0].Status)
	}
}

func TestDomainSPFStrictAll(t *testing.T) {
	cases := []struct {
		name string
		spf  string
		want core.Status
	}{
		{"-all", "v=spf1 include:_spf.google.com -all", core.StatusPass},
		{"~all", "v=spf1 include:_spf.google.com ~all", core.StatusFail},
		{"?all", "v=spf1 include:_spf.google.com ?all", core.StatusFail},
		{"+all (open relay)", "v=spf1 +all", core.StatusFail},
		{"missing all", "v=spf1 include:_spf.google.com", core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkDomain("x.com", map[string]any{"spf_records": []string{c.spf}}))
			findings, _ := DomainSPFStrictAll(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v (spf=%q)", findings[0].Status, c.want, c.spf)
			}
		})
	}
}

func TestDomainSPFNoRedirect(t *testing.T) {
	pass := newAccountGraph(mkDomain("x.com", map[string]any{"spf_records": []string{"v=spf1 include:_spf.google.com -all"}}))
	fail := newAccountGraph(mkDomain("y.com", map[string]any{"spf_records": []string{"v=spf1 redirect=other.com"}}))
	p, _ := DomainSPFNoRedirect(context.Background(), pass)
	f, _ := DomainSPFNoRedirect(context.Background(), fail)
	if p[0].Status != core.StatusPass || f[0].Status != core.StatusFail {
		t.Errorf("pass=%v fail=%v", p[0].Status, f[0].Status)
	}
}

func TestDomainDKIMSelectorPresent(t *testing.T) {
	cases := []struct {
		name      string
		attrs     map[string]any
		expectN   int
		wantFirst core.Status
	}{
		{"no MX → skip", map[string]any{"has_mx": false}, 0, ""},
		{"MX no DKIM", map[string]any{"has_mx": true, "dkim_selectors": []string{}}, 1, core.StatusFail},
		{"MX + 1 DKIM", map[string]any{"has_mx": true, "dkim_selectors": []string{"primary"}}, 1, core.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkDomain("x.com", c.attrs))
			findings, _ := DomainDKIMSelectorPresent(context.Background(), g)
			if len(findings) != c.expectN {
				t.Fatalf("findings=%d, want %d", len(findings), c.expectN)
			}
			if c.wantFirst != "" && findings[0].Status != c.wantFirst {
				t.Errorf("status=%v want %v", findings[0].Status, c.wantFirst)
			}
		})
	}
}

func TestDomainCAAIodef(t *testing.T) {
	cases := []struct {
		name string
		caas []string
		want core.Status
	}{
		{"no caa → skip", nil, ""},
		{"with iodef", []string{"0 issue \"letsencrypt.org\"", "0 iodef \"mailto:s@x.com\""}, core.StatusPass},
		{"without iodef", []string{"0 issue \"letsencrypt.org\""}, core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			attrs := map[string]any{}
			if c.caas != nil {
				attrs["caa_records"] = c.caas
			}
			g := newAccountGraph(mkDomain("x.com", attrs))
			findings, _ := DomainCAAIodef(context.Background(), g)
			if c.want == "" {
				if len(findings) != 0 {
					t.Errorf("expected no findings")
				}
				return
			}
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestDomainDNSSECViaRegistrar(t *testing.T) {
	g := newAccountGraph(mkDomain("x.com", nil))
	findings, _ := DomainDNSSECViaRegistrar(context.Background(), g)
	if findings[0].Status != core.StatusError {
		t.Errorf("DNSSEC must be StatusError (manual-verify); got %v", findings[0].Status)
	}
	if !strings.Contains(findings[0].Message, "registrar") {
		t.Errorf("message should mention 'registrar': %q", findings[0].Message)
	}
}
