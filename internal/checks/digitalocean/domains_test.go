package digitalocean

import (
	"context"
	"testing"
	"time"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

func mkDomain(name string, attrs map[string]any) core.Resource {
	return core.Resource{
		ID:         "digitalocean.domain." + name,
		Type:       docol.DomainType,
		Name:       name,
		Provider:   "digitalocean",
		Attributes: attrs,
	}
}

func mkCert(name string, attrs map[string]any) core.Resource {
	return core.Resource{
		ID:         "digitalocean.certificate." + name,
		Type:       docol.CertificateType,
		Name:       name,
		Provider:   "digitalocean",
		Attributes: attrs,
	}
}

func TestDomainCAA(t *testing.T) {
	g := newAccountGraph(
		mkDomain("with-caa", map[string]any{"has_caa": true}),
		mkDomain("no-caa", map[string]any{"has_caa": false}),
	)
	findings, _ := DomainCAA(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "no-caa" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestDomainSPF(t *testing.T) {
	cases := []struct {
		name string
		mx   bool
		spf  bool
		want core.Status
	}{
		{"no-mx-no-spf", false, false, core.StatusPass},
		{"mx-with-spf", true, true, core.StatusPass},
		{"mx-no-spf", true, false, core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkDomain(c.name, map[string]any{"has_mx": c.mx, "has_spf": c.spf}))
			findings, _ := DomainSPF(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestDomainDMARC(t *testing.T) {
	cases := []struct {
		name  string
		mx    bool
		dmarc bool
		want  core.Status
	}{
		{"no-mx", false, false, core.StatusPass},
		{"mx-with-dmarc", true, true, core.StatusPass},
		{"mx-no-dmarc", true, false, core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkDomain(c.name, map[string]any{"has_mx": c.mx, "has_dmarc": c.dmarc}))
			findings, _ := DomainDMARC(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestDomainCAANotWildcard(t *testing.T) {
	cases := []struct {
		name    string
		records []string
		want    core.Status
	}{
		{"explicit", []string{"0 issue \"letsencrypt.org\""}, core.StatusPass},
		{"wildcard-semicolon", []string{";"}, core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkDomain(c.name, map[string]any{"has_caa": true, "caa_records": c.records}))
			findings, _ := DomainCAANotWildcard(context.Background(), g)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestCertificateExpiry(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name     string
		notAfter string
		want     core.Status
	}{
		{"expired", now.Add(-24 * time.Hour).Format(time.RFC3339), core.StatusFail},
		{"near-expiry", now.Add(10 * 24 * time.Hour).Format(time.RFC3339), core.StatusFail},
		{"healthy", now.Add(60 * 24 * time.Hour).Format(time.RFC3339), core.StatusPass},
		{"unparsable", "garbage", core.StatusSkip},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkCert(c.name, map[string]any{"not_after": c.notAfter}))
			findings, _ := CertificateExpiry(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestCertificateLetsEncrypt(t *testing.T) {
	g := newAccountGraph(
		mkCert("managed", map[string]any{"type": "lets_encrypt"}),
		mkCert("custom", map[string]any{"type": "custom"}),
	)
	findings, _ := CertificateLetsEncrypt(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "custom" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
