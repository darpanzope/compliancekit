package digitalocean

import (
	"context"
	"testing"
	"time"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkDomain(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID:         "digitalocean.domain." + name,
		Type:       docol.DomainType,
		Name:       name,
		Provider:   "digitalocean",
		Attributes: attrs,
	}
}

func mkCert(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
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
		want := compliancekit.StatusPass
		if f.Resource.Name == "no-caa" {
			want = compliancekit.StatusFail
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
		want compliancekit.Status
	}{
		{"no-mx-no-spf", false, false, compliancekit.StatusPass},
		{"mx-with-spf", true, true, compliancekit.StatusPass},
		{"mx-no-spf", true, false, compliancekit.StatusFail},
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
		want  compliancekit.Status
	}{
		{"no-mx", false, false, compliancekit.StatusPass},
		{"mx-with-dmarc", true, true, compliancekit.StatusPass},
		{"mx-no-dmarc", true, false, compliancekit.StatusFail},
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
		want    compliancekit.Status
	}{
		{"explicit", []string{"0 issue \"letsencrypt.org\""}, compliancekit.StatusPass},
		{"wildcard-semicolon", []string{";"}, compliancekit.StatusFail},
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
		want     compliancekit.Status
	}{
		{"expired", now.Add(-24 * time.Hour).Format(time.RFC3339), compliancekit.StatusFail},
		{"near-expiry", now.Add(10 * 24 * time.Hour).Format(time.RFC3339), compliancekit.StatusFail},
		{"healthy", now.Add(60 * 24 * time.Hour).Format(time.RFC3339), compliancekit.StatusPass},
		{"unparsable", "garbage", compliancekit.StatusSkip},
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
		want := compliancekit.StatusPass
		if f.Resource.Name == "custom" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
