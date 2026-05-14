package profile

import (
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
)

func mkCheck(id, provider string, sev core.Severity, tags []string, frameworks map[string][]string) core.Check {
	return core.Check{
		ID:         id,
		Provider:   provider,
		Severity:   sev,
		Tags:       tags,
		Frameworks: frameworks,
	}
}

func sampleCatalog() []core.Check {
	return []core.Check{
		mkCheck("do-droplet-no-firewall", "digitalocean", core.SeverityHigh, []string{"network", "exposure"}, map[string][]string{"soc2": {"CC6.6"}, "cis-v8": {"4.4"}}),
		mkCheck("do-droplet-no-tags", "digitalocean", core.SeverityLow, []string{"inventory"}, map[string][]string{"soc2": {"CC1.4"}, "iso27001": {"A.5.9"}}),
		mkCheck("linux-sshd-no-root-login", "linux", core.SeverityHigh, []string{"ssh"}, map[string][]string{"soc2": {"CC6.1"}, "cis-v8": {"5.4"}}),
		mkCheck("linux-aslr-enabled", "linux", core.SeverityMedium, []string{"kernel"}, map[string][]string{"cis-v8": {"4.1"}}),
	}
}

func TestFilter_IncludeProviders(t *testing.T) {
	p := Profile{Name: "do-only", IncludeProviders: []string{"digitalocean"}}
	out, err := p.Filter(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Errorf("got %d checks, want 2", len(out))
	}
	for _, c := range out {
		if c.Provider != "digitalocean" {
			t.Errorf("provider not filtered: %s", c.Provider)
		}
	}
}

func TestFilter_IncludeSeverities(t *testing.T) {
	p := Profile{Name: "high-only", IncludeSeverities: []string{"high", "critical"}}
	out, err := p.Filter(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Errorf("got %d, want 2 (only high severity)", len(out))
	}
}

func TestFilter_IncludeFrameworks(t *testing.T) {
	p := Profile{Name: "iso", IncludeFrameworks: []string{"iso27001"}}
	out, err := p.Filter(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].ID != "do-droplet-no-tags" {
		t.Errorf("got %+v, want only do-droplet-no-tags", checkIDs(out))
	}
}

func TestFilter_IncludeTags(t *testing.T) {
	p := Profile{Name: "ssh-only", IncludeTags: []string{"ssh"}}
	out, err := p.Filter(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].ID != "linux-sshd-no-root-login" {
		t.Errorf("got %+v, want only ssh check", checkIDs(out))
	}
}

func TestFilter_ExcludeTags(t *testing.T) {
	p := Profile{Name: "no-net", ExcludeTags: []string{"network"}}
	out, err := p.Filter(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Errorf("got %d, want 3 (excluding network)", len(out))
	}
	for _, c := range out {
		for _, tag := range c.Tags {
			if tag == "network" {
				t.Errorf("network-tagged check leaked: %s", c.ID)
			}
		}
	}
}

func TestFilter_IncludeIDsShortCircuits(t *testing.T) {
	// IncludeIDs ignores other include selectors.
	p := Profile{
		Name:             "specific",
		IncludeProviders: []string{"this-would-match-nothing"},
		IncludeIDs:       []string{"linux-aslr-enabled"},
	}
	out, err := p.Filter(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].ID != "linux-aslr-enabled" {
		t.Errorf("got %+v, want only linux-aslr-enabled", checkIDs(out))
	}
}

func TestFilter_ExcludeIDsAppliesEvenWithIncludeIDs(t *testing.T) {
	p := Profile{
		Name:       "specific-minus-one",
		IncludeIDs: []string{"linux-aslr-enabled", "linux-sshd-no-root-login"},
		ExcludeIDs: []string{"linux-aslr-enabled"},
	}
	out, err := p.Filter(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].ID != "linux-sshd-no-root-login" {
		t.Errorf("got %+v, want only sshd", checkIDs(out))
	}
}

func TestFilter_AndComposesSelectors(t *testing.T) {
	// Both selectors must match.
	p := Profile{
		Name:              "linux-high",
		IncludeProviders:  []string{"linux"},
		IncludeSeverities: []string{"high"},
	}
	out, err := p.Filter(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].ID != "linux-sshd-no-root-login" {
		t.Errorf("got %+v, want only linux-sshd-no-root-login", checkIDs(out))
	}
}

func TestFilter_EmptySelectorsMatchAll(t *testing.T) {
	p := Profile{Name: "any"}
	out, err := p.Filter(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 4 {
		t.Errorf("empty selectors: got %d, want 4 (everything)", len(out))
	}
}

func TestFilter_ZeroMatchErrors(t *testing.T) {
	p := Profile{Name: "ghost", IncludeProviders: []string{"nowhere"}}
	_, err := p.Filter(sampleCatalog())
	if err == nil || !strings.Contains(err.Error(), "matches no checks") {
		t.Errorf("expected 'matches no checks' error, got: %v", err)
	}
}

func TestFilter_CaseInsensitive(t *testing.T) {
	// "DigitalOcean" vs "digitalocean" -- accept either.
	p := Profile{Name: "case", IncludeProviders: []string{"DigitalOcean"}}
	out, err := p.Filter(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Errorf("case-insensitive provider match: got %d, want 2", len(out))
	}
}

func TestFilter_SortedOutput(t *testing.T) {
	// Output sorted by ID regardless of input order.
	shuffled := []core.Check{
		mkCheck("zzz", "x", core.SeverityHigh, nil, nil),
		mkCheck("aaa", "x", core.SeverityHigh, nil, nil),
		mkCheck("mmm", "x", core.SeverityHigh, nil, nil),
	}
	p := Profile{Name: "any"}
	out, err := p.Filter(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	if out[0].ID != "aaa" || out[1].ID != "mmm" || out[2].ID != "zzz" {
		t.Errorf("not sorted: %+v", checkIDs(out))
	}
}

func checkIDs(checks []core.Check) []string {
	out := make([]string, len(checks))
	for i, c := range checks {
		out[i] = c.ID
	}
	return out
}
