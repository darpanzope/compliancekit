package linux

import "testing"

const systemctlFixture = `chrony.service                       enabled
ssh.service                          enabled
auditd.service                       enabled
---
chrony.service                  loaded active running NTP client
ssh.service                     loaded active running OpenSSH server
auditd.service                  loaded active running Security Auditing Service
---
telnet.socket                        masked
rsh.socket                           masked
`

func TestParseSystemctlListing(t *testing.T) {
	enabled, active, masked := ParseSystemctlListing(systemctlFixture)
	if len(enabled) != 3 {
		t.Errorf("enabled=%d want 3", len(enabled))
	}
	if len(active) != 3 || active[0] != "chrony.service" {
		t.Errorf("active=%v", active)
	}
	if len(masked) != 2 || masked[1] != "rsh.socket" {
		t.Errorf("masked=%v", masked)
	}
}

func TestServiceFacts_Has(t *testing.T) {
	s := ServiceFacts{
		Enabled: []string{"ssh.service"},
		Active:  []string{"ssh.service"},
		Masked:  []string{"telnet.socket"},
	}
	if !s.HasEnabled("ssh.service") || !s.HasActive("ssh.service") || !s.HasMasked("telnet.socket") {
		t.Errorf("Has* helpers wrong: %+v", s)
	}
	if s.HasEnabled("nope.service") || s.HasActive("nope.service") || s.HasMasked("nope.service") {
		t.Errorf("Has* should return false for absent units")
	}
}
