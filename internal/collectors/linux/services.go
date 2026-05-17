package linux

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// v0.20 phase 4 — systemd unit + service state. Two cheap systemctl
// probes feed the v0.20 phase 4 services checks (which services must
// be running, which must be disabled, which insecure inetd-era
// services must be absent entirely).

// ServiceFacts summarizes the systemd unit state on the host.
type ServiceFacts struct {
	Enabled []string // unit files in state "enabled"
	Active  []string // unit files in active "active"
	Masked  []string // unit files in state "masked"
}

// HasEnabled reports whether unit is present in the Enabled slice.
func (s ServiceFacts) HasEnabled(unit string) bool { return contains(s.Enabled, unit) }

// HasActive reports whether unit is present in the Active slice.
func (s ServiceFacts) HasActive(unit string) bool { return contains(s.Active, unit) }

// HasMasked reports whether unit is present in the Masked slice.
func (s ServiceFacts) HasMasked(unit string) bool { return contains(s.Masked, unit) }

func contains(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}

const servicesCommand = `systemctl list-unit-files --state=enabled --type=service --no-legend --plain 2>/dev/null; echo '---';` +
	`systemctl list-units --state=active --type=service --no-legend --plain 2>/dev/null; echo '---';` +
	`systemctl list-unit-files --state=masked --type=service --no-legend --plain 2>/dev/null`

// gatherServices runs the systemctl probe over SSH and parses the
// output into the typed ServiceFacts struct. Empty result is a hard
// error — every systemd host has dozens of units; empty means the
// probe didn't run (Alpine on OpenRC, container without /run/systemd).
func gatherServices(ctx context.Context, client *ssh.Client) (ServiceFacts, error) {
	output, _, err := RunCommand(ctx, client, servicesCommand)
	if err != nil {
		return ServiceFacts{}, fmt.Errorf("services probe: %w", err)
	}
	enabled, active, masked := ParseSystemctlListing(output)
	if len(enabled)+len(active) == 0 {
		return ServiceFacts{}, fmt.Errorf("services probe returned no entries (not systemd?)")
	}
	return ServiceFacts{Enabled: enabled, Active: active, Masked: masked}, nil
}

// ParseSystemctlListing turns the 3-block probe output (enabled →
// active → masked, separated by `---`) into three slices of unit
// names. Each list-unit{,-files} line is `<unit-name> <state> ...` —
// the unit name is the first whitespace-delimited token.
//
// Exported so tests + downstream collectors share the parser.
func ParseSystemctlListing(body string) (enabled, active, masked []string) {
	blocks := strings.Split(body, "---")
	if len(blocks) >= 1 {
		enabled = systemctlUnitNames(blocks[0])
	}
	if len(blocks) >= 2 {
		active = systemctlUnitNames(blocks[1])
	}
	if len(blocks) >= 3 {
		masked = systemctlUnitNames(blocks[2])
	}
	return enabled, active, masked
}

func systemctlUnitNames(block string) []string {
	out := []string{}
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		out = append(out, parts[0])
	}
	return out
}
