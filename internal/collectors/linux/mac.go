package linux

import (
	"context"
	"strings"

	"golang.org/x/crypto/ssh"
)

// v0.20 phase 9 — Mandatory Access Control collector. Two cheap
// probes feed the MAC-enforcing checks: getenforce (SELinux) +
// aa-status (AppArmor). Both fall through gracefully on hosts
// without the corresponding subsystem installed.

// MACFacts captures the host's SELinux + AppArmor posture.
type MACFacts struct {
	SELinuxMode      string // "enforcing" | "permissive" | "disabled" | ""
	AppArmorActive   bool   // aa-status --enabled returns 0
	AppArmorProfiles int    // loaded profile count (from aa-status text)
}

const (
	getenforceCmd = "getenforce 2>/dev/null || true"
	aaStatusCmd   = "aa-status 2>/dev/null || true"
)

func gatherMAC(ctx context.Context, client *ssh.Client) MACFacts {
	out := MACFacts{}

	if mode, _, err := RunCommand(ctx, client, getenforceCmd); err == nil {
		out.SELinuxMode = strings.ToLower(strings.TrimSpace(mode))
	}

	if aa, _, err := RunCommand(ctx, client, aaStatusCmd); err == nil {
		txt := strings.ToLower(aa)
		// aa-status output usually starts with "apparmor module is loaded"
		// followed by "N profiles are loaded."
		if strings.Contains(txt, "apparmor module is loaded") {
			out.AppArmorActive = true
		}
		out.AppArmorProfiles = aaStatusProfileCount(aa)
	}
	return out
}

// aaStatusProfileCount extracts the first integer from a line like
// "  42 profiles are loaded." in aa-status output. Returns 0 on
// failure.
func aaStatusProfileCount(body string) int {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "profiles are loaded") {
			continue
		}
		// First space-delimited token is the count.
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		n := 0
		for _, c := range fields[0] {
			if c < '0' || c > '9' {
				return n
			}
			n = n*10 + int(c-'0')
		}
		return n
	}
	return 0
}
