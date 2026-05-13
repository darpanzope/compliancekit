package linux

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Probes for firewall state. `|| true` keeps exit codes at 0 so
// RunCommand returns a usable output rather than treating a "service
// not installed" as a transport error.
const (
	ufwStatusCmd      = "sudo -n ufw status verbose 2>/dev/null || ufw status verbose 2>/dev/null || true"
	nftablesActiveCmd = "systemctl is-active nftables 2>/dev/null || true"
)

// gatherFirewall probes the host for ufw and nftables state. Returns a
// sub-map intended to be stored under the "firewall" attribute key on
// the host Resource.
//
// Keys produced:
//
//	ufw_active            bool
//	ufw_default_incoming  string  (only when ufw_active)
//	ufw_default_outgoing  string  (only when ufw_active)
//	nftables_active       bool
//
// Checks read these via map lookups; missing keys are treated as
// "unknown" by the consuming check (which Fails on unknown for the
// default-deny check, by design -- absence of evidence is not
// evidence of absence).
func gatherFirewall(ctx context.Context, client *ssh.Client) (map[string]any, error) {
	out := map[string]any{
		"ufw_active":      false,
		"nftables_active": false,
	}

	ufwOut, _, err := RunCommand(ctx, client, ufwStatusCmd)
	if err != nil {
		return nil, fmt.Errorf("ufw probe: %w", err)
	}
	if strings.Contains(ufwOut, "Status: active") {
		out["ufw_active"] = true
		out["ufw_default_incoming"] = parseUFWDefault(ufwOut, "incoming")
		out["ufw_default_outgoing"] = parseUFWDefault(ufwOut, "outgoing")
	}

	nftOut, _, err := RunCommand(ctx, client, nftablesActiveCmd)
	if err != nil {
		return nil, fmt.Errorf("nftables probe: %w", err)
	}
	if strings.TrimSpace(nftOut) == "active" {
		out["nftables_active"] = true
	}

	return out, nil
}

// parseUFWDefault extracts the policy for a single direction (incoming /
// outgoing / routed) from the "Default:" line emitted by
// `ufw status verbose`:
//
//	Default: deny (incoming), allow (outgoing), disabled (routed)
//
// Returns "" if the direction is not present or the line is missing.
func parseUFWDefault(output, direction string) string {
	suffix := "(" + direction + ")"
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Default:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "Default:"))
		for _, seg := range strings.Split(rest, ",") {
			seg = strings.TrimSpace(seg)
			if strings.HasSuffix(seg, suffix) {
				return strings.TrimSpace(strings.TrimSuffix(seg, suffix))
			}
		}
	}
	return ""
}
