package linux

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	auditdActiveCmd = "systemctl is-active auditd 2>/dev/null || true"
	journaldConfCmd = "cat /etc/systemd/journald.conf 2>/dev/null || true"
)

// gatherAudit probes auditd and journald state. Returns a sub-map
// intended to be stored under the "audit" attribute key.
//
// Keys produced:
//
//	auditd_active       bool
//	journald_storage    string  ("persistent", "auto", "volatile", "none", or "")
//
// journald_storage defaults to "auto" when /etc/systemd/journald.conf
// is absent or has the directive commented -- matching systemd's
// in-binary default. The persistent check then Fails on anything but
// "persistent".
func gatherAudit(ctx context.Context, client *ssh.Client) (map[string]any, error) {
	out := map[string]any{
		"auditd_active":    false,
		"journald_storage": "",
	}

	audOut, _, err := RunCommand(ctx, client, auditdActiveCmd)
	if err != nil {
		return nil, fmt.Errorf("auditd probe: %w", err)
	}
	if strings.TrimSpace(audOut) == "active" {
		out["auditd_active"] = true
	}

	jrnOut, _, err := RunCommand(ctx, client, journaldConfCmd)
	if err != nil {
		return nil, fmt.Errorf("journald probe: %w", err)
	}
	out["journald_storage"] = parseJournaldStorage(jrnOut)

	return out, nil
}

// parseJournaldStorage returns the value of the "Storage=" directive
// in journald.conf. If the directive is missing or commented, returns
// "auto" -- the systemd-internal default per journald.conf(5).
//
// Whitespace around the value is trimmed; quote characters are not
// stripped (journald.conf does not use quoting).
func parseJournaldStorage(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "Storage=") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(line, "Storage="))
	}
	return "auto"
}
