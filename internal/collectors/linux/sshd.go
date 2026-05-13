package linux

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// sshdEffectiveCommand prints the effective sshd configuration after
// resolving Match blocks, Includes, and defaults. Requires root (or
// NOPASSWD sudo) on most distros; compliancekit-as-user can use
// `cat /etc/ssh/sshd_config` as a fallback if needed (see
// gatherSSHDConfig for the fallback chain).
//
// We use `sudo -n` so a non-root operator with sudoers entries can
// still run the check non-interactively. -n returns immediately if a
// password would be needed, which is the right behavior for an
// automated scanner.
const sshdEffectiveCommand = "sudo -n sshd -T 2>/dev/null || sshd -T 2>/dev/null || cat /etc/ssh/sshd_config"

// gatherSSHDConfig runs the sshd-config probe on client and returns
// the parsed key/value pairs. An empty or all-comments result yields
// an error -- it almost certainly means the probe failed silently
// (no sshd installed, no permission, etc.) and the caller should
// record a sshd_error.
func gatherSSHDConfig(ctx context.Context, client *ssh.Client) (map[string]string, error) {
	output, exitCode, err := RunCommand(ctx, client, sshdEffectiveCommand)
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	// exitCode is 0 from `cat` even when sshd -T fails, but on systems
	// with neither sshd nor a config file the final fallback also fails.
	if exitCode != 0 {
		return nil, fmt.Errorf("sshd probe exited %d: %s", exitCode, truncateForError(output))
	}
	parsed := parseSSHDConfig(output)
	if len(parsed) == 0 {
		return nil, fmt.Errorf("sshd probe returned no recognizable directives: %s", truncateForError(output))
	}
	return parsed, nil
}

// parseSSHDConfig converts sshd_config / `sshd -T` output into a
// lowercase-keyed map. Comments and blank lines are skipped; the first
// whitespace run separates key from value.
//
// `sshd -T` emits one directive per line. sshd_config can have
// multiple values for the same key (HostKey, AllowUsers); the LAST
// occurrence wins in OpenSSH's resolution, so we overwrite on
// duplicate -- matches OpenSSH semantics.
func parseSSHDConfig(output string) map[string]string {
	m := make(map[string]string)
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Find first whitespace run.
		idx := strings.IndexAny(line, " \t")
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		value := strings.TrimSpace(line[idx:])
		m[key] = value
	}
	return m
}

// truncateForError limits an error-embedded string to a readable length.
const errorOutputLimit = 200

func truncateForError(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= errorOutputLimit {
		return s
	}
	return s[:errorOutputLimit] + "..."
}
