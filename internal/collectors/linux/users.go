package linux

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// User accounts derived from /etc/passwd parsing.
//
// /etc/shadow holds the actual password hashes; we read it (root only)
// to detect empty-hash entries because /etc/passwd has "x" (placeholder)
// for every modern account whether the shadow entry is empty or not.
// The "passwd" / "shadow" strings here name shell commands and file
// paths, not stored credentials -- the gosec G101 substring match is a
// false positive.
const (
	passwdCommand = "cat /etc/passwd 2>/dev/null || true"                                        //nolint:gosec // shell command name, not a credential
	shadowCommand = "sudo -n cat /etc/shadow 2>/dev/null || cat /etc/shadow 2>/dev/null || true" //nolint:gosec // shell command name, not a credential
)

// UserAccount captures the bits of /etc/passwd a check might consult.
// We don't expose home/shell/gecos because no v0.2 check uses them.
type UserAccount struct {
	Name             string
	UID              int
	HasEmptyPassword bool
}

// gatherUsers runs both reads and produces:
//
//	"accounts": []UserAccount
//	"shadow_readable": bool        // false when /etc/shadow not readable
//
// Checks that depend on shadow content (empty passwords) Skip when
// shadow_readable=false rather than reporting a false negative.
func gatherUsers(ctx context.Context, client *ssh.Client) (map[string]any, error) {
	passwd, _, err := RunCommand(ctx, client, passwdCommand)
	if err != nil {
		return nil, fmt.Errorf("/etc/passwd probe: %w", err)
	}
	shadow, _, err := RunCommand(ctx, client, shadowCommand)
	if err != nil {
		return nil, fmt.Errorf("/etc/shadow probe: %w", err)
	}

	emptyShadow := parseEmptyPasswordUsers(shadow)
	shadowReadable := strings.TrimSpace(shadow) != ""

	accounts := parsePasswdAccounts(passwd, emptyShadow)
	return map[string]any{
		"accounts":        accounts,
		"shadow_readable": shadowReadable,
	}, nil
}

// parsePasswdAccounts converts /etc/passwd into a slice of UserAccount.
// emptyShadow is the set of usernames with empty /etc/shadow password
// fields; we mark them HasEmptyPassword.
func parsePasswdAccounts(output string, emptyShadow map[string]bool) []UserAccount {
	lines := strings.Split(output, "\n")
	out := make([]UserAccount, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// /etc/passwd: name:passwd:uid:gid:gecos:home:shell
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		out = append(out, UserAccount{
			Name:             parts[0],
			UID:              uid,
			HasEmptyPassword: emptyShadow[parts[0]],
		})
	}
	return out
}

// parseEmptyPasswordUsers returns the set of usernames whose
// /etc/shadow password hash field is literally empty. A locked account
// would have "!" or "*" or a longer locked-marker; only "" is the
// genuine "no password required" state.
func parseEmptyPasswordUsers(shadow string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(shadow, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// /etc/shadow: name:hash:last_change:min:max:warn:inactive:expire:reserved
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		if parts[1] == "" {
			out[parts[0]] = true
		}
	}
	return out
}
