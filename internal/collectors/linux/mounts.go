package linux

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// v0.20 phase 3 — mount information for filesystem-hardening checks
// (separate-partition + mount-option enforcement on /tmp, /var, /home,
// /dev/shm, etc.). Read from /proc/mounts (kernel-canonical, identical
// shape across every distro we support).

// MountEntry is a single line from /proc/mounts. Field order matches
// proc(5) — source, target, fstype, options, dump, pass.
type MountEntry struct {
	Source  string   // /dev/sda1, tmpfs, etc.
	Target  string   // /tmp, /var, etc.
	FSType  string   // ext4, tmpfs, xfs, ...
	Options []string // ["rw", "nodev", "nosuid", "noexec"]
}

// HasOption reports whether opt is present in the mount's options
// list (case-sensitive, exact match).
func (m MountEntry) HasOption(opt string) bool {
	for _, o := range m.Options {
		if o == opt {
			return true
		}
	}
	return false
}

const mountsCommand = "cat /proc/mounts 2>/dev/null"

// gatherMounts reads /proc/mounts over SSH and returns the parsed
// slice. An empty result is a hard error (every running Linux has
// at least a few mounts — empty means the probe failed).
func gatherMounts(ctx context.Context, client *ssh.Client) ([]MountEntry, error) {
	output, _, err := RunCommand(ctx, client, mountsCommand)
	if err != nil {
		return nil, fmt.Errorf("mounts probe: %w", err)
	}
	mounts := ParseProcMounts(output)
	if len(mounts) == 0 {
		return nil, fmt.Errorf("mounts probe returned no entries")
	}
	return mounts, nil
}

// ParseProcMounts converts the canonical /proc/mounts shape into a
// MountEntry slice. Exported so tests can drive it from fixtures.
//
// Lines are space-separated with at least 4 fields. Empty / malformed
// lines are silently skipped — checks fall through to "mount not
// present" semantics if the target path isn't in the result.
func ParseProcMounts(body string) []MountEntry {
	out := []MountEntry{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		out = append(out, MountEntry{
			Source:  parts[0],
			Target:  parts[1],
			FSType:  parts[2],
			Options: strings.Split(parts[3], ","),
		})
	}
	return out
}

// FindMount returns the MountEntry whose Target equals target, or a
// zero-value MountEntry + false when no match. Used by checks that
// expect a specific path to be its own mount.
func FindMount(mounts []MountEntry, target string) (MountEntry, bool) {
	for _, m := range mounts {
		if m.Target == target {
			return m, true
		}
	}
	return MountEntry{}, false
}
