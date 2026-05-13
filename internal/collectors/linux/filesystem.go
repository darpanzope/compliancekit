package linux

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// statCommand emits one space-separated line per requested path:
//
//	<octal-mode> <uid> <user> <gid> <group> <path>
//
// Missing paths produce an error line on stderr (we discard it) and
// skip the path in stdout, so the absence of a row is meaningful.
const statCommand = `stat -c '%a %u %U %g %G %n' /etc/shadow /etc/passwd /root 2>/dev/null`

// FileFacts describes one path's permission bits and owner.
type FileFacts struct {
	Mode  int // octal, e.g. 640
	UID   int
	User  string
	GID   int
	Group string
}

// gatherFilesystem runs statCommand and parses the per-path result.
// Returns a sub-map keyed by path:
//
//	"/etc/shadow":  FileFacts{Mode: 640, ...}
//	"/etc/passwd":  FileFacts{...}
//	"/root":        FileFacts{...}
//
// Missing paths are absent from the result; checks treat "missing"
// as Skip.
func gatherFilesystem(ctx context.Context, client *ssh.Client) (map[string]any, error) {
	output, _, err := RunCommand(ctx, client, statCommand)
	if err != nil {
		return nil, fmt.Errorf("stat probe: %w", err)
	}
	parsed := parseStatLines(output)
	out := make(map[string]any, len(parsed))
	for path, facts := range parsed {
		out[path] = facts
	}
	return out, nil
}

// parseStatLines turns the stat output into a path -> FileFacts map.
// Lines that don't match the expected format are silently skipped --
// the next reading layer (checks) treats "missing" the same as
// "unparseable".
func parseStatLines(output string) map[string]FileFacts {
	out := map[string]FileFacts{}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// Split into at most 6 fields. The path may contain spaces in
		// principle (none of our targets do, but be defensive).
		parts := strings.SplitN(line, " ", 6)
		if len(parts) != 6 {
			continue
		}
		mode, err := strconv.ParseInt(parts[0], 8, 32)
		if err != nil {
			continue
		}
		uid, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		gid, err := strconv.Atoi(parts[3])
		if err != nil {
			continue
		}
		// Mask off the type bits so the value is just permission bits.
		out[parts[5]] = FileFacts{
			Mode:  int(mode) & 0o7777,
			UID:   uid,
			User:  parts[2],
			GID:   gid,
			Group: parts[4],
		}
	}
	return out
}
