package linux

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// v0.20 phase 1 — distro detection. /etc/os-release is the
// systemd-blessed cross-distro identity file (present on every
// supported distro since ~2017). We read it from the SSH client and
// parse out ID + ID_LIKE + VERSION_ID + PRETTY_NAME — every
// downstream check that wants per-distro behavior reads these
// attributes off the host resource.
//
// ID values we expect: debian, ubuntu, rhel, centos, rocky, almalinux,
// fedora, alpine, amzn (Amazon Linux), arch, opensuse-leap, sles.
// ID_LIKE values group distros into families: "debian" (Debian/Ubuntu/
// Pop_OS!/Mint), "rhel fedora" (RHEL/Rocky/Alma/CentOS), etc.

const osReleaseCommand = "cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null"

// OSRelease holds the parsed /etc/os-release fields the collector
// captures. Field names match os-release(5) lowercased.
type OSRelease struct {
	ID         string // "ubuntu"
	IDLike     string // "debian"
	VersionID  string // "22.04"
	PrettyName string // "Ubuntu 22.04.3 LTS"
}

// IsDebianFamily reports whether the host runs Debian, Ubuntu, or a
// derivative (apt-based package manager).
func (o OSRelease) IsDebianFamily() bool {
	if o.ID == "debian" || o.ID == "ubuntu" {
		return true
	}
	return strings.Contains(o.IDLike, "debian")
}

// IsRHELFamily reports whether the host runs RHEL, CentOS, Rocky, Alma,
// or any other dnf/yum-based distro.
func (o OSRelease) IsRHELFamily() bool {
	switch o.ID {
	case "rhel", "centos", "rocky", "almalinux", "fedora":
		return true
	}
	return strings.Contains(o.IDLike, "rhel") || strings.Contains(o.IDLike, "fedora")
}

// IsAlpine reports whether the host runs Alpine Linux (apk).
func (o OSRelease) IsAlpine() bool { return o.ID == "alpine" }

// IsAmazonLinux reports whether the host runs Amazon Linux 2 or 2023.
func (o OSRelease) IsAmazonLinux() bool { return o.ID == "amzn" }

// gatherOSRelease runs `cat /etc/os-release` over ssh and returns the
// parsed identity record. A read failure yields an OSRelease with all
// fields zero plus an error — checks fall through to "distro unknown"
// behavior in that case rather than aborting the scan.
func gatherOSRelease(ctx context.Context, client *ssh.Client) (OSRelease, error) {
	output, exitCode, err := RunCommand(ctx, client, osReleaseCommand)
	if err != nil {
		return OSRelease{}, fmt.Errorf("ssh: %w", err)
	}
	if exitCode != 0 {
		return OSRelease{}, fmt.Errorf("os-release probe exited %d: %s", exitCode, truncateForError(output))
	}
	rel, err := ParseOSRelease(output)
	if err != nil {
		return OSRelease{}, err
	}
	if rel.ID == "" {
		return OSRelease{}, fmt.Errorf("os-release returned no ID field")
	}
	return rel, nil
}

// ParseOSRelease parses the canonical key=value shape of
// /etc/os-release. Exported so per-distro test fixtures + the
// collector helpers share one implementation.
//
// Per os-release(5):
//   - blank lines + lines starting with # are comments
//   - values may be unquoted or wrapped in single / double quotes
//   - quoted values may contain spaces; unquoted values may not
func ParseOSRelease(body string) (OSRelease, error) {
	out := OSRelease{}
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		val = stripOSReleaseQuotes(val)

		switch key {
		case "ID":
			out.ID = val
		case "ID_LIKE":
			out.IDLike = val
		case "VERSION_ID":
			out.VersionID = val
		case "PRETTY_NAME":
			out.PrettyName = val
		}
	}
	if err := scanner.Err(); err != nil {
		return OSRelease{}, fmt.Errorf("scan os-release: %w", err)
	}
	return out, nil
}

// stripOSReleaseQuotes removes a matching outer pair of single OR
// double quotes. os-release(5) doesn't mandate either form; tools in
// the wild use both.
func stripOSReleaseQuotes(s string) string {
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
