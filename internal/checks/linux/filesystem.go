package linux

import (
	"context"
	"fmt"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

// filesystemOf returns the filesystem sub-map and FileFacts for path
// on a host Resource, or (zero, false) when unavailable.
func filesystemFactsOf(host core.Resource, path string) (linuxcol.FileFacts, bool) {
	if !host.AttrBool("reachable") {
		return linuxcol.FileFacts{}, false
	}
	raw, ok := host.Attributes["filesystem"]
	if !ok {
		return linuxcol.FileFacts{}, false
	}
	fs, ok := raw.(map[string]any)
	if !ok {
		return linuxcol.FileFacts{}, false
	}
	entry, ok := fs[path]
	if !ok {
		return linuxcol.FileFacts{}, false
	}
	facts, ok := entry.(linuxcol.FileFacts)
	return facts, ok
}

func fsSkip(check core.Check, host core.Resource, path string) core.Finding {
	return core.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Status:   core.StatusSkip,
		Resource: host.Ref(),
		Message:  fmt.Sprintf("%s metadata unavailable", path),
		Tags:     check.Tags,
	}
}

// ============================================================
// linux-shadow-perms
// ============================================================

// CheckShadowPerms requires /etc/shadow to be mode 0640 and owned
// root:shadow (CIS Ubuntu 22.04 benchmark 7.1.3).
var CheckShadowPerms = core.Check{
	ID:           "linux-shadow-perms",
	Title:        "/etc/shadow must be 0640 root:shadow",
	Severity:     core.SeverityHigh,
	Provider:     "linux",
	Service:      "filesystem",
	ResourceType: linuxcol.HostType,
	Description: "/etc/shadow holds the password hashes for every local " +
		"account. Read access for non-root, non-shadow users enables " +
		"offline cracking and is the textbook CIS Ubuntu 7.1.3 finding. " +
		"Correct ownership is root:shadow with mode 0640.",
	Remediation: "chmod 0640 /etc/shadow && chown root:shadow /etc/shadow.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.3"},
		"cis-v8":   {"3.3", "5.1"},
	},
	Tags:    []string{"filesystem", "shadow"},
	Scanner: "filesystem.ShadowPerms",
}

// ShadowPerms is the CheckFunc for CheckShadowPerms.
func ShadowPerms(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	hosts := g.ByType(linuxcol.HostType)
	findings := make([]core.Finding, 0, len(hosts))
	for _, h := range hosts {
		facts, ok := filesystemFactsOf(h, "/etc/shadow")
		if !ok {
			findings = append(findings, fsSkip(CheckShadowPerms, h, "/etc/shadow"))
			continue
		}
		f := core.Finding{
			CheckID:  CheckShadowPerms.ID,
			Severity: CheckShadowPerms.Severity,
			Resource: h.Ref(),
			Tags:     CheckShadowPerms.Tags,
		}
		modeOK := facts.Mode == 0o640
		ownerOK := facts.User == "root" && facts.Group == "shadow"
		if modeOK && ownerOK {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: /etc/shadow mode=0640 owner=root:shadow", h.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: /etc/shadow mode=0%o owner=%s:%s (want 0640 root:shadow)",
				h.Name, facts.Mode, facts.User, facts.Group)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ============================================================
// linux-passwd-perms
// ============================================================

// CheckPasswdPerms requires /etc/passwd to be mode 0644 or stricter.
var CheckPasswdPerms = core.Check{
	ID:           "linux-passwd-perms",
	Title:        "/etc/passwd must be 0644 or stricter",
	Severity:     core.SeverityMedium,
	Provider:     "linux",
	Service:      "filesystem",
	ResourceType: linuxcol.HostType,
	Description: "/etc/passwd must be world-readable (login commands " +
		"need it) but must not be writable by anyone but root. CIS " +
		"Ubuntu 7.1.2 prescribes mode 0644 exactly; we accept 0644 " +
		"or stricter (0640, 0600).",
	Remediation: "chmod 0644 /etc/passwd && chown root:root /etc/passwd.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.3"},
		"cis-v8":   {"3.3"},
	},
	Tags:    []string{"filesystem", "passwd"},
	Scanner: "filesystem.PasswdPerms",
}

// PasswdPerms is the CheckFunc for CheckPasswdPerms.
func PasswdPerms(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	hosts := g.ByType(linuxcol.HostType)
	findings := make([]core.Finding, 0, len(hosts))
	for _, h := range hosts {
		facts, ok := filesystemFactsOf(h, "/etc/passwd")
		if !ok {
			findings = append(findings, fsSkip(CheckPasswdPerms, h, "/etc/passwd"))
			continue
		}
		f := core.Finding{
			CheckID:  CheckPasswdPerms.ID,
			Severity: CheckPasswdPerms.Severity,
			Resource: h.Ref(),
			Tags:     CheckPasswdPerms.Tags,
		}
		// Mode must be no looser than 0644: no group-write, no other-write.
		// Stricter (e.g. 0640, 0600) passes.
		// 0644 in octal is rw-r--r--. The forbidden bits are 0022 (group + other write).
		if facts.Mode&0o022 == 0 && facts.User == "root" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: /etc/passwd mode=0%o owner=%s", h.Name, facts.Mode, facts.User)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: /etc/passwd mode=0%o owner=%s (want 0644 or stricter, owner root)",
				h.Name, facts.Mode, facts.User)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckShadowPerms.ID, ShadowPerms)
	core.Register(CheckPasswdPerms.ID, PasswdPerms)
}
