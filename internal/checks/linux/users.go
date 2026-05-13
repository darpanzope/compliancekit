package linux

import (
	"context"
	"fmt"
	"strings"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

// usersOf returns (accounts, shadow_readable, ok). When shadow was not
// readable, checks that depend on it (empty-password) skip instead of
// reporting a false negative.
func usersOf(host core.Resource) (accounts []linuxcol.UserAccount, shadowReadable, ok bool) {
	if !host.AttrBool("reachable") {
		return nil, false, false
	}
	raw, present := host.Attributes["users"]
	if !present {
		return nil, false, false
	}
	m, present := raw.(map[string]any)
	if !present {
		return nil, false, false
	}
	accs, accsOK := m["accounts"].([]linuxcol.UserAccount)
	sr, _ := m["shadow_readable"].(bool)
	return accs, sr, accsOK
}

func usersSkip(check core.Check, host core.Resource, why string) core.Finding {
	return core.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Status:   core.StatusSkip,
		Resource: host.Ref(),
		Message:  why,
		Tags:     check.Tags,
	}
}

// ============================================================
// linux-uid-zero-only-root
// ============================================================

// CheckUIDZeroOnlyRoot requires that only the "root" account has UID 0.
var CheckUIDZeroOnlyRoot = core.Check{
	ID:           "linux-uid-zero-only-root",
	Title:        "Only the root account may have UID 0",
	Severity:     core.SeverityHigh,
	Provider:     "linux",
	Service:      "users",
	ResourceType: linuxcol.HostType,
	Description: "A second account with UID 0 is a stealth backdoor: " +
		"sudo / auditd see the username but every privilege check " +
		"resolves to root. CIS Ubuntu 5.4.3 requires that only the " +
		"literal 'root' user holds UID 0.",
	Remediation: "userdel <hidden-root-account> or change its UID to a " +
		"non-zero value with usermod -u <uid> <name>.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.2"},
		"cis-v8":   {"5.4", "6.8"},
	},
	Tags:    []string{"users", "privilege"},
	Scanner: "users.UIDZeroOnlyRoot",
}

// UIDZeroOnlyRoot is the CheckFunc for CheckUIDZeroOnlyRoot.
func UIDZeroOnlyRoot(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	hosts := g.ByType(linuxcol.HostType)
	findings := make([]core.Finding, 0, len(hosts))
	for _, h := range hosts {
		accounts, _, ok := usersOf(h)
		if !ok {
			findings = append(findings, usersSkip(CheckUIDZeroOnlyRoot, h, "/etc/passwd unavailable"))
			continue
		}
		var hiddenRoots []string
		for _, a := range accounts {
			if a.UID == 0 && a.Name != "root" {
				hiddenRoots = append(hiddenRoots, a.Name)
			}
		}
		f := core.Finding{
			CheckID:  CheckUIDZeroOnlyRoot.ID,
			Severity: CheckUIDZeroOnlyRoot.Severity,
			Resource: h.Ref(),
			Tags:     CheckUIDZeroOnlyRoot.Tags,
		}
		if len(hiddenRoots) == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: only root holds UID 0", h.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: additional UID-0 accounts: %s", h.Name, strings.Join(hiddenRoots, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ============================================================
// linux-no-empty-passwords
// ============================================================

// CheckNoEmptyPasswords requires no /etc/shadow entry to have an empty
// password hash field.
var CheckNoEmptyPasswords = core.Check{
	ID:           "linux-no-empty-passwords",
	Title:        "No account may have an empty password",
	Severity:     core.SeverityHigh,
	Provider:     "linux",
	Service:      "users",
	ResourceType: linuxcol.HostType,
	Description: "An account whose /etc/shadow password field is " +
		"literally empty can be logged in to with any password (or " +
		"no password, depending on PAM config). CIS Ubuntu 7.2.4 " +
		"requires that no entry have an empty hash; locked accounts " +
		"use '!' or '*' instead.",
	Remediation: "passwd -l <user> to lock the account, or set a " +
		"strong password.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.5"},
		"cis-v8":   {"5.2"},
	},
	Tags:    []string{"users", "passwords"},
	Scanner: "users.NoEmptyPasswords",
}

// NoEmptyPasswords is the CheckFunc for CheckNoEmptyPasswords.
func NoEmptyPasswords(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	hosts := g.ByType(linuxcol.HostType)
	findings := make([]core.Finding, 0, len(hosts))
	for _, h := range hosts {
		accounts, shadowReadable, ok := usersOf(h)
		if !ok {
			findings = append(findings, usersSkip(CheckNoEmptyPasswords, h, "/etc/passwd unavailable"))
			continue
		}
		if !shadowReadable {
			findings = append(findings, usersSkip(CheckNoEmptyPasswords, h, "/etc/shadow not readable (need sudo)"))
			continue
		}
		var empties []string
		for _, a := range accounts {
			if a.HasEmptyPassword {
				empties = append(empties, a.Name)
			}
		}
		f := core.Finding{
			CheckID:  CheckNoEmptyPasswords.ID,
			Severity: CheckNoEmptyPasswords.Severity,
			Resource: h.Ref(),
			Tags:     CheckNoEmptyPasswords.Tags,
		}
		if len(empties) == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: no accounts with empty passwords", h.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: accounts with empty passwords: %s", h.Name, strings.Join(empties, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckUIDZeroOnlyRoot.ID, UIDZeroOnlyRoot)
	core.Register(CheckNoEmptyPasswords.ID, NoEmptyPasswords)
}
