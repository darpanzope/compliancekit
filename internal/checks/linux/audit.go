package linux

import (
	"context"
	"fmt"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

// auditOf returns the audit sub-map on a host Resource, or (nil, false)
// when unavailable.
func auditOf(host core.Resource) (map[string]any, bool) {
	if !host.AttrBool("reachable") {
		return nil, false
	}
	raw, ok := host.Attributes["audit"]
	if !ok {
		return nil, false
	}
	a, ok := raw.(map[string]any)
	if !ok {
		return nil, false
	}
	return a, true
}

func auditSkip(check core.Check, host core.Resource) core.Finding {
	return core.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Status:   core.StatusSkip,
		Resource: host.Ref(),
		Message:  "audit state unavailable",
		Tags:     check.Tags,
	}
}

// ============================================================
// linux-auditd-running
// ============================================================

// CheckAuditdRunning requires auditd to be active.
var CheckAuditdRunning = core.Check{
	ID:           "linux-auditd-running",
	Title:        "auditd must be running",
	Severity:     core.SeverityMedium,
	Provider:     "linux",
	Service:      "audit",
	ResourceType: linuxcol.HostType,
	Description: "auditd captures syscall-level audit events that " +
		"satisfy 'log access to sensitive systems' controls. Without " +
		"it, evidence for SOC 2 CC7.2, ISO 27001 A.8.15, and CIS " +
		"Controls v8 8.5 is hard to produce.",
	Remediation: "Install and enable auditd: " +
		"'sudo apt install auditd && sudo systemctl enable --now auditd' " +
		"(Debian/Ubuntu) or the equivalent on your distro.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2", "CC7.3"},
		"iso27001": {"A.8.15"},
		"cis-v8":   {"8.5"},
	},
	Tags:    []string{"audit", "logging"},
	Scanner: "audit.AuditdRunning",
}

// AuditdRunning is the CheckFunc for CheckAuditdRunning.
func AuditdRunning(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	hosts := g.ByType(linuxcol.HostType)
	findings := make([]core.Finding, 0, len(hosts))
	for _, h := range hosts {
		a, ok := auditOf(h)
		if !ok {
			findings = append(findings, auditSkip(CheckAuditdRunning, h))
			continue
		}
		active, _ := a["auditd_active"].(bool)
		f := core.Finding{
			CheckID:  CheckAuditdRunning.ID,
			Severity: CheckAuditdRunning.Severity,
			Resource: h.Ref(),
			Tags:     CheckAuditdRunning.Tags,
		}
		if active {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: auditd active", h.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: auditd not active", h.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ============================================================
// linux-journald-persistent
// ============================================================

// CheckJournaldPersistent requires journald Storage=persistent so logs
// survive reboots and produce auditor-acceptable evidence.
var CheckJournaldPersistent = core.Check{
	ID:           "linux-journald-persistent",
	Title:        "journald must use persistent storage",
	Severity:     core.SeverityLow,
	Provider:     "linux",
	Service:      "audit",
	ResourceType: linuxcol.HostType,
	Description: "systemd's journald default ('auto') writes to disk " +
		"only if /var/log/journal exists, and falls back to a " +
		"volatile ramdisk otherwise. A reboot wipes the latter and " +
		"breaks the audit trail. Setting Storage=persistent forces " +
		"disk storage and creates the directory if missing.",
	Remediation: "Set 'Storage=persistent' in /etc/systemd/journald.conf " +
		"and 'systemctl restart systemd-journald'. Confirm with " +
		"'journalctl --header | head'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.15"},
		"cis-v8":   {"8.5", "8.10"},
	},
	Tags:    []string{"audit", "logging", "journald"},
	Scanner: "audit.JournaldPersistent",
}

// JournaldPersistent is the CheckFunc for CheckJournaldPersistent.
func JournaldPersistent(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	hosts := g.ByType(linuxcol.HostType)
	findings := make([]core.Finding, 0, len(hosts))
	for _, h := range hosts {
		a, ok := auditOf(h)
		if !ok {
			findings = append(findings, auditSkip(CheckJournaldPersistent, h))
			continue
		}
		storage, _ := a["journald_storage"].(string)
		f := core.Finding{
			CheckID:  CheckJournaldPersistent.ID,
			Severity: CheckJournaldPersistent.Severity,
			Resource: h.Ref(),
			Tags:     CheckJournaldPersistent.Tags,
		}
		if storage == "persistent" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: journald Storage=persistent", h.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: journald Storage=%q (want persistent)", h.Name, storage)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckAuditdRunning.ID, AuditdRunning)
	core.Register(CheckJournaldPersistent.ID, JournaldPersistent)
}
