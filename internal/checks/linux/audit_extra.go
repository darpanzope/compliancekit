package linux

import (
	"context"
	"fmt"
	"strings"

	docol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.20 phase 7 — auditd rule-presence checks. Each spec lists one or
// more substrings that must appear in the auditctl -l output for the
// rule to count as loaded. Substring matching is intentionally fuzzy
// to handle minor formatting differences across distros (auditctl
// elides leading flags / reorders -F predicates between RHEL + Debian).
//
// Source: CIS Linux Server Benchmark v8 §4.1.3.x (audit rules).

type auditRuleSpec struct {
	id, title, scanner string
	severity           core.Severity
	soc2, iso, cis     []string
	tags               []string
	descSuffix         string
	// must contains substrings ALL of which must appear in a single rule line.
	must []string
}

var auditRuleSpecs = []auditRuleSpec{
	{id: "linux-audit-rule-passwd", title: "auditd must watch /etc/passwd",
		severity: core.SeverityHigh, soc2: []string{"CC7.2"}, iso: []string{"A.8.15"}, cis: []string{"4.1.3.7"},
		tags: []string{"audit", "identity"}, must: []string{"/etc/passwd"},
		descSuffix: "Watch writes to /etc/passwd; every legitimate user-add / user-mod produces a record.",
		scanner:    "linux.audit.RulePasswd"},
	{id: "linux-audit-rule-shadow", title: "auditd must watch /etc/shadow",
		severity: core.SeverityHigh, soc2: []string{"CC7.2"}, iso: []string{"A.8.15"}, cis: []string{"4.1.3.7"},
		tags: []string{"audit", "identity"}, must: []string{"/etc/shadow"},
		descSuffix: "Direct edits to /etc/shadow bypass passwd/chpasswd; an audit record catches the attempt.",
		scanner:    "linux.audit.RuleShadow"},
	{id: "linux-audit-rule-group", title: "auditd must watch /etc/group",
		severity: core.SeverityMedium, soc2: []string{"CC7.2"}, iso: []string{"A.8.15"}, cis: []string{"4.1.3.7"},
		tags: []string{"audit", "identity"}, must: []string{"/etc/group"},
		descSuffix: "Watch group-membership changes — a privilege-escalation primitive (add user to wheel/sudo).",
		scanner:    "linux.audit.RuleGroup"},
	{id: "linux-audit-rule-gshadow", title: "auditd must watch /etc/gshadow",
		severity: core.SeverityMedium, soc2: []string{"CC7.2"}, iso: []string{"A.8.15"}, cis: []string{"4.1.3.7"},
		tags: []string{"audit", "identity"}, must: []string{"/etc/gshadow"},
		descSuffix: "Group-password file. Rarely edited; an unexpected write is high-signal.",
		scanner:    "linux.audit.RuleGshadow"},
	{id: "linux-audit-rule-sudoers", title: "auditd must watch /etc/sudoers + /etc/sudoers.d",
		severity: core.SeverityHigh, soc2: []string{"CC6.3"}, iso: []string{"A.5.15"}, cis: []string{"4.1.3.20"},
		tags: []string{"audit", "sudo"}, must: []string{"/etc/sudoers"},
		descSuffix: "Watch sudoers edits — most privileged-access drift starts here. /etc/sudoers.d should also be watched.",
		scanner:    "linux.audit.RuleSudoers"},
	{id: "linux-audit-rule-selinux", title: "auditd must watch /etc/selinux/ + /usr/share/selinux/",
		severity: core.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"4.1.3.14"},
		tags: []string{"audit", "selinux"}, must: []string{"/etc/selinux"},
		descSuffix: "MAC policy changes (SELinux config) should be audit-trailed.",
		scanner:    "linux.audit.RuleSELinux"},
	{id: "linux-audit-rule-time-change", title: "auditd must watch time-change syscalls",
		severity: core.SeverityMedium, soc2: []string{"CC7.2"}, iso: []string{"A.8.17"}, cis: []string{"4.1.3.5"},
		tags: []string{"audit", "time"}, must: []string{"adjtimex"},
		descSuffix: "adjtimex / settimeofday / clock_settime calls — a backdoor for log-correlation evasion.",
		scanner:    "linux.audit.RuleTimeChange"},
	{id: "linux-audit-rule-localtime", title: "auditd must watch /etc/localtime",
		severity: core.SeverityLow, soc2: []string{"CC7.2"}, iso: []string{"A.8.17"}, cis: []string{"4.1.3.5"},
		tags: []string{"audit", "time"}, must: []string{"/etc/localtime"},
		descSuffix: "Timezone changes shift every log timestamp; a recorded change is essential for correlation.",
		scanner:    "linux.audit.RuleLocaltime"},
	{id: "linux-audit-rule-lastlog", title: "auditd must watch /var/log/lastlog (login records)",
		severity: core.SeverityMedium, soc2: []string{"CC7.2"}, iso: []string{"A.8.15"}, cis: []string{"4.1.3.6"},
		tags: []string{"audit", "login"}, must: []string{"/var/log/lastlog"},
		descSuffix: "lastlog tracks per-user last-login time; tampering is a forensic-evasion signal.",
		scanner:    "linux.audit.RuleLastlog"},
	{id: "linux-audit-rule-mac-policy", title: "auditd must watch /etc/apparmor/ (or /etc/apparmor.d/)",
		severity: core.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"4.1.3.14"},
		tags: []string{"audit", "apparmor"}, must: []string{"/etc/apparmor"},
		descSuffix: "AppArmor policy changes — same rationale as the SELinux watch but for the alternative MAC.",
		scanner:    "linux.audit.RuleAppArmor"},
}

func auditRulesFromHost(h core.Resource) ([]string, bool) {
	audit, ok := h.Attributes["audit"].(map[string]any)
	if !ok {
		return nil, false
	}
	rules, ok := audit["audit_rules"].([]string)
	return rules, ok
}

func auditRuleCheckFunc(spec auditRuleSpec) core.CheckFunc {
	return func(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
		findings := []core.Finding{}
		for _, h := range g.ByType(docol.HostType) {
			f := core.Finding{
				CheckID:  spec.id,
				Severity: spec.severity,
				Resource: h.Ref(),
				Tags:     spec.tags,
			}
			reachable, _ := h.Attributes["reachable"].(bool)
			if !reachable {
				f.Status = core.StatusSkip
				f.Message = fmt.Sprintf("host %q: unreachable", h.Name)
				findings = append(findings, f)
				continue
			}
			rules, ok := auditRulesFromHost(h)
			if !ok {
				f.Status = core.StatusSkip
				f.Message = fmt.Sprintf("host %q: audit_rules unavailable (auditd not running OR no sudo)", h.Name)
				findings = append(findings, f)
				continue
			}
			matched := false
			for _, line := range rules {
				allFound := true
				for _, sub := range spec.must {
					if !strings.Contains(line, sub) {
						allFound = false
						break
					}
				}
				if allFound {
					matched = true
					break
				}
			}
			if matched {
				f.Status = core.StatusPass
				f.Message = fmt.Sprintf("host %q: audit rule watching %v is loaded", h.Name, spec.must)
			} else {
				f.Status = core.StatusFail
				f.Message = fmt.Sprintf("host %q: no loaded audit rule contains %v", h.Name, spec.must)
			}
			findings = append(findings, f)
		}
		return findings, nil
	}
}

func auditRuleCheck(spec auditRuleSpec) core.Check {
	return core.Check{
		ID: spec.id, Title: spec.title, Severity: spec.severity,
		Provider: "linux", Service: "audit", ResourceType: docol.HostType,
		Description: fmt.Sprintf("auditd watch rule for %v; CIS Linux Server v8 §%s. %s",
			spec.must, firstNonEmpty(spec.cis...), spec.descSuffix),
		Remediation: fmt.Sprintf("Append to /etc/audit/rules.d/50-cis.rules:\n  -w %s -p wa -k cis_v8\nThen `sudo augenrules --load` (RHEL family) or `sudo systemctl restart auditd` (Debian/Ubuntu).",
			spec.must[0]),
		Frameworks: map[string][]string{
			"soc2": spec.soc2, "iso27001": spec.iso, "cis-v8": spec.cis, "cis-linux-server": spec.cis,
		},
		Tags:    spec.tags,
		Scanner: spec.scanner,
	}
}

func init() {
	for _, spec := range auditRuleSpecs {
		spec := spec
		core.Register(auditRuleCheck(spec), auditRuleCheckFunc(spec))
	}
}
