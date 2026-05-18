package linux

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	docol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 6 — sshd hardening deepening. 10 new sshd_config-shaped
// checks declared as data + registered via a loop. Same shape as the
// Phase 2 sysctl framework — adding a new sshd knob is one struct
// literal.

type sshdCmp string

const (
	sshdCmpEqNo     sshdCmp = "eq-no"     // value must equal "no"
	sshdCmpEqYes    sshdCmp = "eq-yes"    // value must equal "yes"
	sshdCmpLteInt   sshdCmp = "lte-int"   // value must be ≤ wantInt
	sshdCmpEqString sshdCmp = "eq-string" // value must equal wantString (case-insensitive)
)

type sshdSpec struct {
	id, title, key, scanner string
	cmp                     sshdCmp
	wantInt                 int
	wantString              string
	severity                compliancekit.Severity
	soc2, iso, cis          []string
	tags                    []string
	descSuffix              string
}

var sshdSpecs = []sshdSpec{
	{id: "linux-sshd-permit-empty-passwords", title: "sshd_config PermitEmptyPasswords must be no",
		key: "permitemptypasswords", cmp: sshdCmpEqNo, severity: compliancekit.SeverityHigh,
		soc2: []string{"CC6.1"}, iso: []string{"A.5.16"}, cis: []string{"5.2.10"},
		tags:       []string{"sshd", "auth"},
		descSuffix: "Empty passwords are an open door. The CIS default is no; verify even if you've never seen this misconfigured.",
		scanner:    "linux.sshd.PermitEmptyPasswords"},
	{id: "linux-sshd-x11-forwarding-disabled", title: "sshd_config X11Forwarding must be no",
		key: "x11forwarding", cmp: sshdCmpEqNo, severity: compliancekit.SeverityMedium,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"5.2.6"},
		tags:       []string{"sshd", "x11"},
		descSuffix: "X11 forwarding exposes the local DISPLAY through the SSH tunnel — historically a vector for keystroke capture. Production servers don't need it.",
		scanner:    "linux.sshd.X11Forwarding"},
	{id: "linux-sshd-permit-user-environment", title: "sshd_config PermitUserEnvironment must be no",
		key: "permituserenvironment", cmp: sshdCmpEqNo, severity: compliancekit.SeverityMedium,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"5.2.11"},
		tags:       []string{"sshd"},
		descSuffix: "PermitUserEnvironment=yes lets ~/.ssh/environment override LD_PRELOAD, PATH, etc. — sufficient for any local privilege escalation that needs an envvar.",
		scanner:    "linux.sshd.PermitUserEnvironment"},
	{id: "linux-sshd-ignore-rhosts", title: "sshd_config IgnoreRhosts must be yes",
		key: "ignorerhosts", cmp: sshdCmpEqYes, severity: compliancekit.SeverityMedium,
		soc2: []string{"CC6.1"}, iso: []string{"A.5.16"}, cis: []string{"5.2.7"},
		tags:       []string{"sshd", "rhosts"},
		descSuffix: ".rhosts is rsh-era trust; IgnoreRhosts=yes (the default) tells sshd not to honor the file.",
		scanner:    "linux.sshd.IgnoreRhosts"},
	{id: "linux-sshd-hostbased-auth-disabled", title: "sshd_config HostbasedAuthentication must be no",
		key: "hostbasedauthentication", cmp: sshdCmpEqNo, severity: compliancekit.SeverityMedium,
		soc2: []string{"CC6.1"}, iso: []string{"A.5.16"}, cis: []string{"5.2.8"},
		tags:       []string{"sshd"},
		descSuffix: "Host-based authentication trusts the client host's hostkey — a per-host trust model that's hard to revoke and easy to mismanage.",
		scanner:    "linux.sshd.HostbasedAuth"},
	{id: "linux-sshd-client-alive-interval", title: "sshd_config ClientAliveInterval must be > 0 and ≤ 300",
		key: "clientaliveinterval", cmp: sshdCmpLteInt, wantInt: 300, severity: compliancekit.SeverityLow,
		soc2: []string{"CC6.1"}, iso: []string{"A.5.16"}, cis: []string{"5.2.14"},
		tags:       []string{"sshd", "session"},
		descSuffix: "Idle SSH sessions get reaped after ClientAliveInterval × ClientAliveCountMax seconds. ≤300s caps abandoned tmux/screen sessions.",
		scanner:    "linux.sshd.ClientAliveInterval"},
	{id: "linux-sshd-client-alive-count-max", title: "sshd_config ClientAliveCountMax must be ≤ 3",
		key: "clientalivecountmax", cmp: sshdCmpLteInt, wantInt: 3, severity: compliancekit.SeverityLow,
		soc2: []string{"CC6.1"}, iso: []string{"A.5.16"}, cis: []string{"5.2.15"},
		tags:       []string{"sshd", "session"},
		descSuffix: "ClientAliveCountMax × ClientAliveInterval is the idle ceiling. ≤3 (CIS recommended) keeps the total under ~15 min when paired with the recommended interval.",
		scanner:    "linux.sshd.ClientAliveCountMax"},
	{id: "linux-sshd-max-sessions", title: "sshd_config MaxSessions must be ≤ 10",
		key: "maxsessions", cmp: sshdCmpLteInt, wantInt: 10, severity: compliancekit.SeverityLow,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"5.2.21"},
		tags:       []string{"sshd"},
		descSuffix: "MaxSessions caps the concurrent sessions one auth'd user may open. ≤10 (CIS) constrains a compromised key's blast radius.",
		scanner:    "linux.sshd.MaxSessions"},
	{id: "linux-sshd-banner-set", title: "sshd_config Banner must be set (typically /etc/issue.net)",
		key: "banner", cmp: sshdCmpEqString, wantString: "/etc/issue.net", severity: compliancekit.SeverityLow,
		soc2: []string{"CC1.4"}, iso: []string{"A.5.10"}, cis: []string{"5.2.13"},
		tags:       []string{"sshd", "banner"},
		descSuffix: "Login banner is the audit-evidence point for legal-notice display. /etc/issue.net is the CIS-conventional path.",
		scanner:    "linux.sshd.Banner"},
	{id: "linux-sshd-loglevel-info-or-verbose", title: "sshd_config LogLevel must be INFO or VERBOSE",
		key: "loglevel", cmp: sshdCmpEqString, wantString: "VERBOSE", severity: compliancekit.SeverityMedium,
		soc2: []string{"CC7.2"}, iso: []string{"A.8.15"}, cis: []string{"5.2.5"},
		tags:       []string{"sshd", "logging"},
		descSuffix: "VERBOSE logs key fingerprints for every login (essential for audit). INFO is the upstream default and acceptable; QUIET drops too much detail.",
		scanner:    "linux.sshd.LogLevel"},
}

func sshdCheck(spec sshdSpec) compliancekit.Check {
	return compliancekit.Check{
		ID: spec.id, Title: spec.title, Severity: spec.severity,
		Provider: "linux", Service: "sshd", ResourceType: docol.HostType,
		Description: fmt.Sprintf("%s; CIS Linux Server v8 §%s. %s",
			spec.key, firstNonEmpty(spec.cis...), spec.descSuffix),
		Remediation: renderSshdRemediation(spec),
		Frameworks: map[string][]string{
			"soc2": spec.soc2, "iso27001": spec.iso, "cis-v8": spec.cis, "cis-linux-server": spec.cis,
		},
		Tags:    spec.tags,
		Scanner: spec.scanner,
	}
}

func renderSshdRemediation(spec sshdSpec) string {
	switch spec.cmp {
	case sshdCmpEqYes:
		return fmt.Sprintf("Edit /etc/ssh/sshd_config:\n  %s yes\nThen `sudo systemctl reload sshd`.", spec.key)
	case sshdCmpEqNo:
		return fmt.Sprintf("Edit /etc/ssh/sshd_config:\n  %s no\nThen `sudo systemctl reload sshd`.", spec.key)
	case sshdCmpLteInt:
		return fmt.Sprintf("Edit /etc/ssh/sshd_config:\n  %s %d\nThen `sudo systemctl reload sshd`.", spec.key, spec.wantInt)
	case sshdCmpEqString:
		return fmt.Sprintf("Edit /etc/ssh/sshd_config:\n  %s %s\nThen `sudo systemctl reload sshd`.", spec.key, spec.wantString)
	}
	return ""
}

func sshdCheckFunc(spec sshdSpec) compliancekit.CheckFunc {
	return func(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
		findings := []compliancekit.Finding{}
		for _, h := range g.ByType(docol.HostType) {
			f := compliancekit.Finding{
				CheckID:  spec.id,
				Severity: spec.severity,
				Resource: h.Ref(),
				Tags:     spec.tags,
			}
			cfg, ok := sshdConfigOf(h)
			if !ok {
				f.Status = compliancekit.StatusSkip
				f.Message = fmt.Sprintf("host %q: sshd_config unavailable", h.Name)
				findings = append(findings, f)
				continue
			}
			val := cfg[spec.key]
			pass, msg := sshdEvaluate(spec, val, h.Name)
			if pass {
				f.Status = compliancekit.StatusPass
			} else {
				f.Status = compliancekit.StatusFail
			}
			f.Message = msg
			findings = append(findings, f)
		}
		return findings, nil
	}
}

func sshdEvaluate(spec sshdSpec, value, host string) (pass bool, msg string) {
	lower := strings.ToLower(strings.TrimSpace(value))
	switch spec.cmp {
	case sshdCmpEqYes:
		if lower == "yes" {
			return true, fmt.Sprintf("host %q: %s=yes", host, spec.key)
		}
		return false, fmt.Sprintf("host %q: %s=%q (want yes)", host, spec.key, value)
	case sshdCmpEqNo:
		if lower == "no" {
			return true, fmt.Sprintf("host %q: %s=no", host, spec.key)
		}
		return false, fmt.Sprintf("host %q: %s=%q (want no)", host, spec.key, value)
	case sshdCmpLteInt:
		i, err := strconv.Atoi(lower)
		if err != nil {
			return false, fmt.Sprintf("host %q: %s=%q (must be integer ≤ %d)", host, spec.key, value, spec.wantInt)
		}
		if i > 0 && i <= spec.wantInt {
			return true, fmt.Sprintf("host %q: %s=%d (≤ %d)", host, spec.key, i, spec.wantInt)
		}
		return false, fmt.Sprintf("host %q: %s=%d (must be 1..%d)", host, spec.key, i, spec.wantInt)
	case sshdCmpEqString:
		if strings.EqualFold(lower, spec.wantString) {
			return true, fmt.Sprintf("host %q: %s=%s", host, spec.key, value)
		}
		// LogLevel: VERBOSE recommended but INFO accepted.
		if spec.key == "loglevel" && (lower == "info" || lower == "verbose") {
			return true, fmt.Sprintf("host %q: %s=%s (acceptable)", host, spec.key, value)
		}
		return false, fmt.Sprintf("host %q: %s=%q (want %s)", host, spec.key, value, spec.wantString)
	}
	return false, fmt.Sprintf("host %q: unknown sshd cmp %q", host, spec.cmp)
}

func init() {
	for _, spec := range sshdSpecs {
		spec := spec
		compliancekit.Register(sshdCheck(spec), sshdCheckFunc(spec))
	}
}
