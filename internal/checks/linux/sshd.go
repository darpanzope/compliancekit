// Package linux holds the Linux check implementations.
//
// Each check operates on the "linux.host" Resources emitted by the
// linux collector (internal/collectors/linux). Helper functions live
// here for resource attribute extraction common across many checks.
//
// Per v0.2 ROADMAP §9, the Linux check set targets CIS Ubuntu / Debian
// directives weighted for "what actually matters in 2026". v0.2 ships
// 15 checks total; this file holds the five sshd hardening checks.
package linux

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

// sshdConfigOf returns the parsed sshd_config from a host Resource, or
// (nil, false) when the host was unreachable, sshd probe failed, or
// the attribute is otherwise missing. Every sshd check uses this
// helper so the skip path lives in one place.
func sshdConfigOf(host core.Resource) (map[string]string, bool) {
	if !host.AttrBool("reachable") {
		return nil, false
	}
	raw, ok := host.Attributes["sshd_config"]
	if !ok {
		return nil, false
	}
	cfg, ok := raw.(map[string]string)
	if !ok {
		return nil, false
	}
	return cfg, true
}

// skipFinding builds the StatusSkip finding every sshd check emits
// when its data is unavailable (host unreachable, sshd probe failed,
// or the attribute missing). Severity is denormalized from the check
// so the report reads the same shape as a Pass/Fail row.
//
// The reason is constant for now -- future gatherers may want to
// distinguish "unreachable" vs "sshd probe failed" but every existing
// check folds those into the same Skip with the same message.
func skipFinding(check core.Check, host core.Resource) core.Finding {
	return core.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Status:   core.StatusSkip,
		Resource: host.Ref(),
		Message:  "sshd config unavailable",
		Tags:     check.Tags,
	}
}

// ============================================================
// linux-sshd-no-root-login
// ============================================================

// CheckSSHDNoRootLogin requires PermitRootLogin=no.
var CheckSSHDNoRootLogin = core.Check{
	ID:           "linux-sshd-no-root-login",
	Title:        "SSH must not permit root login",
	Severity:     core.SeverityHigh,
	Provider:     "linux",
	Service:      "sshd",
	ResourceType: linuxcol.HostType,
	Description: "Direct root SSH logins bypass per-user auditability " +
		"and remove the speed bump that catches automated brute-force. " +
		"SOC 2 CC6.1 / CC6.6, ISO 27001 A.8.21, and CIS Controls v8 " +
		"5.4 all require unique attribution for privileged access.",
	Remediation: "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and " +
		"reload sshd (systemctl reload sshd). Operators should use a " +
		"named user + sudo instead.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.21"},
		"cis-v8":   {"5.4"},
	},
	Tags:    []string{"sshd", "access-control"},
	Scanner: "sshd.NoRootLogin",
}

// SSHDNoRootLogin is the CheckFunc for CheckSSHDNoRootLogin.
func SSHDNoRootLogin(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	hosts := g.ByType(linuxcol.HostType)
	findings := make([]core.Finding, 0, len(hosts))
	for _, h := range hosts {
		cfg, ok := sshdConfigOf(h)
		if !ok {
			findings = append(findings, skipFinding(CheckSSHDNoRootLogin, h))
			continue
		}
		v := cfg["permitrootlogin"]
		f := core.Finding{
			CheckID:  CheckSSHDNoRootLogin.ID,
			Severity: CheckSSHDNoRootLogin.Severity,
			Resource: h.Ref(),
			Tags:     CheckSSHDNoRootLogin.Tags,
		}
		if v == "no" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: PermitRootLogin=no", h.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: PermitRootLogin=%q (want no)", h.Name, v)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ============================================================
// linux-sshd-no-password-auth
// ============================================================

// CheckSSHDNoPasswordAuth requires PasswordAuthentication=no.
var CheckSSHDNoPasswordAuth = core.Check{
	ID:           "linux-sshd-no-password-auth",
	Title:        "SSH must not accept password authentication",
	Severity:     core.SeverityMedium,
	Provider:     "linux",
	Service:      "sshd",
	ResourceType: linuxcol.HostType,
	Description: "Password authentication exposes SSH to credential " +
		"stuffing and online brute-force. Public-key authentication " +
		"is the modern baseline. SOC 2 CC6.1 and CIS Controls v8 5.2 " +
		"both require strong authentication for remote administrative " +
		"access.",
	Remediation: "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config " +
		"(and confirm operators have working public-key access first to " +
		"avoid lockout). Reload sshd to apply.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.5", "A.8.21"},
		"cis-v8":   {"5.2", "6.5"},
	},
	Tags:    []string{"sshd", "authentication"},
	Scanner: "sshd.NoPasswordAuth",
}

// SSHDNoPasswordAuth is the CheckFunc for CheckSSHDNoPasswordAuth.
func SSHDNoPasswordAuth(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	hosts := g.ByType(linuxcol.HostType)
	findings := make([]core.Finding, 0, len(hosts))
	for _, h := range hosts {
		cfg, ok := sshdConfigOf(h)
		if !ok {
			findings = append(findings, skipFinding(CheckSSHDNoPasswordAuth, h))
			continue
		}
		v := cfg["passwordauthentication"]
		f := core.Finding{
			CheckID:  CheckSSHDNoPasswordAuth.ID,
			Severity: CheckSSHDNoPasswordAuth.Severity,
			Resource: h.Ref(),
			Tags:     CheckSSHDNoPasswordAuth.Tags,
		}
		if v == "no" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: PasswordAuthentication=no", h.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: PasswordAuthentication=%q (want no)", h.Name, v)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ============================================================
// linux-sshd-protocol-2
// ============================================================

// CheckSSHDProtocol2 requires Protocol 2 (SSH-1 is ancient and broken).
var CheckSSHDProtocol2 = core.Check{
	ID:           "linux-sshd-protocol-2",
	Title:        "SSH must use protocol version 2 only",
	Severity:     core.SeverityLow,
	Provider:     "linux",
	Service:      "sshd",
	ResourceType: linuxcol.HostType,
	Description: "SSH-1 was retired in 2017 and is cryptographically " +
		"broken. Modern OpenSSH defaults to Protocol 2 and refuses to " +
		"build SSH-1 without explicit flags; this check confirms the " +
		"observed config has not been weakened. Mostly an audit-trail " +
		"check at this point.",
	Remediation: "Remove any 'Protocol 1' line from /etc/ssh/sshd_config " +
		"(or set 'Protocol 2' explicitly). Reload sshd to apply.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"sshd", "crypto"},
	Scanner: "sshd.Protocol2",
}

// SSHDProtocol2 is the CheckFunc for CheckSSHDProtocol2.
func SSHDProtocol2(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	hosts := g.ByType(linuxcol.HostType)
	findings := make([]core.Finding, 0, len(hosts))
	for _, h := range hosts {
		cfg, ok := sshdConfigOf(h)
		if !ok {
			findings = append(findings, skipFinding(CheckSSHDProtocol2, h))
			continue
		}
		// `sshd -T` does not emit Protocol on modern OpenSSH (it is
		// always 2 and the directive is deprecated). Treat "missing"
		// as Pass to avoid a noisy finding on every modern host;
		// "explicit non-2" is a Fail.
		v, present := cfg["protocol"]
		f := core.Finding{
			CheckID:  CheckSSHDProtocol2.ID,
			Severity: CheckSSHDProtocol2.Severity,
			Resource: h.Ref(),
			Tags:     CheckSSHDProtocol2.Tags,
		}
		switch {
		case !present:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: Protocol directive absent (modern OpenSSH default is 2)", h.Name)
		case v == "2":
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: Protocol=2", h.Name)
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: Protocol=%q (want 2)", h.Name, v)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ============================================================
// linux-sshd-max-auth-tries
// ============================================================

// MaxAuthTriesCeiling is the highest value at which MaxAuthTries
// remains compliant. Operators routinely lower it further; 4 is the
// CIS-recommended ceiling.
const MaxAuthTriesCeiling = 4

// CheckSSHDMaxAuthTries flags MaxAuthTries > MaxAuthTriesCeiling.
var CheckSSHDMaxAuthTries = core.Check{
	ID:           "linux-sshd-max-auth-tries",
	Title:        "SSH MaxAuthTries should be 4 or less",
	Severity:     core.SeverityLow,
	Provider:     "linux",
	Service:      "sshd",
	ResourceType: linuxcol.HostType,
	Description: "MaxAuthTries caps the number of authentication " +
		"attempts per connection; a low value frustrates online " +
		"brute-force. The OpenSSH default is 6; CIS Controls v8 " +
		"recommends 4 or less.",
	Remediation: "Set 'MaxAuthTries 4' (or lower) in /etc/ssh/sshd_config " +
		"and reload sshd.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.21"},
		"cis-v8":   {"5.2"},
	},
	Tags:    []string{"sshd", "brute-force"},
	Scanner: "sshd.MaxAuthTries",
}

// SSHDMaxAuthTries is the CheckFunc for CheckSSHDMaxAuthTries.
func SSHDMaxAuthTries(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	hosts := g.ByType(linuxcol.HostType)
	findings := make([]core.Finding, 0, len(hosts))
	for _, h := range hosts {
		cfg, ok := sshdConfigOf(h)
		if !ok {
			findings = append(findings, skipFinding(CheckSSHDMaxAuthTries, h))
			continue
		}
		raw, present := cfg["maxauthtries"]
		f := core.Finding{
			CheckID:  CheckSSHDMaxAuthTries.ID,
			Severity: CheckSSHDMaxAuthTries.Severity,
			Resource: h.Ref(),
			Tags:     CheckSSHDMaxAuthTries.Tags,
		}
		if !present {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: MaxAuthTries absent (OpenSSH default is 6, exceeds ceiling %d)", h.Name, MaxAuthTriesCeiling)
			findings = append(findings, f)
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		switch {
		case err != nil:
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("host %q: MaxAuthTries=%q is not an integer", h.Name, raw)
		case n <= MaxAuthTriesCeiling:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: MaxAuthTries=%d", h.Name, n)
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: MaxAuthTries=%d (ceiling %d)", h.Name, n, MaxAuthTriesCeiling)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ============================================================
// linux-sshd-login-grace-time
// ============================================================

// LoginGraceTimeCeilingSeconds is the maximum LoginGraceTime in
// seconds. Lower values frustrate online brute-force by tying up
// fewer connection slots.
const LoginGraceTimeCeilingSeconds = 60

// CheckSSHDLoginGraceTime flags LoginGraceTime > 60s.
var CheckSSHDLoginGraceTime = core.Check{
	ID:           "linux-sshd-login-grace-time",
	Title:        "SSH LoginGraceTime should be 60 seconds or less",
	Severity:     core.SeverityLow,
	Provider:     "linux",
	Service:      "sshd",
	ResourceType: linuxcol.HostType,
	Description: "LoginGraceTime is the window between connection " +
		"and authentication completion. A long window lets a misbehaving " +
		"client (or attacker) hold a connection slot open, enabling " +
		"slowloris-style resource exhaustion. OpenSSH default is 2 " +
		"minutes; CIS recommends 60 seconds or less.",
	Remediation: "Set 'LoginGraceTime 60' in /etc/ssh/sshd_config and " +
		"reload sshd.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.20", "A.8.21"},
		"cis-v8":   {"5.2", "8.5"},
	},
	Tags:    []string{"sshd", "resource-exhaustion"},
	Scanner: "sshd.LoginGraceTime",
}

// SSHDLoginGraceTime is the CheckFunc for CheckSSHDLoginGraceTime.
func SSHDLoginGraceTime(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	hosts := g.ByType(linuxcol.HostType)
	findings := make([]core.Finding, 0, len(hosts))
	for _, h := range hosts {
		cfg, ok := sshdConfigOf(h)
		if !ok {
			findings = append(findings, skipFinding(CheckSSHDLoginGraceTime, h))
			continue
		}
		raw, present := cfg["logingracetime"]
		f := core.Finding{
			CheckID:  CheckSSHDLoginGraceTime.ID,
			Severity: CheckSSHDLoginGraceTime.Severity,
			Resource: h.Ref(),
			Tags:     CheckSSHDLoginGraceTime.Tags,
		}
		if !present {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: LoginGraceTime absent (OpenSSH default 120s exceeds ceiling %ds)", h.Name, LoginGraceTimeCeilingSeconds)
			findings = append(findings, f)
			continue
		}
		seconds, err := parseSSHDDuration(raw)
		switch {
		case err != nil:
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("host %q: LoginGraceTime=%q is not a parseable duration", h.Name, raw)
		case seconds <= LoginGraceTimeCeilingSeconds:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: LoginGraceTime=%ds", h.Name, seconds)
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: LoginGraceTime=%ds (ceiling %ds)", h.Name, seconds, LoginGraceTimeCeilingSeconds)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// parseSSHDDuration accepts the sshd_config time format: a bare integer
// is seconds; suffixes s/m/h/d/w scale accordingly. Examples: "60",
// "60s", "2m", "1h". Returns the value in seconds.
//
// Reference: sshd_config(5) "TIME FORMATS".
func parseSSHDDuration(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	last := s[len(s)-1]
	multiplier := 1
	switch last {
	case 's', 'S':
		multiplier = 1
		s = s[:len(s)-1]
	case 'm', 'M':
		multiplier = 60
		s = s[:len(s)-1]
	case 'h', 'H':
		multiplier = 3600
		s = s[:len(s)-1]
	case 'd', 'D':
		multiplier = 86400
		s = s[:len(s)-1]
	case 'w', 'W':
		multiplier = 604800
		s = s[:len(s)-1]
	default:
		// no suffix; treat as seconds
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	return n * multiplier, nil
}

// init registers every check in this file with the default registry.
// cmd/compliancekit imports this package for its side effects.
func init() {
	core.Register(CheckSSHDNoRootLogin, SSHDNoRootLogin)
	core.Register(CheckSSHDNoPasswordAuth, SSHDNoPasswordAuth)
	core.Register(CheckSSHDProtocol2, SSHDProtocol2)
	core.Register(CheckSSHDMaxAuthTries, SSHDMaxAuthTries)
	core.Register(CheckSSHDLoginGraceTime, SSHDLoginGraceTime)
}
