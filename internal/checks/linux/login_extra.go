package linux

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	docol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.20 phase 5 — PAM + sudo + login.defs hardening. Five real-data
// checks read /etc/login.defs (PASS_MAX_DAYS / PASS_MIN_DAYS / etc.);
// five manual-verify checks cover the controls compliancekit doesn't
// yet model in detail (per-distro PAM stacks, sudoers semantics).
// Per ADR-013 manual-verify findings stay actionable so the auditor
// records compensating evidence (screenshot, runbook excerpt) and
// waives via waivers.yaml.

// ----- login.defs real-data checks --------------------------------------

func loginDefsFromHost(h core.Resource) (docol.LoginDefs, bool) {
	v, ok := h.Attributes["login_defs"].(docol.LoginDefs)
	return v, ok
}

func newLoginFinding(check core.Check, h core.Resource) core.Finding {
	return core.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Resource: h.Ref(),
		Tags:     check.Tags,
	}
}

var CheckPassMaxDays = core.Check{
	ID:           "linux-login-defs-pass-max-days",
	Title:        "/etc/login.defs PASS_MAX_DAYS must be ≤ 365",
	Severity:     core.SeverityMedium,
	Provider:     "linux",
	Service:      "auth",
	ResourceType: docol.HostType,
	Description: "PASS_MAX_DAYS bounds the maximum password lifetime for accounts " +
		"created from /etc/login.defs defaults. CIS Linux Server v8 §5.5.1.1 " +
		"requires ≤365 (NIST 800-63B aligned). Existing accounts may need " +
		"`chage --maxdays` separately.",
	Remediation: "Edit /etc/login.defs:\n  PASS_MAX_DAYS   365\nApply to existing users:\n  awk -F: '($3>=1000 && $3<60000) {print $1}' /etc/passwd | xargs -I{} chage --maxdays 365 {}",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.17"},
		"cis-v8":   {"5.5.1.1"},
	},
	Tags:    []string{"auth", "password-age"},
	Scanner: "linux.login.PassMaxDays",
}

func PassMaxDays(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, h := range g.ByType(docol.HostType) {
		f := newLoginFinding(CheckPassMaxDays, h)
		ld, ok := loginDefsFromHost(h)
		if !ok {
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("host %q: login_defs unavailable", h.Name)
			findings = append(findings, f)
			continue
		}
		switch {
		case !ld.HasPassMaxDays:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: PASS_MAX_DAYS not set in /etc/login.defs", h.Name)
		case ld.PassMaxDays <= 365 && ld.PassMaxDays > 0:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: PASS_MAX_DAYS=%d (≤365)", h.Name, ld.PassMaxDays)
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: PASS_MAX_DAYS=%d (must be 1..365)", h.Name, ld.PassMaxDays)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckPassMinDays = core.Check{
	ID:           "linux-login-defs-pass-min-days",
	Title:        "/etc/login.defs PASS_MIN_DAYS must be ≥ 1",
	Severity:     core.SeverityMedium,
	Provider:     "linux",
	Service:      "auth",
	ResourceType: docol.HostType,
	Description: "PASS_MIN_DAYS prevents a user from cycling through their password " +
		"history in a single sitting (defeats reuse-prevention). CIS §5.5.1.2 requires ≥1.",
	Remediation: "/etc/login.defs:\n  PASS_MIN_DAYS   1",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.17"},
		"cis-v8":   {"5.5.1.2"},
	},
	Tags:    []string{"auth", "password-age"},
	Scanner: "linux.login.PassMinDays",
}

func PassMinDays(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, h := range g.ByType(docol.HostType) {
		f := newLoginFinding(CheckPassMinDays, h)
		ld, ok := loginDefsFromHost(h)
		if !ok {
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("host %q: login_defs unavailable", h.Name)
			findings = append(findings, f)
			continue
		}
		switch {
		case !ld.HasPassMinDays:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: PASS_MIN_DAYS not set", h.Name)
		case ld.PassMinDays >= 1:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: PASS_MIN_DAYS=%d (≥1)", h.Name, ld.PassMinDays)
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: PASS_MIN_DAYS=%d (must be ≥1)", h.Name, ld.PassMinDays)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckPassWarnAge = core.Check{
	ID:           "linux-login-defs-pass-warn-age",
	Title:        "/etc/login.defs PASS_WARN_AGE must be ≥ 7",
	Severity:     core.SeverityLow,
	Provider:     "linux",
	Service:      "auth",
	ResourceType: docol.HostType,
	Description: "PASS_WARN_AGE controls how many days ahead of expiry the user " +
		"sees a warning at login. ≥7 days gives the user a meaningful chance " +
		"to rotate before being locked out. CIS §5.5.1.3.",
	Remediation: "/etc/login.defs:\n  PASS_WARN_AGE   7",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.17"},
		"cis-v8":   {"5.5.1.3"},
	},
	Tags:    []string{"auth", "password-age"},
	Scanner: "linux.login.PassWarnAge",
}

func PassWarnAge(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, h := range g.ByType(docol.HostType) {
		f := newLoginFinding(CheckPassWarnAge, h)
		ld, ok := loginDefsFromHost(h)
		if !ok {
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("host %q: login_defs unavailable", h.Name)
			findings = append(findings, f)
			continue
		}
		switch {
		case !ld.HasPassWarnAge:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: PASS_WARN_AGE not set", h.Name)
		case ld.PassWarnAge >= 7:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: PASS_WARN_AGE=%d (≥7)", h.Name, ld.PassWarnAge)
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: PASS_WARN_AGE=%d (must be ≥7)", h.Name, ld.PassWarnAge)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckEncryptMethod = core.Check{
	ID:           "linux-login-defs-encrypt-method",
	Title:        "/etc/login.defs ENCRYPT_METHOD must be SHA512 or YESCRYPT",
	Severity:     core.SeverityHigh,
	Provider:     "linux",
	Service:      "auth",
	ResourceType: docol.HostType,
	Description: "ENCRYPT_METHOD controls the hash algorithm used to store new " +
		"user passwords in /etc/shadow. SHA512 + YESCRYPT are the only " +
		"acceptable choices in 2026 (DES + MD5 are trivially crackable; " +
		"SHA256 is acceptable but SHA512 is the explicit CIS pick). " +
		"CIS Linux Server v8 §5.5.1.4.",
	Remediation: "/etc/login.defs:\n  ENCRYPT_METHOD YESCRYPT   # or SHA512\nRehash existing accounts on next password change.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"5.5.1.4"},
	},
	Tags:    []string{"auth", "password-hashing"},
	Scanner: "linux.login.EncryptMethod",
}

func EncryptMethod(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, h := range g.ByType(docol.HostType) {
		f := newLoginFinding(CheckEncryptMethod, h)
		ld, ok := loginDefsFromHost(h)
		if !ok {
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("host %q: login_defs unavailable", h.Name)
			findings = append(findings, f)
			continue
		}
		method := strings.ToUpper(ld.EncryptMethod)
		switch method {
		case "SHA512", "YESCRYPT":
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: ENCRYPT_METHOD=%s", h.Name, method)
		case "":
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: ENCRYPT_METHOD not set; relies on PAM default which may be SHA256/MD5", h.Name)
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: ENCRYPT_METHOD=%s (must be SHA512 or YESCRYPT)", h.Name, method)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckUmask = core.Check{
	ID:           "linux-login-defs-umask",
	Title:        "/etc/login.defs UMASK must be 027 or stricter",
	Severity:     core.SeverityMedium,
	Provider:     "linux",
	Service:      "auth",
	ResourceType: docol.HostType,
	Description: "Default UMASK 022 (group + world readable) is too permissive for " +
		"shared / multi-tenant systems. 027 (no group write, no world access) " +
		"is the CIS Linux Server v8 §5.5.5 recommendation.",
	Remediation: "/etc/login.defs:\n  UMASK   027\nAlso check /etc/profile.d/*.sh + /etc/bashrc for shell-level overrides.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.7"},
		"cis-v8":   {"5.5.5"},
	},
	Tags:    []string{"auth", "umask"},
	Scanner: "linux.login.Umask",
}

func UmaskCheck(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, h := range g.ByType(docol.HostType) {
		f := newLoginFinding(CheckUmask, h)
		ld, ok := loginDefsFromHost(h)
		if !ok {
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("host %q: login_defs unavailable", h.Name)
			findings = append(findings, f)
			continue
		}
		if !ld.HasUmask {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: UMASK not set", h.Name)
			findings = append(findings, f)
			continue
		}
		if umaskAtLeast(ld.Umask, 0o27) {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: UMASK=%s (≥ 027)", h.Name, ld.Umask)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: UMASK=%s (must be 027 or stricter)", h.Name, ld.Umask)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// umaskAtLeast reports whether the given umask (octal, possibly with
// leading 0) is at least as strict as floor (a higher umask = stricter
// because umask bits are inverted permissions).
func umaskAtLeast(umask string, floor int) bool {
	s := strings.TrimLeft(umask, "0")
	if s == "" {
		s = "0"
	}
	v, err := strconv.ParseInt(s, 8, 32)
	if err != nil {
		return false
	}
	return int(v)&floor == floor
}

// ----- manual-verify checks ---------------------------------------------

var manualLoginChecks = []manualVerifySpec{
	{id: "linux-sudo-nopasswd-audit", title: "Audit /etc/sudoers + /etc/sudoers.d for NOPASSWD entries",
		severity: core.SeverityHigh, soc2: []string{"CC6.3"}, iso: []string{"A.5.15"}, cis: []string{"5.4.4"},
		tags:       []string{"sudo", "manual-verify"},
		descSuffix: "NOPASSWD entries let a compromised account elevate without re-auth. Every entry should be (a) auditable + (b) narrowly scoped (Cmnd_Alias) — not blanket. Per-distro PAM + sudoers parsing is deferred to a future milestone; verify manually.",
		hint:       "`sudo grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/`",
		scanner:    "linux.sudo.NopasswdAudit"},
	{id: "linux-sudo-secure-path", title: "/etc/sudoers must set secure_path (no user-controlled PATH)",
		severity: core.SeverityMedium, soc2: []string{"CC6.3"}, iso: []string{"A.5.15"}, cis: []string{"5.4.3"},
		tags:       []string{"sudo", "manual-verify"},
		descSuffix: "secure_path strips the user's PATH and substitutes a hardcoded list — prevents trojan binaries in ~/bin from being run via sudo. Distro defaults differ; verify.",
		hint:       "`sudo grep ^Defaults.*secure_path /etc/sudoers`",
		scanner:    "linux.sudo.SecurePath"},
	{id: "linux-sudo-logging", title: "sudo must log to syslog or a dedicated log file",
		severity: core.SeverityMedium, soc2: []string{"CC7.2"}, iso: []string{"A.8.15"}, cis: []string{"5.4.5"},
		tags:       []string{"sudo", "manual-verify"},
		descSuffix: "sudo's default logging is via syslog. Verify the syslog target collects sudoers entries OR add a Defaults logfile= line.",
		hint:       "`sudo grep -E '^Defaults.*(logfile|syslog)' /etc/sudoers`",
		scanner:    "linux.sudo.Logging"},
	{id: "linux-pam-faillock-configured", title: "PAM must enforce account lockout after failed attempts (faillock / tally2)",
		severity: core.SeverityHigh, soc2: []string{"CC6.1"}, iso: []string{"A.8.5"}, cis: []string{"5.4.2.1"},
		tags:       []string{"pam", "manual-verify"},
		descSuffix: "faillock (RHEL family, Ubuntu 22.04+) or pam_tally2 (older) implements account lockout after N failed password attempts. PAM stack varies per distro; verify the appropriate module is present + configured (CIS recommends deny=5, unlock_time=900).",
		hint:       "`sudo grep -E 'pam_faillock|pam_tally2' /etc/pam.d/* | head`",
		scanner:    "linux.pam.Faillock"},
	{id: "linux-pam-pwquality-configured", title: "PAM pwquality must enforce length + complexity",
		severity: core.SeverityMedium, soc2: []string{"CC6.1"}, iso: []string{"A.5.17"}, cis: []string{"5.4.3.1"},
		tags:       []string{"pam", "manual-verify"},
		descSuffix: "pam_pwquality (or pam_passwdqc) enforces minimum password length (≥14 per CIS) + complexity classes. /etc/security/pwquality.conf carries the knobs.",
		hint:       "`sudo cat /etc/security/pwquality.conf | grep -v '^#'`",
		scanner:    "linux.pam.Pwquality"},
}

type manualVerifySpec struct {
	id, title        string
	severity         core.Severity
	soc2, iso, cis   []string
	tags             []string
	descSuffix, hint string
	scanner          string
}

func manualVerifyCheck(spec manualVerifySpec) core.Check {
	return core.Check{
		ID: spec.id, Title: spec.title, Severity: spec.severity,
		Provider: "linux", Service: "auth", ResourceType: docol.HostType,
		Description: fmt.Sprintf("Manual-verify check; CIS Linux Server v8 §%s. %s",
			firstNonEmpty(spec.cis...), spec.descSuffix),
		Remediation: fmt.Sprintf("Per-distro PAM + sudoers grammars are deferred; verify via %s + record evidence (screenshot or shell output) in waivers.yaml per ADR-013.", spec.hint),
		Frameworks: map[string][]string{
			"soc2": spec.soc2, "iso27001": spec.iso, "cis-v8": spec.cis, "cis-linux-server": spec.cis,
		},
		Tags:    spec.tags,
		Scanner: spec.scanner,
	}
}

func manualVerifyFunc(spec manualVerifySpec) core.CheckFunc {
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
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("host %q: manual-verify — run %s and record evidence", h.Name, spec.hint)
			findings = append(findings, f)
		}
		return findings, nil
	}
}

func init() {
	core.Register(CheckPassMaxDays, PassMaxDays)
	core.Register(CheckPassMinDays, PassMinDays)
	core.Register(CheckPassWarnAge, PassWarnAge)
	core.Register(CheckEncryptMethod, EncryptMethod)
	core.Register(CheckUmask, UmaskCheck)
	for _, spec := range manualLoginChecks {
		spec := spec
		core.Register(manualVerifyCheck(spec), manualVerifyFunc(spec))
	}
}
