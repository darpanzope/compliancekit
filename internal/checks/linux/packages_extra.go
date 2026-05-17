package linux

import (
	"context"
	"fmt"

	docol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.20 phase 9 — Packages + MAC. Two real-data checks (SELinux
// enforcing on RHEL family, AppArmor active on Debian family) +
// eight manual-verify checks for package-manager hygiene + MAC
// profile coverage that varies per distro.

// ----- real-data ---------------------------------------------------------

var CheckSELinuxEnforcing = core.Check{
	ID:           "linux-mac-selinux-enforcing",
	Title:        "SELinux must be enforcing on RHEL-family hosts",
	Severity:     core.SeverityHigh,
	Provider:     "linux",
	Service:      "mac",
	ResourceType: docol.HostType,
	Description: "SELinux 'enforcing' is the production posture — 'permissive' logs " +
		"violations without blocking them (useful only during policy tuning); " +
		"'disabled' removes the MAC layer entirely. CIS Linux Server v8 §1.7.1.4 " +
		"requires enforcing on RHEL-family hosts.",
	Remediation: "sudo setenforce 1                # live\nsudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config   # persist",
	Frameworks: map[string][]string{
		"soc2":             {"CC6.6"},
		"iso27001":         {"A.8.7"},
		"cis-v8":           {"1.7.1.4"},
		"cis-linux-server": {"1.7.1.4"},
	},
	Tags:    []string{"mac", "selinux"},
	Scanner: "linux.mac.SELinuxEnforcing",
}

func SELinuxEnforcing(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, h := range g.ByType(docol.HostType) {
		f := core.Finding{
			CheckID:  CheckSELinuxEnforcing.ID,
			Severity: CheckSELinuxEnforcing.Severity,
			Resource: h.Ref(),
			Tags:     CheckSELinuxEnforcing.Tags,
		}
		rel, _ := h.Attributes["os_release"].(docol.OSRelease)
		if !rel.IsRHELFamily() {
			f.Status = core.StatusSkip
			f.Message = fmt.Sprintf("host %q: not RHEL family; SELinux check N/A", h.Name)
			findings = append(findings, f)
			continue
		}
		mac, _ := h.Attributes["mac"].(docol.MACFacts)
		switch mac.SELinuxMode {
		case "enforcing":
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: SELinux=enforcing", h.Name)
		case "":
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("host %q: getenforce returned nothing (selinux-utils not installed?)", h.Name)
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: SELinux=%s (must be enforcing)", h.Name, mac.SELinuxMode)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckAppArmorActive = core.Check{
	ID:           "linux-mac-apparmor-active",
	Title:        "AppArmor must be active on Debian-family hosts",
	Severity:     core.SeverityHigh,
	Provider:     "linux",
	Service:      "mac",
	ResourceType: docol.HostType,
	Description: "AppArmor is the Debian/Ubuntu MAC layer. Active = kernel module loaded " +
		"AND at least one profile loaded. CIS Linux Server v8 §1.7.2.",
	Remediation: "sudo apt-get install -y apparmor apparmor-utils\nsudo systemctl enable --now apparmor\nsudo aa-enforce /etc/apparmor.d/*",
	Frameworks: map[string][]string{
		"soc2":             {"CC6.6"},
		"iso27001":         {"A.8.7"},
		"cis-v8":           {"1.7.2"},
		"cis-linux-server": {"1.7.2"},
	},
	Tags:    []string{"mac", "apparmor"},
	Scanner: "linux.mac.AppArmorActive",
}

func AppArmorActive(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, h := range g.ByType(docol.HostType) {
		f := core.Finding{
			CheckID:  CheckAppArmorActive.ID,
			Severity: CheckAppArmorActive.Severity,
			Resource: h.Ref(),
			Tags:     CheckAppArmorActive.Tags,
		}
		rel, _ := h.Attributes["os_release"].(docol.OSRelease)
		if !rel.IsDebianFamily() {
			f.Status = core.StatusSkip
			f.Message = fmt.Sprintf("host %q: not Debian family; AppArmor check N/A", h.Name)
			findings = append(findings, f)
			continue
		}
		mac, _ := h.Attributes["mac"].(docol.MACFacts)
		if mac.AppArmorActive && mac.AppArmorProfiles > 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: AppArmor active with %d loaded profiles", h.Name, mac.AppArmorProfiles)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: AppArmor not active OR no profiles loaded", h.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- manual-verify (8) ------------------------------------------------

var manualPackageChecks = []manualVerifySpec{
	{id: "linux-pkg-gpg-keys-trusted-only", title: "Package manager must trust only documented signing keys",
		severity: core.SeverityHigh, soc2: []string{"CC6.7"}, iso: []string{"A.8.32"}, cis: []string{"1.2.1.1"},
		tags:       []string{"packages", "gpg", "manual-verify"},
		descSuffix: "apt + dnf both maintain a keychain of repository signing keys. Periodic audit catches keys added during ad-hoc 'add-apt-repository' sessions that were never reviewed.",
		hint:       "`apt-key list 2>/dev/null` or `dnf repolist --enablerepo='*'`",
		scanner:    "linux.pkg.GPGKeys"},
	{id: "linux-pkg-no-unattended-upgrades", title: "Auto-updates of security patches should be enabled",
		severity: core.SeverityMedium, soc2: []string{"CC7.1"}, iso: []string{"A.8.8"}, cis: []string{"1.9"},
		tags:       []string{"packages", "patching", "manual-verify"},
		descSuffix: "Debian/Ubuntu: unattended-upgrades package. RHEL: dnf-automatic.timer. Periodic kernel + library updates without operator intervention.",
		hint:       "`systemctl is-active unattended-upgrades` OR `systemctl is-active dnf-automatic.timer`",
		scanner:    "linux.pkg.UnattendedUpgrades"},
	{id: "linux-pkg-aide-installed", title: "AIDE (file integrity) should be installed",
		severity: core.SeverityMedium, soc2: []string{"CC7.2"}, iso: []string{"A.8.7"}, cis: []string{"6.1.1"},
		tags:       []string{"packages", "aide", "manual-verify"},
		descSuffix: "AIDE periodically hashes system files + reports drift. Pair with a cron entry that emails the report.",
		hint:       "`which aide && systemctl is-active aidecheck.timer`",
		scanner:    "linux.pkg.AideInstalled"},
	{id: "linux-pkg-no-orphaned-packages", title: "Orphaned packages should be removed",
		severity: core.SeverityLow, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.9.2"},
		tags:       []string{"packages", "hygiene", "manual-verify"},
		descSuffix: "Packages with no rdepends are removable. Reduces attack surface for CVEs in dependencies the host doesn't actually use.",
		hint:       "Debian: `apt-get autoremove --dry-run`. RHEL: `dnf autoremove`",
		scanner:    "linux.pkg.NoOrphans"},
	{id: "linux-pkg-prelink-absent", title: "prelink must not be installed",
		severity: core.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.6.4"},
		tags:       []string{"packages", "prelink", "manual-verify"},
		descSuffix: "prelink rewrites ELF binaries to speed up library resolution — defeats package integrity verification (rpm -V / dpkg --verify report every binary modified).",
		hint:       "`dpkg -l prelink 2>/dev/null` or `rpm -q prelink 2>/dev/null`",
		scanner:    "linux.pkg.PrelinkAbsent"},
	{id: "linux-mac-selinux-no-permissive-services", title: "No SELinux services should be in permissive mode",
		severity: core.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.7.1.5"},
		tags:       []string{"mac", "selinux", "manual-verify"},
		descSuffix: "Per-service permissive overrides (semanage permissive) are sometimes added during policy debug + forgotten. Audit periodically.",
		hint:       "`sudo semanage permissive -l`",
		scanner:    "linux.mac.SELinuxNoPermissive"},
	{id: "linux-mac-apparmor-no-complain-mode", title: "AppArmor profiles must not be in complain mode (production)",
		severity: core.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.7.2.3"},
		tags:       []string{"mac", "apparmor", "manual-verify"},
		descSuffix: "complain-mode profiles log violations but don't enforce. Per-profile knob; verify production profiles are in enforce.",
		hint:       "`sudo aa-status | grep -A 100 'profiles are in complain mode'`",
		scanner:    "linux.mac.AppArmorNoComplain"},
	{id: "linux-pkg-cron-restricted-to-root", title: "cron.allow + at.allow must restrict to root (or specific users)",
		severity: core.SeverityLow, soc2: []string{"CC6.3"}, iso: []string{"A.5.15"}, cis: []string{"5.1.2"},
		tags:       []string{"packages", "cron", "manual-verify"},
		descSuffix: "Default cron permits every user to schedule jobs. Restrict via /etc/cron.allow (whitelist) + ensure /etc/cron.deny is empty/absent.",
		hint:       "`ls -la /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null`",
		scanner:    "linux.pkg.CronRestricted"},
}

func init() {
	core.Register(CheckSELinuxEnforcing, SELinuxEnforcing)
	core.Register(CheckAppArmorActive, AppArmorActive)
	for _, spec := range manualPackageChecks {
		spec := spec
		core.Register(manualVerifyCheck(spec), manualVerifyFunc(spec))
	}
}
