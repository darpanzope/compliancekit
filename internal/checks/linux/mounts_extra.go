package linux

import (
	"context"
	"fmt"

	docol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 3 — filesystem hardening: separate-partition + mount-
// option enforcement on the standard CIS Linux Server v8 §1.1 set
// of mount points (/tmp, /var, /var/log, /var/log/audit, /home,
// /dev/shm, /boot, /var/tmp).
//
// Two check shapes, both data-driven:
//
//   - mountSeparateSpec — asserts the path is mounted as its own
//     filesystem (not just a directory in the root mount).
//   - mountOptionSpec   — asserts the mount carries the named option
//     (nodev / nosuid / noexec).
//
// Both pull from host.attributes["mounts"].([]docol.MountEntry); a
// missing mount → StatusSkip on the option checks (separate gate
// already failed), StatusFail on the separate gate itself.

// ----- separate-partition specs -----------------------------------------

type mountSeparateSpec struct {
	id, title, scanner string
	target             string
	severity           compliancekit.Severity
	soc2, iso, cis     []string
	tags               []string
	descSuffix         string
}

var mountSeparateSpecs = []mountSeparateSpec{
	{id: "linux-mount-tmp-separate", title: "/tmp must be its own filesystem", target: "/tmp",
		severity: compliancekit.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.1.2.1"},
		tags:       []string{"mount", "separate-partition"},
		descSuffix: "Isolating /tmp lets the operator quota it, mount it with nodev/nosuid/noexec, and reset it on reboot — none of which work when /tmp is a directory in /.",
		scanner:    "linux.mounts.TmpSeparate"},
	{id: "linux-mount-var-separate", title: "/var must be its own filesystem", target: "/var",
		severity: compliancekit.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.1.3.1"},
		tags:       []string{"mount", "separate-partition"},
		descSuffix: "Isolating /var prevents log-file growth from filling root and lets the operator mount with nodev.",
		scanner:    "linux.mounts.VarSeparate"},
	{id: "linux-mount-var-tmp-separate", title: "/var/tmp must be its own filesystem", target: "/var/tmp",
		severity: compliancekit.SeverityLow, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.1.4.1"},
		tags:       []string{"mount", "separate-partition"},
		descSuffix: "Separate /var/tmp prevents user-created files in /var/tmp from competing with /var space + admits separate noexec/nosuid/nodev.",
		scanner:    "linux.mounts.VarTmpSeparate"},
	{id: "linux-mount-var-log-separate", title: "/var/log must be its own filesystem", target: "/var/log",
		severity: compliancekit.SeverityMedium, soc2: []string{"CC7.2"}, iso: []string{"A.8.15"}, cis: []string{"1.1.5.1"},
		tags:       []string{"mount", "separate-partition", "logging"},
		descSuffix: "Separate /var/log keeps log growth from breaking other /var consumers + admits per-mount quotas / forwarding.",
		scanner:    "linux.mounts.VarLogSeparate"},
	{id: "linux-mount-var-log-audit-separate", title: "/var/log/audit must be its own filesystem", target: "/var/log/audit",
		severity: compliancekit.SeverityHigh, soc2: []string{"CC7.2"}, iso: []string{"A.8.15"}, cis: []string{"1.1.6.1"},
		tags:       []string{"mount", "separate-partition", "audit"},
		descSuffix: "auditd takes the host offline if /var/log/audit fills up (default behavior). Separate filesystem with a generous size prevents accidental DoS-by-log-overflow.",
		scanner:    "linux.mounts.VarLogAuditSeparate"},
	{id: "linux-mount-home-separate", title: "/home must be its own filesystem", target: "/home",
		severity: compliancekit.SeverityLow, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.1.7.1"},
		tags:       []string{"mount", "separate-partition"},
		descSuffix: "Separate /home admits nodev/nosuid + lets user-data backups be filesystem-snapshot-driven independently of OS state.",
		scanner:    "linux.mounts.HomeSeparate"},
}

// ----- mount-option specs -----------------------------------------------

type mountOptionSpec struct {
	id, title, scanner string
	target, option     string
	severity           compliancekit.Severity
	soc2, iso, cis     []string
	tags               []string
	descSuffix         string
}

var mountOptionSpecs = []mountOptionSpec{
	{id: "linux-mount-tmp-nodev", title: "/tmp must be mounted with nodev", target: "/tmp", option: "nodev",
		severity: compliancekit.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.1.2.2"},
		tags: []string{"mount", "nodev"}, scanner: "linux.mounts.TmpNodev",
		descSuffix: "nodev prevents the creation of device files on /tmp, blocking a class of exploits where an attacker mknods their own /dev/sda."},
	{id: "linux-mount-tmp-nosuid", title: "/tmp must be mounted with nosuid", target: "/tmp", option: "nosuid",
		severity: compliancekit.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.1.2.3"},
		tags: []string{"mount", "nosuid"}, scanner: "linux.mounts.TmpNosuid",
		descSuffix: "nosuid disables SUID bit honoring on /tmp — a copied-out setuid binary can't elevate privileges."},
	{id: "linux-mount-tmp-noexec", title: "/tmp must be mounted with noexec", target: "/tmp", option: "noexec",
		severity: compliancekit.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.1.2.4"},
		tags: []string{"mount", "noexec"}, scanner: "linux.mounts.TmpNoexec",
		descSuffix: "noexec prevents executing arbitrary files dropped in /tmp — blocks a common payload-execution staging area for fileless malware + exploit kits."},
	{id: "linux-mount-home-nodev", title: "/home must be mounted with nodev", target: "/home", option: "nodev",
		severity: compliancekit.SeverityLow, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.1.7.2"},
		tags: []string{"mount", "nodev"}, scanner: "linux.mounts.HomeNodev",
		descSuffix: "nodev on /home prevents user-created device files."},
	{id: "linux-mount-home-nosuid", title: "/home must be mounted with nosuid", target: "/home", option: "nosuid",
		severity: compliancekit.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.1.7.3"},
		tags: []string{"mount", "nosuid"}, scanner: "linux.mounts.HomeNosuid",
		descSuffix: "nosuid on /home stops users from staging setuid binaries in their own home directories."},
	{id: "linux-mount-dev-shm-nodev", title: "/dev/shm must be mounted with nodev", target: "/dev/shm", option: "nodev",
		severity: compliancekit.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.1.8.2"},
		tags: []string{"mount", "nodev"}, scanner: "linux.mounts.DevShmNodev",
		descSuffix: "nodev on /dev/shm prevents the world-writable tmpfs from hosting device files."},
	{id: "linux-mount-dev-shm-nosuid", title: "/dev/shm must be mounted with nosuid", target: "/dev/shm", option: "nosuid",
		severity: compliancekit.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.1.8.3"},
		tags: []string{"mount", "nosuid"}, scanner: "linux.mounts.DevShmNosuid",
		descSuffix: "nosuid on /dev/shm; same rationale as /tmp."},
	{id: "linux-mount-dev-shm-noexec", title: "/dev/shm must be mounted with noexec", target: "/dev/shm", option: "noexec",
		severity: compliancekit.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.1.8.4"},
		tags: []string{"mount", "noexec"}, scanner: "linux.mounts.DevShmNoexec",
		descSuffix: "noexec on /dev/shm; same rationale as /tmp."},
	{id: "linux-mount-var-tmp-noexec", title: "/var/tmp must be mounted with noexec", target: "/var/tmp", option: "noexec",
		severity: compliancekit.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.1.4.4"},
		tags: []string{"mount", "noexec"}, scanner: "linux.mounts.VarTmpNoexec",
		descSuffix: "noexec on /var/tmp; same rationale as /tmp."},
}

func mountsFromHost(h compliancekit.Resource) ([]docol.MountEntry, bool) {
	v, _ := h.Attributes["mounts"].([]docol.MountEntry)
	return v, v != nil
}

func mountSeparateFunc(spec mountSeparateSpec) compliancekit.CheckFunc {
	return func(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
		findings := []compliancekit.Finding{}
		for _, h := range g.ByType(docol.HostType) {
			f := compliancekit.Finding{
				CheckID:  spec.id,
				Severity: spec.severity,
				Resource: h.Ref(),
				Tags:     spec.tags,
			}
			reachable, _ := h.Attributes["reachable"].(bool)
			if !reachable {
				f.Status = compliancekit.StatusSkip
				f.Message = fmt.Sprintf("host %q: unreachable", h.Name)
				findings = append(findings, f)
				continue
			}
			mounts, ok := mountsFromHost(h)
			if !ok {
				f.Status = compliancekit.StatusError
				f.Message = fmt.Sprintf("host %q: mounts attribute missing", h.Name)
				findings = append(findings, f)
				continue
			}
			if _, found := docol.FindMount(mounts, spec.target); found {
				f.Status = compliancekit.StatusPass
				f.Message = fmt.Sprintf("host %q: %s is a separate mount", h.Name, spec.target)
			} else {
				f.Status = compliancekit.StatusFail
				f.Message = fmt.Sprintf("host %q: %s is NOT a separate mount", h.Name, spec.target)
			}
			findings = append(findings, f)
		}
		return findings, nil
	}
}

func mountOptionFunc(spec mountOptionSpec) compliancekit.CheckFunc {
	return func(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
		findings := []compliancekit.Finding{}
		for _, h := range g.ByType(docol.HostType) {
			f := compliancekit.Finding{
				CheckID:  spec.id,
				Severity: spec.severity,
				Resource: h.Ref(),
				Tags:     spec.tags,
			}
			reachable, _ := h.Attributes["reachable"].(bool)
			if !reachable {
				f.Status = compliancekit.StatusSkip
				f.Message = fmt.Sprintf("host %q: unreachable", h.Name)
				findings = append(findings, f)
				continue
			}
			mounts, ok := mountsFromHost(h)
			if !ok {
				f.Status = compliancekit.StatusError
				f.Message = fmt.Sprintf("host %q: mounts attribute missing", h.Name)
				findings = append(findings, f)
				continue
			}
			m, found := docol.FindMount(mounts, spec.target)
			if !found {
				f.Status = compliancekit.StatusSkip
				f.Message = fmt.Sprintf("host %q: %s not present as a mount; separate-partition check covers this", h.Name, spec.target)
				findings = append(findings, f)
				continue
			}
			if m.HasOption(spec.option) {
				f.Status = compliancekit.StatusPass
				f.Message = fmt.Sprintf("host %q: %s mounted with %s", h.Name, spec.target, spec.option)
			} else {
				f.Status = compliancekit.StatusFail
				f.Message = fmt.Sprintf("host %q: %s missing %s option", h.Name, spec.target, spec.option)
			}
			findings = append(findings, f)
		}
		return findings, nil
	}
}

func mountSeparateCheck(spec mountSeparateSpec) compliancekit.Check {
	return compliancekit.Check{
		ID: spec.id, Title: spec.title, Severity: spec.severity,
		Provider: "linux", Service: "filesystem", ResourceType: docol.HostType,
		Description: fmt.Sprintf("Separate mount for %s; CIS Linux Server v8 §%s. %s",
			spec.target, firstNonEmpty(spec.cis...), spec.descSuffix),
		Remediation: fmt.Sprintf("Plan downtime + repartition: create a dedicated partition / LVM volume + mount at %s. "+
			"For new builds use a partition layout that breaks out /tmp /var /var/log /var/log/audit /home from /. "+
			"systemd-mount(8) + /etc/fstab carry the persistent state.", spec.target),
		Frameworks: map[string][]string{
			"soc2": spec.soc2, "iso27001": spec.iso, "cis-v8": spec.cis, "cis-linux-server": spec.cis,
		},
		Tags:    spec.tags,
		Scanner: spec.scanner,
	}
}

func mountOptionCheck(spec mountOptionSpec) compliancekit.Check {
	return compliancekit.Check{
		ID: spec.id, Title: spec.title, Severity: spec.severity,
		Provider: "linux", Service: "filesystem", ResourceType: docol.HostType,
		Description: fmt.Sprintf("%s mount option on %s; CIS Linux Server v8 §%s. %s",
			spec.option, spec.target, firstNonEmpty(spec.cis...), spec.descSuffix),
		Remediation: fmt.Sprintf("Edit /etc/fstab — append %s to the options column for %s:\n\n  UUID=... %s tmpfs defaults,rw,%s 0 0\n\n"+
			"Apply live without reboot: `sudo mount -o remount,%s %s`. Persistence requires the fstab edit.",
			spec.option, spec.target, spec.target, spec.option, spec.option, spec.target),
		Frameworks: map[string][]string{
			"soc2": spec.soc2, "iso27001": spec.iso, "cis-v8": spec.cis, "cis-linux-server": spec.cis,
		},
		Tags:    spec.tags,
		Scanner: spec.scanner,
	}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func init() {
	for _, s := range mountSeparateSpecs {
		s := s
		compliancekit.Register(mountSeparateCheck(s), mountSeparateFunc(s))
	}
	for _, s := range mountOptionSpecs {
		s := s
		compliancekit.Register(mountOptionCheck(s), mountOptionFunc(s))
	}
}
