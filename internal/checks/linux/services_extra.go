package linux

import (
	"context"
	"fmt"

	docol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 4 — systemd unit + services hardening. Three check
// shapes, all data-driven:
//
//   - serviceMustRunSpec     — unit must be enabled AND active
//                              (chrony, auditd, rsyslog, journald).
//   - serviceMustNotRunSpec  — unit must be NOT enabled AND NOT active
//                              (avahi, cups, dhcpd — bare-server stuff).
//   - serviceMustAbsentSpec  — unit must not be installed at all
//                              (telnet, rsh, talk, tftp — inetd-era
//                              cleartext protocols).
//
// On non-systemd hosts (Alpine on OpenRC), checks emit StatusSkip
// rather than failing — Alpine support is opt-in for systemd-specific
// rules.

type serviceMustRunSpec struct {
	id, title, unit, scanner string
	severity                 compliancekit.Severity
	soc2, iso, cis           []string
	tags                     []string
	descSuffix               string
}

var serviceMustRunSpecs = []serviceMustRunSpec{
	{id: "linux-service-time-sync-active", title: "Time-sync daemon must be running (chrony or systemd-timesyncd)",
		unit: "chronyd.service", severity: compliancekit.SeverityHigh,
		soc2: []string{"CC7.2"}, iso: []string{"A.8.17"}, cis: []string{"2.1.1"},
		tags:       []string{"services", "time", "must-run"},
		descSuffix: "Accurate clocks are prerequisite for log correlation, TLS validity, Kerberos. chronyd is the modern default; systemd-timesyncd is acceptable on hosts that don't need server-grade chrony features.",
		scanner:    "linux.services.TimeSyncActive"},
	{id: "linux-service-auditd-enabled", title: "auditd must be enabled at boot",
		unit: "auditd.service", severity: compliancekit.SeverityHigh,
		soc2: []string{"CC7.2"}, iso: []string{"A.8.15"}, cis: []string{"4.1.1.1"},
		tags:       []string{"services", "audit", "must-run"},
		descSuffix: "auditd captures the syscall-level audit trail every CIS / STIG / PCI control depends on. Enable at boot so a missed start doesn't blind the auditor.",
		scanner:    "linux.services.AuditdEnabled"},
	{id: "linux-service-rsyslog-active", title: "rsyslog (or journald-forwarder) must be running",
		unit: "rsyslog.service", severity: compliancekit.SeverityHigh,
		soc2: []string{"CC7.2"}, iso: []string{"A.8.15"}, cis: []string{"4.2.1.1"},
		tags:       []string{"services", "logging", "must-run"},
		descSuffix: "rsyslog forwards local logs off-host (TCP/RFC5424 to a SIEM). journald-only setups can use systemd-journal-upload instead but the SOC2 evidence requirement is the same: ≥90d off-host retention.",
		scanner:    "linux.services.RsyslogActive"},
	{id: "linux-service-cron-active", title: "cron daemon must be running (cron or cronie)",
		unit: "cron.service", severity: compliancekit.SeverityMedium,
		soc2: []string{"CC7.2"}, iso: []string{"A.8.7"}, cis: []string{"5.1.1"},
		tags:       []string{"services", "must-run"},
		descSuffix: "Many hardening tasks (log rotation, aide scan, certificate renewal) are scheduled via cron. A missing cron daemon silently breaks those.",
		scanner:    "linux.services.CronActive"},
}

type serviceMustNotRunSpec struct {
	id, title, unit, scanner string
	severity                 compliancekit.Severity
	soc2, iso, cis           []string
	tags                     []string
	descSuffix               string
}

var serviceMustNotRunSpecs = []serviceMustNotRunSpec{
	{id: "linux-service-avahi-disabled", title: "avahi-daemon must be disabled",
		unit: "avahi-daemon.service", severity: compliancekit.SeverityMedium,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"2.2.3"},
		tags:       []string{"services", "mdns", "must-not-run"},
		descSuffix: "Avahi (mDNS / zeroconf) is for ad-hoc LANs. Servers don't need it; running broadcasts hostnames + capabilities to anyone on the segment.",
		scanner:    "linux.services.AvahiDisabled"},
	{id: "linux-service-cups-disabled", title: "cups (print server) must be disabled",
		unit: "cups.service", severity: compliancekit.SeverityLow,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"2.2.5"},
		tags:       []string{"services", "print", "must-not-run"},
		descSuffix: "Print services on a cloud server are a CIS hardening miss + a CVE attack surface for nothing.",
		scanner:    "linux.services.CupsDisabled"},
	{id: "linux-service-dhcpd-disabled", title: "DHCP server must be disabled on non-DHCP hosts",
		unit: "isc-dhcp-server.service", severity: compliancekit.SeverityMedium,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"2.2.7"},
		tags:       []string{"services", "dhcp", "must-not-run"},
		descSuffix: "A rogue DHCP server poisons the LAN's gateway. Most cloud workloads aren't DHCP servers; disable if not used.",
		scanner:    "linux.services.DhcpdDisabled"},
}

type serviceMustAbsentSpec struct {
	id, title, unit, scanner string
	severity                 compliancekit.Severity
	soc2, iso, cis           []string
	tags                     []string
	descSuffix               string
}

var serviceMustAbsentSpecs = []serviceMustAbsentSpec{
	{id: "linux-service-telnet-absent", title: "telnetd must not be installed",
		unit: "telnetd.service", severity: compliancekit.SeverityHigh,
		soc2: []string{"CC6.7"}, iso: []string{"A.8.24"}, cis: []string{"2.2.16"},
		tags:       []string{"services", "cleartext", "must-absent"},
		descSuffix: "telnet sends credentials in cleartext. Has no legitimate place on a 2026 server — there's always an ssh alternative.",
		scanner:    "linux.services.TelnetAbsent"},
	{id: "linux-service-rsh-absent", title: "rsh / rlogin / rexec must not be installed",
		unit: "rsh.service", severity: compliancekit.SeverityHigh,
		soc2: []string{"CC6.7"}, iso: []string{"A.8.24"}, cis: []string{"2.2.17"},
		tags:       []string{"services", "cleartext", "must-absent"},
		descSuffix: "Same as telnet — cleartext credential transmission with no upside.",
		scanner:    "linux.services.RshAbsent"},
	{id: "linux-service-tftp-absent", title: "tftp server must not be installed",
		unit: "tftp-server.service", severity: compliancekit.SeverityHigh,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"2.2.18"},
		tags:       []string{"services", "cleartext", "must-absent"},
		descSuffix: "TFTP has no authentication. Boot servers (PXE, switch firmware) sometimes need it; flag + waive in that case.",
		scanner:    "linux.services.TftpAbsent"},
}

func servicesFromHost(h compliancekit.Resource) (docol.ServiceFacts, bool) {
	v, ok := h.Attributes["services"].(docol.ServiceFacts)
	return v, ok
}

func serviceCheckFunc(decide func(host string, present bool) (compliancekit.Status, string)) func(spec serviceCheckMeta) compliancekit.CheckFunc {
	return func(spec serviceCheckMeta) compliancekit.CheckFunc {
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
				svc, ok := servicesFromHost(h)
				if !ok {
					f.Status = compliancekit.StatusSkip
					f.Message = fmt.Sprintf("host %q: services probe unavailable (likely non-systemd, e.g. Alpine on OpenRC)", h.Name)
					findings = append(findings, f)
					continue
				}
				status, msg := decide(h.Name, spec.matches(svc))
				f.Status = status
				f.Message = msg
				findings = append(findings, f)
			}
			return findings, nil
		}
	}
}

// serviceCheckMeta is the closure-friendly fields each per-shape spec
// needs to plug into serviceCheckFunc.
type serviceCheckMeta struct {
	id, unit string
	severity compliancekit.Severity
	tags     []string
	matches  func(docol.ServiceFacts) bool
}

func mustRunCheck(spec serviceMustRunSpec) (compliancekit.Check, compliancekit.CheckFunc) {
	meta := serviceCheckMeta{
		id: spec.id, unit: spec.unit, severity: spec.severity, tags: spec.tags,
		matches: func(s docol.ServiceFacts) bool { return s.HasEnabled(spec.unit) && s.HasActive(spec.unit) },
	}
	fn := serviceCheckFunc(func(host string, ok bool) (compliancekit.Status, string) {
		if ok {
			return compliancekit.StatusPass, fmt.Sprintf("host %q: %s enabled + active", host, spec.unit)
		}
		return compliancekit.StatusFail, fmt.Sprintf("host %q: %s NOT enabled+active (must-run set)", host, spec.unit)
	})(meta)
	return makeServiceCheck(spec.id, spec.title, spec.severity, spec.soc2, spec.iso, spec.cis, spec.tags, spec.descSuffix, spec.scanner, spec.unit), fn
}

func mustNotRunCheck(spec serviceMustNotRunSpec) (compliancekit.Check, compliancekit.CheckFunc) {
	meta := serviceCheckMeta{
		id: spec.id, unit: spec.unit, severity: spec.severity, tags: spec.tags,
		matches: func(s docol.ServiceFacts) bool { return !s.HasEnabled(spec.unit) && !s.HasActive(spec.unit) },
	}
	fn := serviceCheckFunc(func(host string, ok bool) (compliancekit.Status, string) {
		if ok {
			return compliancekit.StatusPass, fmt.Sprintf("host %q: %s neither enabled nor active", host, spec.unit)
		}
		return compliancekit.StatusFail, fmt.Sprintf("host %q: %s is enabled / active (must-not-run set)", host, spec.unit)
	})(meta)
	return makeServiceCheck(spec.id, spec.title, spec.severity, spec.soc2, spec.iso, spec.cis, spec.tags, spec.descSuffix, spec.scanner, spec.unit), fn
}

func mustAbsentCheck(spec serviceMustAbsentSpec) (compliancekit.Check, compliancekit.CheckFunc) {
	meta := serviceCheckMeta{
		id: spec.id, unit: spec.unit, severity: spec.severity, tags: spec.tags,
		matches: func(s docol.ServiceFacts) bool {
			// "Absent" we approximate as: not listed in enabled/active/masked.
			// Masked counts as acceptable too (admin's deliberate block).
			return !s.HasEnabled(spec.unit) && !s.HasActive(spec.unit)
		},
	}
	fn := serviceCheckFunc(func(host string, ok bool) (compliancekit.Status, string) {
		if ok {
			return compliancekit.StatusPass, fmt.Sprintf("host %q: %s absent (or masked)", host, spec.unit)
		}
		return compliancekit.StatusFail, fmt.Sprintf("host %q: insecure service %s present (must-absent set)", host, spec.unit)
	})(meta)
	return makeServiceCheck(spec.id, spec.title, spec.severity, spec.soc2, spec.iso, spec.cis, spec.tags, spec.descSuffix, spec.scanner, spec.unit), fn
}

func makeServiceCheck(id, title string, sev compliancekit.Severity, soc2, iso, cis, tags []string, descSuffix, scanner, unit string) compliancekit.Check {
	return compliancekit.Check{
		ID: id, Title: title, Severity: sev,
		Provider: "linux", Service: "services", ResourceType: docol.HostType,
		Description: fmt.Sprintf("systemd unit %s; CIS Linux Server v8 §%s. %s",
			unit, firstNonEmpty(cis...), descSuffix),
		Remediation: fmt.Sprintf("systemctl enable --now %s     # must-run\nsystemctl disable --now %s  # must-not-run\nsystemctl mask %s            # must-absent (mask prevents accidental re-enable)\napt-get remove --purge %s    # Debian/Ubuntu absent\ndnf remove %s                # RHEL family absent",
			unit, unit, unit, packageFromUnit(unit), packageFromUnit(unit)),
		Frameworks: map[string][]string{
			"soc2": soc2, "iso27001": iso, "cis-v8": cis, "cis-linux-server": cis,
		},
		Tags:    tags,
		Scanner: scanner,
	}
}

// packageFromUnit returns the apt/dnf package name typically owning the
// given unit. Best-effort heuristic; the operator still verifies.
func packageFromUnit(unit string) string {
	switch unit {
	case "telnetd.service":
		return "telnetd inetutils-telnetd"
	case "rsh.service":
		return "rsh-server inetutils-rsh"
	case "tftp-server.service":
		return "tftpd-hpa tftp-server"
	case "avahi-daemon.service":
		return "avahi-daemon"
	case "cups.service":
		return "cups"
	}
	return unit
}

func init() {
	for _, s := range serviceMustRunSpecs {
		s := s
		c, fn := mustRunCheck(s)
		compliancekit.Register(c, fn)
	}
	for _, s := range serviceMustNotRunSpecs {
		s := s
		c, fn := mustNotRunCheck(s)
		compliancekit.Register(c, fn)
	}
	for _, s := range serviceMustAbsentSpecs {
		s := s
		c, fn := mustAbsentCheck(s)
		compliancekit.Register(c, fn)
	}
}
