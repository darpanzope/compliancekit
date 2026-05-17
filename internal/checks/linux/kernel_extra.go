package linux

import (
	"context"
	"fmt"

	docol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.20 phase 2 — kernel sysctl deepening. 25 new sysctl-shaped
// checks declared as data + registered via a loop so each entry
// stays compact. Every check follows the same pattern:
//
//   1. Pull host.attributes["kernel"].(map[string]any)["sysctls"]
//      → string→int map
//   2. Compare the value at the declared key against the desired
//      value (eq / gte / lte / in)
//   3. Emit StatusSkip if the key isn't surfaced (sysctl was
//      unavailable: kernel build option, no permission, distro-
//      specific knob)
//
// Source: CIS Linux Server Benchmark v8 §1.5 (kernel) + §3.3
// (network) + §1.6 (filesystem). ISO 27001 A.8.20 / A.8.21
// (network controls) + A.8.7 (hardening). SOC 2 CC6.6.

type sysctlCmp string

const (
	cmpEq  sysctlCmp = "eq"  // value must equal target
	cmpGte sysctlCmp = "gte" // value must be ≥ target (e.g. randomize_va_space ≥ 2)
)

// sysctlSpec drives one sysctl-shaped check. The slice below lists
// every v0.20 sysctl rule; init() iterates + registers.
type sysctlSpec struct {
	id, title, scanner string
	severity           core.Severity
	key                string    // sysctl name
	want               int       // target value
	cmp                sysctlCmp // comparison operator
	soc2, iso, cis     []string
	tags               []string
	description        string
	remediation        string
}

var sysctlSpecs = []sysctlSpec{
	// --- TCP / IP defenses ----------------------------------------------
	{
		id: "linux-sysctl-tcp-syncookies", title: "net.ipv4.tcp_syncookies must be enabled",
		severity: core.SeverityHigh, key: "net.ipv4.tcp_syncookies", want: 1, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.3.4", "9.2"},
		tags: []string{"sysctl", "network", "syn-flood"},
		description: "SYN cookies allow the kernel to handle the SYN queue without " +
			"reserving state until the three-way handshake completes — the primary " +
			"defense against SYN flood denial-of-service. Disabled-by-default on some " +
			"older builds; enable by setting net.ipv4.tcp_syncookies=1.",
		remediation: "Persist via /etc/sysctl.d/60-tcp-syncookies.conf:\n  net.ipv4.tcp_syncookies = 1\nThen `sysctl --system` to apply.",
		scanner:     "linux.sysctl.TCPSyncookies",
	},
	{
		id: "linux-sysctl-rp-filter-all", title: "net.ipv4.conf.all.rp_filter must be strict (1)",
		severity: core.SeverityMedium, key: "net.ipv4.conf.all.rp_filter", want: 1, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.3.7"},
		tags:        []string{"sysctl", "network", "rp-filter"},
		description: "Reverse Path filtering rejects packets arriving on an interface that wouldn't be used to reply (IP spoofing mitigation). Strict mode (1) matches the RFC 3704 recommendation.",
		remediation: "/etc/sysctl.d/60-network-hardening.conf:\n  net.ipv4.conf.all.rp_filter = 1\n  net.ipv4.conf.default.rp_filter = 1\nThen `sysctl --system`.",
		scanner:     "linux.sysctl.RPFilterAll",
	},
	{
		id: "linux-sysctl-rp-filter-default", title: "net.ipv4.conf.default.rp_filter must be strict (1)",
		severity: core.SeverityMedium, key: "net.ipv4.conf.default.rp_filter", want: 1, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.3.7"},
		tags:        []string{"sysctl", "network", "rp-filter"},
		description: "The 'default' value is applied to any new interface created after sysctl is set; pair with the 'all' counterpart so currently-attached + future interfaces both filter.",
		remediation: "See linux-sysctl-rp-filter-all — set both keys together.",
		scanner:     "linux.sysctl.RPFilterDefault",
	},
	{
		id: "linux-sysctl-accept-redirects-all", title: "ICMP redirects must be ignored (all)",
		severity: core.SeverityMedium, key: "net.ipv4.conf.all.accept_redirects", want: 0, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.3.2"},
		tags:        []string{"sysctl", "network", "icmp"},
		description: "ICMP redirects let any host on the LAN tell the kernel to route through a different gateway — an obvious MITM primitive. Always disabled on servers.",
		remediation: "/etc/sysctl.d/60-network-hardening.conf:\n  net.ipv4.conf.all.accept_redirects = 0\n  net.ipv4.conf.default.accept_redirects = 0",
		scanner:     "linux.sysctl.AcceptRedirectsAll",
	},
	{
		id: "linux-sysctl-accept-redirects-default", title: "ICMP redirects must be ignored (default)",
		severity: core.SeverityMedium, key: "net.ipv4.conf.default.accept_redirects", want: 0, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.3.2"},
		tags:        []string{"sysctl", "network", "icmp"},
		description: "Paired with the 'all' counterpart; default applies to new interfaces.",
		remediation: "See linux-sysctl-accept-redirects-all.",
		scanner:     "linux.sysctl.AcceptRedirectsDefault",
	},
	{
		id: "linux-sysctl-secure-redirects-all", title: "Secure ICMP redirects must be disabled (all)",
		severity: core.SeverityLow, key: "net.ipv4.conf.all.secure_redirects", want: 0, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.3.3"},
		tags:        []string{"sysctl", "network", "icmp"},
		description: "secure_redirects accepts redirects from gateways in the default route — slightly safer than accept_redirects but still rejected by CIS for servers.",
		remediation: "/etc/sysctl.d/60-network-hardening.conf:\n  net.ipv4.conf.all.secure_redirects = 0\n  net.ipv4.conf.default.secure_redirects = 0",
		scanner:     "linux.sysctl.SecureRedirectsAll",
	},
	{
		id: "linux-sysctl-secure-redirects-default", title: "Secure ICMP redirects must be disabled (default)",
		severity: core.SeverityLow, key: "net.ipv4.conf.default.secure_redirects", want: 0, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.3.3"},
		tags:        []string{"sysctl", "network", "icmp"},
		description: "Default counterpart to the 'all' rule.",
		remediation: "See linux-sysctl-secure-redirects-all.",
		scanner:     "linux.sysctl.SecureRedirectsDefault",
	},
	{
		id: "linux-sysctl-icmp-echo-ignore-broadcasts", title: "Smurf-amplifier ICMP echo must be ignored",
		severity: core.SeverityMedium, key: "net.ipv4.icmp_echo_ignore_broadcasts", want: 1, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.3.5"},
		tags:        []string{"sysctl", "network", "icmp"},
		description: "Ignoring broadcast ICMP echo blocks the classic Smurf DoS amplifier where attackers spoof a victim address and broadcast an echo request.",
		remediation: "/etc/sysctl.d/60-network-hardening.conf:\n  net.ipv4.icmp_echo_ignore_broadcasts = 1",
		scanner:     "linux.sysctl.ICMPEchoIgnoreBroadcasts",
	},
	{
		id: "linux-sysctl-icmp-ignore-bogus-error-responses", title: "Bogus ICMP error responses must be ignored",
		severity: core.SeverityLow, key: "net.ipv4.icmp_ignore_bogus_error_responses", want: 1, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.3.6"},
		tags:        []string{"sysctl", "network", "icmp"},
		description: "Silently drops bogus ICMP error responses that some routers emit in violation of RFC 1122 — reduces kernel-log noise that masks real attacks.",
		remediation: "/etc/sysctl.d/60-network-hardening.conf:\n  net.ipv4.icmp_ignore_bogus_error_responses = 1",
		scanner:     "linux.sysctl.ICMPIgnoreBogus",
	},
	{
		id: "linux-sysctl-log-martians-all", title: "Martian packets must be logged (all)",
		severity: core.SeverityLow, key: "net.ipv4.conf.all.log_martians", want: 1, cmp: cmpEq,
		soc2: []string{"CC7.2"}, iso: []string{"A.8.15"}, cis: []string{"3.3.8"},
		tags:        []string{"sysctl", "network", "logging"},
		description: "Martian packets (impossible source addresses) are logged when this knob is enabled — a useful signal that something is either spoofing or seriously misconfigured upstream.",
		remediation: "/etc/sysctl.d/60-network-hardening.conf:\n  net.ipv4.conf.all.log_martians = 1\n  net.ipv4.conf.default.log_martians = 1",
		scanner:     "linux.sysctl.LogMartiansAll",
	},
	{
		id: "linux-sysctl-log-martians-default", title: "Martian packets must be logged (default)",
		severity: core.SeverityLow, key: "net.ipv4.conf.default.log_martians", want: 1, cmp: cmpEq,
		soc2: []string{"CC7.2"}, iso: []string{"A.8.15"}, cis: []string{"3.3.8"},
		tags:        []string{"sysctl", "network", "logging"},
		description: "Default counterpart to the 'all' rule.",
		remediation: "See linux-sysctl-log-martians-all.",
		scanner:     "linux.sysctl.LogMartiansDefault",
	},
	{
		id: "linux-sysctl-accept-source-route-default", title: "Source-routed packets must be dropped (default)",
		severity: core.SeverityMedium, key: "net.ipv4.conf.default.accept_source_route", want: 0, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.3.1"},
		tags:        []string{"sysctl", "network"},
		description: "Source routing lets the sender dictate the path a packet takes — bypasses upstream firewalls + reverses NAT mappings. Always disabled on servers.",
		remediation: "/etc/sysctl.d/60-network-hardening.conf:\n  net.ipv4.conf.all.accept_source_route = 0\n  net.ipv4.conf.default.accept_source_route = 0",
		scanner:     "linux.sysctl.AcceptSourceRouteDefault",
	},
	{
		id: "linux-sysctl-send-redirects-default", title: "Kernel must not send ICMP redirects (default)",
		severity: core.SeverityMedium, key: "net.ipv4.conf.default.send_redirects", want: 0, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.2.1"},
		tags:        []string{"sysctl", "network"},
		description: "Only routers should emit ICMP redirects. End-user servers + cloud workloads disable both 'all' and 'default'.",
		remediation: "/etc/sysctl.d/60-network-hardening.conf:\n  net.ipv4.conf.all.send_redirects = 0\n  net.ipv4.conf.default.send_redirects = 0",
		scanner:     "linux.sysctl.SendRedirectsDefault",
	},
	{
		id: "linux-sysctl-ip-forward-disabled", title: "IPv4 forwarding must be disabled on non-router hosts",
		severity: core.SeverityMedium, key: "net.ipv4.ip_forward", want: 0, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.2.2"},
		tags:        []string{"sysctl", "network"},
		description: "ip_forward=1 turns the host into a router (forwards packets between interfaces). Container hosts running Docker/k8s flip this to 1 intentionally; non-router servers leave it at 0. Waive on Docker / k8s nodes via waivers.yaml.",
		remediation: "/etc/sysctl.d/60-network-hardening.conf:\n  net.ipv4.ip_forward = 0\nWaive when the host genuinely routes (k8s node, NAT gateway).",
		scanner:     "linux.sysctl.IPForward",
	},
	// --- IPv6 hardening -------------------------------------------------
	{
		id: "linux-sysctl-ipv6-accept-ra-all", title: "IPv6 router advertisements must be ignored (all)",
		severity: core.SeverityMedium, key: "net.ipv6.conf.all.accept_ra", want: 0, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.3.9"},
		tags:        []string{"sysctl", "network", "ipv6"},
		description: "Router Advertisements let any host on the L2 segment set the default IPv6 gateway — Stateless Address Autoconfig (SLAAC) primitive. On managed cloud networks (static IPv6 from the provider) disabling RA blocks rogue-router attacks.",
		remediation: "/etc/sysctl.d/60-ipv6-hardening.conf:\n  net.ipv6.conf.all.accept_ra = 0\n  net.ipv6.conf.default.accept_ra = 0",
		scanner:     "linux.sysctl.IPv6AcceptRAAll",
	},
	{
		id: "linux-sysctl-ipv6-accept-ra-default", title: "IPv6 router advertisements must be ignored (default)",
		severity: core.SeverityMedium, key: "net.ipv6.conf.default.accept_ra", want: 0, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.3.9"},
		tags:        []string{"sysctl", "network", "ipv6"},
		description: "Default counterpart to the 'all' rule.",
		remediation: "See linux-sysctl-ipv6-accept-ra-all.",
		scanner:     "linux.sysctl.IPv6AcceptRADefault",
	},
	{
		id: "linux-sysctl-ipv6-accept-redirects-all", title: "IPv6 ICMP redirects must be ignored (all)",
		severity: core.SeverityMedium, key: "net.ipv6.conf.all.accept_redirects", want: 0, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.3.2"},
		tags:        []string{"sysctl", "network", "ipv6"},
		description: "Same MITM concern as IPv4 ICMP redirects, applied to the v6 stack.",
		remediation: "/etc/sysctl.d/60-ipv6-hardening.conf:\n  net.ipv6.conf.all.accept_redirects = 0\n  net.ipv6.conf.default.accept_redirects = 0",
		scanner:     "linux.sysctl.IPv6AcceptRedirectsAll",
	},
	{
		id: "linux-sysctl-ipv6-accept-redirects-default", title: "IPv6 ICMP redirects must be ignored (default)",
		severity: core.SeverityMedium, key: "net.ipv6.conf.default.accept_redirects", want: 0, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.3.2"},
		tags:        []string{"sysctl", "network", "ipv6"},
		description: "Default counterpart to the 'all' rule.",
		remediation: "See linux-sysctl-ipv6-accept-redirects-all.",
		scanner:     "linux.sysctl.IPv6AcceptRedirectsDefault",
	},
	{
		id: "linux-sysctl-ipv6-source-route-all", title: "IPv6 source routing must be disabled (all)",
		severity: core.SeverityMedium, key: "net.ipv6.conf.all.accept_source_route", want: 0, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.3.1"},
		tags:        []string{"sysctl", "network", "ipv6"},
		description: "Same path-spoofing concern as IPv4 source routing, applied to the v6 stack.",
		remediation: "/etc/sysctl.d/60-ipv6-hardening.conf:\n  net.ipv6.conf.all.accept_source_route = 0\n  net.ipv6.conf.default.accept_source_route = 0",
		scanner:     "linux.sysctl.IPv6SourceRouteAll",
	},
	{
		id: "linux-sysctl-ipv6-source-route-default", title: "IPv6 source routing must be disabled (default)",
		severity: core.SeverityMedium, key: "net.ipv6.conf.default.accept_source_route", want: 0, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.3.1"},
		tags:        []string{"sysctl", "network", "ipv6"},
		description: "Default counterpart to the 'all' rule.",
		remediation: "See linux-sysctl-ipv6-source-route-all.",
		scanner:     "linux.sysctl.IPv6SourceRouteDefault",
	},
	// --- Kernel info-leak + exploit-mitigation knobs --------------------
	{
		id: "linux-sysctl-dmesg-restrict", title: "kernel.dmesg_restrict must be enabled",
		severity: core.SeverityMedium, key: "kernel.dmesg_restrict", want: 1, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.5.1"},
		tags:        []string{"sysctl", "kernel", "info-leak"},
		description: "dmesg_restrict prevents unprivileged users from reading the kernel ring buffer (KASLR offsets, addresses of loaded modules, hardware MAC addresses). 1 = root-only; 0 = anyone.",
		remediation: "/etc/sysctl.d/60-kernel-hardening.conf:\n  kernel.dmesg_restrict = 1",
		scanner:     "linux.sysctl.DmesgRestrict",
	},
	{
		id: "linux-sysctl-kptr-restrict", title: "kernel.kptr_restrict must be ≥1 (CIS: 2)",
		severity: core.SeverityMedium, key: "kernel.kptr_restrict", want: 1, cmp: cmpGte,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.5.2"},
		tags:        []string{"sysctl", "kernel", "info-leak"},
		description: "kptr_restrict hides kernel pointer values from /proc — defeats KASLR-defeat exploits that scrape /proc/kallsyms etc. 1 redacts for unprivileged; 2 redacts for everyone.",
		remediation: "/etc/sysctl.d/60-kernel-hardening.conf:\n  kernel.kptr_restrict = 2",
		scanner:     "linux.sysctl.KptrRestrict",
	},
	{
		id: "linux-sysctl-yama-ptrace-scope", title: "kernel.yama.ptrace_scope must be ≥1",
		severity: core.SeverityMedium, key: "kernel.yama.ptrace_scope", want: 1, cmp: cmpGte,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.5.3"},
		tags:        []string{"sysctl", "kernel"},
		description: "Yama restricts ptrace() across processes the caller didn't fork — kills the LD_PRELOAD-then-attach style credential extraction. 0=permissive, 1=restricted (recommended), 2=admin-only, 3=disabled.",
		remediation: "/etc/sysctl.d/60-kernel-hardening.conf:\n  kernel.yama.ptrace_scope = 1",
		scanner:     "linux.sysctl.YamaPtraceScope",
	},
	{
		id: "linux-sysctl-unprivileged-bpf-disabled", title: "kernel.unprivileged_bpf_disabled must be 1",
		severity: core.SeverityHigh, key: "kernel.unprivileged_bpf_disabled", want: 1, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.5.4"},
		tags:        []string{"sysctl", "kernel", "bpf"},
		description: "Unprivileged eBPF has been a recurring source of LPE CVEs (CVE-2021-3490, CVE-2022-23222, CVE-2023-2236). Disable unless a specific workload (Cilium, Falco) needs it; even then, prefer CAP_BPF over universal access.",
		remediation: "/etc/sysctl.d/60-kernel-hardening.conf:\n  kernel.unprivileged_bpf_disabled = 1\nWaive on hosts running Cilium / Falco / eBPF observability.",
		scanner:     "linux.sysctl.UnprivilegedBPFDisabled",
	},
	{
		id: "linux-sysctl-bpf-jit-harden", title: "net.core.bpf_jit_harden must be ≥1",
		severity: core.SeverityMedium, key: "net.core.bpf_jit_harden", want: 1, cmp: cmpGte,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.5.5"},
		tags:        []string{"sysctl", "kernel", "bpf"},
		description: "BPF JIT hardening mitigates CPU speculative-execution side-channel attacks in JIT-compiled BPF programs. 1=privileged hardening; 2=all programs hardened.",
		remediation: "/etc/sysctl.d/60-kernel-hardening.conf:\n  net.core.bpf_jit_harden = 2",
		scanner:     "linux.sysctl.BPFJITHarden",
	},
	// --- Filesystem hardening (sysctl-shaped) ---------------------------
	{
		id: "linux-sysctl-suid-dumpable", title: "fs.suid_dumpable must be 0 (no core dumps from SUID)",
		severity: core.SeverityHigh, key: "fs.suid_dumpable", want: 0, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.6.1"},
		tags:        []string{"sysctl", "filesystem", "suid"},
		description: "SUID programs that core dump can leak privileged memory (cached secrets, fd contents). Per CIS, 0 = SUID processes never core dump; 1 = always; 2 = root-readable only.",
		remediation: "/etc/sysctl.d/60-fs-hardening.conf:\n  fs.suid_dumpable = 0",
		scanner:     "linux.sysctl.SuidDumpable",
	},
	{
		id: "linux-sysctl-protected-hardlinks", title: "fs.protected_hardlinks must be enabled",
		severity: core.SeverityMedium, key: "fs.protected_hardlinks", want: 1, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.6.2"},
		tags:        []string{"sysctl", "filesystem"},
		description: "protected_hardlinks blocks unprivileged users from creating hardlinks to files they don't own — a classic prelude to /etc/passwd race exploits.",
		remediation: "/etc/sysctl.d/60-fs-hardening.conf:\n  fs.protected_hardlinks = 1",
		scanner:     "linux.sysctl.ProtectedHardlinks",
	},
	{
		id: "linux-sysctl-protected-symlinks", title: "fs.protected_symlinks must be enabled",
		severity: core.SeverityMedium, key: "fs.protected_symlinks", want: 1, cmp: cmpEq,
		soc2: []string{"CC6.6"}, iso: []string{"A.8.7"}, cis: []string{"1.6.3"},
		tags:        []string{"sysctl", "filesystem"},
		description: "protected_symlinks restricts symlink-following in world-writable directories — kills TOCTOU race exploits via /tmp symlinks.",
		remediation: "/etc/sysctl.d/60-fs-hardening.conf:\n  fs.protected_symlinks = 1",
		scanner:     "linux.sysctl.ProtectedSymlinks",
	},
}

func sysctlsFromHost(h core.Resource) (map[string]int, bool) {
	kernel, _ := h.Attributes["kernel"].(map[string]any)
	if kernel == nil {
		return nil, false
	}
	raw := kernel["sysctls"]
	switch v := raw.(type) {
	case map[string]int:
		return v, true
	case map[string]any:
		// Defensive parse — some serializers may have round-tripped the
		// map through any-typed values.
		out := map[string]int{}
		for k, vv := range v {
			if i, ok := vv.(int); ok {
				out[k] = i
			}
		}
		return out, true
	}
	return nil, false
}

func sysctlCheckFunc(spec sysctlSpec) core.CheckFunc {
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
				f.Message = fmt.Sprintf("host %q: unreachable; skipping %s", h.Name, spec.key)
				findings = append(findings, f)
				continue
			}
			sysctls, ok := sysctlsFromHost(h)
			if !ok {
				f.Status = core.StatusError
				f.Message = fmt.Sprintf("host %q: kernel.sysctls attribute missing", h.Name)
				findings = append(findings, f)
				continue
			}
			got, present := sysctls[spec.key]
			if !present {
				f.Status = core.StatusSkip
				f.Message = fmt.Sprintf("host %q: sysctl %q unavailable (kernel build / permission)", h.Name, spec.key)
				findings = append(findings, f)
				continue
			}
			ok = sysctlCompare(spec.cmp, got, spec.want)
			if ok {
				f.Status = core.StatusPass
				f.Message = fmt.Sprintf("host %q: %s = %d (%s %d)", h.Name, spec.key, got, spec.cmp, spec.want)
			} else {
				f.Status = core.StatusFail
				f.Message = fmt.Sprintf("host %q: %s = %d (want %s %d)", h.Name, spec.key, got, spec.cmp, spec.want)
			}
			findings = append(findings, f)
		}
		return findings, nil
	}
}

func sysctlCompare(op sysctlCmp, got, want int) bool {
	switch op {
	case cmpEq:
		return got == want
	case cmpGte:
		return got >= want
	}
	return false
}

// sysctlCheck builds the core.Check metadata from a sysctlSpec so the
// loop-driven registration in init() doesn't repeat the per-check
// boilerplate.
func sysctlCheck(spec sysctlSpec) core.Check {
	return core.Check{
		ID:           spec.id,
		Title:        spec.title,
		Severity:     spec.severity,
		Provider:     "linux",
		Service:      "kernel",
		ResourceType: docol.HostType,
		Description:  spec.description,
		Remediation:  spec.remediation,
		Frameworks: map[string][]string{
			"soc2":     spec.soc2,
			"iso27001": spec.iso,
			"cis-v8":   spec.cis,
		},
		Tags:    spec.tags,
		Scanner: spec.scanner,
	}
}

func init() {
	for _, spec := range sysctlSpecs {
		spec := spec
		core.Register(sysctlCheck(spec), sysctlCheckFunc(spec))
	}
}
