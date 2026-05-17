package linux

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SysctlKeys is the full set of kernel parameters the v0.20 sysctl
// checks consult. Adding a new check that needs a sysctl: extend this
// slice + add the per-key check definition in
// internal/checks/linux/kernel_extra.go. Single-round-trip via SSH.
var SysctlKeys = []string{
	// v0.5 baseline (still referenced by the legacy checks)
	"kernel.randomize_va_space",
	"net.ipv4.conf.all.accept_source_route",
	"net.ipv4.conf.all.send_redirects",

	// v0.20 phase 2 expansion — CIS Linux Server v8 §3.3 (network),
	// §1.5 (kernel hardening), §1.6 (filesystem hardening sysctls).
	"net.ipv4.tcp_syncookies",
	"net.ipv4.conf.all.rp_filter",
	"net.ipv4.conf.default.rp_filter",
	"net.ipv4.conf.all.accept_redirects",
	"net.ipv4.conf.default.accept_redirects",
	"net.ipv4.conf.all.secure_redirects",
	"net.ipv4.conf.default.secure_redirects",
	"net.ipv4.conf.default.accept_source_route",
	"net.ipv4.conf.default.send_redirects",
	"net.ipv4.icmp_echo_ignore_broadcasts",
	"net.ipv4.icmp_ignore_bogus_error_responses",
	"net.ipv4.conf.all.log_martians",
	"net.ipv4.conf.default.log_martians",
	"net.ipv4.ip_forward",
	"net.ipv6.conf.all.accept_ra",
	"net.ipv6.conf.default.accept_ra",
	"net.ipv6.conf.all.accept_redirects",
	"net.ipv6.conf.default.accept_redirects",
	"net.ipv6.conf.all.accept_source_route",
	"net.ipv6.conf.default.accept_source_route",
	"kernel.dmesg_restrict",
	"kernel.kptr_restrict",
	"kernel.yama.ptrace_scope",
	"kernel.unprivileged_bpf_disabled",
	"net.core.bpf_jit_harden",
	"fs.suid_dumpable",
	"fs.protected_hardlinks",
	"fs.protected_symlinks",
	"fs.protected_fifos",
	"fs.protected_regular",
}

// gatherKernel returns the parsed sysctl key → integer-value map. The
// `attrs["kernel"].(map[string]any)["sysctls"]` shape carries every
// key listed in SysctlKeys; missing entries mean the sysctl was
// unavailable on the host (kernel build option / permission) — the
// per-check code emits StatusSkip in that case rather than failing.
//
// Back-compat: the original v0.5 keys (randomize_va_space, …) are
// also surfaced as top-level entries on the returned map so existing
// checks (kernel.go) read them without churn.
func gatherKernel(ctx context.Context, client *ssh.Client) (map[string]any, error) {
	cmd := "sysctl -e " + strings.Join(SysctlKeys, " ") + " 2>/dev/null"
	output, _, err := RunCommand(ctx, client, cmd)
	if err != nil {
		return nil, fmt.Errorf("sysctl probe: %w", err)
	}
	sysctls := ParseSysctlOutput(output)

	out := map[string]any{
		"sysctls": sysctls,
	}
	// Back-compat aliases for the v0.5 checks.
	if v, ok := sysctls["kernel.randomize_va_space"]; ok {
		out["randomize_va_space"] = v
	}
	if v, ok := sysctls["net.ipv4.conf.all.accept_source_route"]; ok {
		out["accept_source_route_all"] = v
	}
	if v, ok := sysctls["net.ipv4.conf.all.send_redirects"]; ok {
		out["send_redirects_all"] = v
	}
	return out, nil
}

// ParseSysctlOutput parses `sysctl key1 key2` output of the form
// `key = value\n` into a string-keyed integer map. Non-integer values
// (e.g. tunables with comma-separated lists) are skipped — the
// v0.20 check surface only consults integer-valued knobs.
//
// Exported so tests + downstream collectors share the parser.
func ParseSysctlOutput(output string) map[string]int {
	out := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// "key = value" — sysctl uses ` = ` separator on every distro
		// we model (Ubuntu / Debian / RHEL / Alpine / Amazon Linux).
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		valStr := strings.TrimSpace(line[eq+1:])
		// Some sysctl values are multi-token (e.g. net.core.somaxconn)
		// — only the first integer token is consulted.
		if sp := strings.IndexAny(valStr, " \t"); sp > 0 {
			valStr = valStr[:sp]
		}
		v, err := strconv.Atoi(valStr)
		if err != nil {
			continue
		}
		out[key] = v
	}
	return out
}
