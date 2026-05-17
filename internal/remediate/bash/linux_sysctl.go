package bash

import (
	"fmt"
	"strings"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.20 phase 2 — bash strategies for the 31 sysctl-shaped Linux
// hardening checks. Data-driven: each entry pairs a check ID with
// the target sysctl key + value; the render function emits the
// runtime `sysctl -w` + the persistent /etc/sysctl.d drop-in.

type sysctlBashEntry struct {
	key string
	val int
}

var sysctlBash = map[string]sysctlBashEntry{
	"linux-sysctl-tcp-syncookies":                    {"net.ipv4.tcp_syncookies", 1},
	"linux-sysctl-rp-filter-all":                     {"net.ipv4.conf.all.rp_filter", 1},
	"linux-sysctl-rp-filter-default":                 {"net.ipv4.conf.default.rp_filter", 1},
	"linux-sysctl-accept-redirects-all":              {"net.ipv4.conf.all.accept_redirects", 0},
	"linux-sysctl-accept-redirects-default":          {"net.ipv4.conf.default.accept_redirects", 0},
	"linux-sysctl-secure-redirects-all":              {"net.ipv4.conf.all.secure_redirects", 0},
	"linux-sysctl-secure-redirects-default":          {"net.ipv4.conf.default.secure_redirects", 0},
	"linux-sysctl-icmp-echo-ignore-broadcasts":       {"net.ipv4.icmp_echo_ignore_broadcasts", 1},
	"linux-sysctl-icmp-ignore-bogus-error-responses": {"net.ipv4.icmp_ignore_bogus_error_responses", 1},
	"linux-sysctl-log-martians-all":                  {"net.ipv4.conf.all.log_martians", 1},
	"linux-sysctl-log-martians-default":              {"net.ipv4.conf.default.log_martians", 1},
	"linux-sysctl-accept-source-route-default":       {"net.ipv4.conf.default.accept_source_route", 0},
	"linux-sysctl-send-redirects-default":            {"net.ipv4.conf.default.send_redirects", 0},
	"linux-sysctl-ip-forward-disabled":               {"net.ipv4.ip_forward", 0},
	"linux-sysctl-ipv6-accept-ra-all":                {"net.ipv6.conf.all.accept_ra", 0},
	"linux-sysctl-ipv6-accept-ra-default":            {"net.ipv6.conf.default.accept_ra", 0},
	"linux-sysctl-ipv6-accept-redirects-all":         {"net.ipv6.conf.all.accept_redirects", 0},
	"linux-sysctl-ipv6-accept-redirects-default":     {"net.ipv6.conf.default.accept_redirects", 0},
	"linux-sysctl-ipv6-source-route-all":             {"net.ipv6.conf.all.accept_source_route", 0},
	"linux-sysctl-ipv6-source-route-default":         {"net.ipv6.conf.default.accept_source_route", 0},
	"linux-sysctl-dmesg-restrict":                    {"kernel.dmesg_restrict", 1},
	"linux-sysctl-kptr-restrict":                     {"kernel.kptr_restrict", 2},
	"linux-sysctl-yama-ptrace-scope":                 {"kernel.yama.ptrace_scope", 1},
	"linux-sysctl-unprivileged-bpf-disabled":         {"kernel.unprivileged_bpf_disabled", 1},
	"linux-sysctl-bpf-jit-harden":                    {"net.core.bpf_jit_harden", 2},
	"linux-sysctl-suid-dumpable":                     {"fs.suid_dumpable", 0},
	"linux-sysctl-protected-hardlinks":               {"fs.protected_hardlinks", 1},
	"linux-sysctl-protected-symlinks":                {"fs.protected_symlinks", 1},
}

func init() {
	for id, e := range sysctlBash {
		id := id
		e := e
		register("bash-"+id, []string{id}, func(_ core.Finding) (remediate.Snippet, error) {
			body := renderSysctlBash(e.key, e.val)
			return remediate.Snippet{
				Risk: remediate.RiskSafe, Idempotent: true,
				Content:   body,
				VerifyCmd: fmt.Sprintf("sysctl -n %s", e.key),
				Notes:     "Persists via /etc/sysctl.d drop-in (survives reboot) AND applies live via sysctl -w (no reboot needed).",
			}, nil
		})
	}
}

func renderSysctlBash(key string, val int) string {
	// One drop-in file per category so manual reverts are easy.
	dropin := sysctlDropinName(key)
	return strings.TrimLeft(fmt.Sprintf(`# Apply now + persist across reboot.
sudo sysctl -w %s=%d
echo '%s = %d' | sudo tee -a /etc/sysctl.d/%s >/dev/null
sudo sysctl --system >/dev/null`, key, val, key, val, dropin), "\n")
}

// sysctlDropinName routes related sysctl keys into the same /etc/sysctl.d
// file (60-network-hardening.conf, 60-kernel-hardening.conf,
// 60-fs-hardening.conf, 60-ipv6-hardening.conf) so an operator can
// revert the v0.20 hardening pass as a single unit.
func sysctlDropinName(key string) string {
	switch {
	case strings.HasPrefix(key, "kernel."):
		return "60-kernel-hardening.conf"
	case strings.HasPrefix(key, "net.ipv6."):
		return "60-ipv6-hardening.conf"
	case strings.HasPrefix(key, "fs."):
		return "60-fs-hardening.conf"
	case strings.HasPrefix(key, "net."):
		return "60-network-hardening.conf"
	default:
		return "60-misc-hardening.conf"
	}
}
