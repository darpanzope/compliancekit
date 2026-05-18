package ansible

import (
	"fmt"
	"strings"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 2 — Ansible strategies for the 28 sysctl-shaped Linux
// hardening checks. The `ansible.builtin.sysctl` module handles
// runtime apply + sysctl.conf persistence + reload in one idempotent
// task — much simpler than the bash equivalent.

type sysctlAnsibleEntry struct {
	key string
	val int
}

var sysctlAnsible = map[string]sysctlAnsibleEntry{
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
	for id, e := range sysctlAnsible {
		id := id
		e := e
		register("ansible-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := renderSysctlAnsible(id, e.key, e.val)
			return remediate.Snippet{
				Risk: remediate.RiskSafe, Idempotent: true, Content: body,
				Notes: "ansible.builtin.sysctl is idempotent + handles both runtime apply (sysctl_set) and persistence (sysctl_file).",
			}, nil
		})
	}
}

func renderSysctlAnsible(id, key string, val int) string {
	return strings.TrimLeft(fmt.Sprintf(`- name: %s
  ansible.builtin.sysctl:
    name: %s
    value: "%d"
    state: present
    sysctl_set: true
    reload: true
    sysctl_file: /etc/sysctl.d/%s
  become: true
`, id, key, val, sysctlDropinName(key)), "\n")
}

// sysctlDropinName lives in this package too (duplicate of bash/
// linux_sysctl.go) so each remediation package stays import-free of
// the other. Keep both in sync when adding new sysctl categories.
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
