package ansible

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 4 — Ansible strategies for the 10 systemd-services checks.

type svcAnsEntry struct {
	unit, action string
	pkg          string
}

var serviceAnsible = map[string]svcAnsEntry{
	"linux-service-time-sync-active": {"chronyd.service", "enable", ""},
	"linux-service-auditd-enabled":   {"auditd.service", "enable", ""},
	"linux-service-rsyslog-active":   {"rsyslog.service", "enable", ""},
	"linux-service-cron-active":      {"cron.service", "enable", ""},
	"linux-service-avahi-disabled":   {"avahi-daemon.service", "disable", ""},
	"linux-service-cups-disabled":    {"cups.service", "disable", ""},
	"linux-service-dhcpd-disabled":   {"isc-dhcp-server.service", "disable", ""},
	"linux-service-telnet-absent":    {"telnetd.service", "mask", "telnetd"},
	"linux-service-rsh-absent":       {"rsh.service", "mask", "rsh-server"},
	"linux-service-tftp-absent":      {"tftp-server.service", "mask", "tftpd-hpa"},
}

func init() {
	for id, e := range serviceAnsible {
		id := id
		e := e
		register("ansible-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := renderSvcAnsible(id, e)
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: true, Content: body,
				Notes: "ansible.builtin.systemd is idempotent across enable/disable/mask.",
			}, nil
		})
	}
}

func renderSvcAnsible(id string, e svcAnsEntry) string {
	switch e.action {
	case "enable":
		return fmt.Sprintf(`- name: %s — ensure %s enabled + active
  ansible.builtin.systemd:
    name: %s
    enabled: true
    state: started
  become: true
`, id, e.unit, e.unit)
	case "disable":
		return fmt.Sprintf(`- name: %s — ensure %s disabled + stopped + masked
  ansible.builtin.systemd:
    name: %s
    enabled: false
    state: stopped
    masked: true
  become: true
`, id, e.unit, e.unit)
	case "mask":
		return fmt.Sprintf(`- name: %s — mask + uninstall %s
  block:
    - ansible.builtin.systemd:
        name: %s
        masked: true
        state: stopped
      ignore_errors: true
    - ansible.builtin.package:
        name: %s
        state: absent
  become: true
`, id, e.unit, e.unit, e.pkg)
	}
	return ""
}
