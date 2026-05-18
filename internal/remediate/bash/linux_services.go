package bash

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 4 — bash strategies for the 10 systemd-services checks.

type svcBashEntry struct {
	unit, action string // "enable" | "disable" | "mask"
	pkg          string // optional apt/dnf package name for absent checks
}

var serviceBash = map[string]svcBashEntry{
	"linux-service-time-sync-active": {"chronyd.service", "enable", ""},
	"linux-service-auditd-enabled":   {"auditd.service", "enable", ""},
	"linux-service-rsyslog-active":   {"rsyslog.service", "enable", ""},
	"linux-service-cron-active":      {"cron.service", "enable", ""},
	"linux-service-avahi-disabled":   {"avahi-daemon.service", "disable", ""},
	"linux-service-cups-disabled":    {"cups.service", "disable", ""},
	"linux-service-dhcpd-disabled":   {"isc-dhcp-server.service", "disable", ""},
	"linux-service-telnet-absent":    {"telnetd.service", "mask", "telnetd inetutils-telnetd"},
	"linux-service-rsh-absent":       {"rsh.service", "mask", "rsh-server inetutils-rsh"},
	"linux-service-tftp-absent":      {"tftp-server.service", "mask", "tftpd-hpa tftp-server"},
}

func init() {
	for id, e := range serviceBash {
		id := id
		e := e
		register("bash-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := renderSvcBash(e)
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: true, Content: body,
				VerifyCmd: fmt.Sprintf("systemctl is-active %s; systemctl is-enabled %s", e.unit, e.unit),
			}, nil
		})
	}
}

func renderSvcBash(e svcBashEntry) string {
	switch e.action {
	case "enable":
		return fmt.Sprintf(`sudo systemctl enable --now %s`, e.unit)
	case "disable":
		return fmt.Sprintf(`sudo systemctl disable --now %s
sudo systemctl mask %s   # prevents accidental re-enable`, e.unit, e.unit)
	case "mask":
		// "Absent" maps to mask + uninstall the package.
		return fmt.Sprintf(`sudo systemctl mask %s
# Then uninstall the package (Debian/Ubuntu OR RHEL family):
if command -v apt-get >/dev/null; then
  sudo apt-get remove --purge -y %s
elif command -v dnf >/dev/null; then
  sudo dnf remove -y %s
fi`, e.unit, e.pkg, e.pkg)
	}
	return ""
}
