package linux

import (
	"context"
	"fmt"
	"strings"

	docol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 1 — distro support gate. Asserts every host's
// `/etc/os-release` ID is on the supported-distro allowlist. Per-
// distro behavior in later checks (sysctl variants, package manager,
// init-system semantics) all assume a recognized distro; if detection
// failed OR the distro is outside the allowlist, downstream checks
// can't reliably interpret findings.

// supportedDistros are the ID values the v0.20 collector + check
// surface understands. Per the v0.20 issue scope: Debian / Ubuntu /
// RHEL / CentOS / Rocky / Alma / Fedora / Alpine / Amazon Linux 2 + 2023.
var supportedDistros = map[string]bool{
	"debian":    true,
	"ubuntu":    true,
	"rhel":      true,
	"centos":    true,
	"rocky":     true,
	"almalinux": true,
	"fedora":    true,
	"alpine":    true,
	"amzn":      true,
}

var CheckDistroSupported = compliancekit.Check{
	ID:           "linux-distro-supported",
	Title:        "/etc/os-release ID must be on the supported-distro allowlist",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "linux",
	Service:      "distro",
	ResourceType: docol.HostType,
	Description: "v0.20 introduces per-distro behavior in many Linux checks " +
		"(package manager, init system, sysctl key names). The collector " +
		"reads /etc/os-release at the top of every gather pass; if the " +
		"ID isn't on the allowlist (debian, ubuntu, rhel, centos, rocky, " +
		"almalinux, fedora, alpine, amzn) downstream checks fall through " +
		"to generic defaults that may misclassify findings. Pin the host " +
		"to a supported distro OR open a tracking issue to extend the " +
		"allowlist.",
	Remediation: "Either migrate the workload to a supported distro " +
		"(Ubuntu LTS / Debian Stable / RHEL family / Alpine / Amazon " +
		"Linux 2 or 2023), or open an issue at " +
		"https://github.com/darpanzope/compliancekit/issues with the " +
		"target distro + /etc/os-release contents so it can be added to " +
		"`supportedDistros` in `internal/checks/linux/distro.go`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1"},
		"iso27001": {"A.8.8"},
		"cis-v8":   {"7.3"},
	},
	Tags:    []string{"distro", "platform"},
	Scanner: "linux.distro.Supported",
}

func DistroSupported(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, h := range g.ByType(docol.HostType) {
		f := compliancekit.Finding{
			CheckID:  CheckDistroSupported.ID,
			Severity: CheckDistroSupported.Severity,
			Resource: h.Ref(),
			Tags:     CheckDistroSupported.Tags,
		}
		reachable, _ := h.Attributes["reachable"].(bool)
		if !reachable {
			f.Status = compliancekit.StatusSkip
			f.Message = fmt.Sprintf("host %q: unreachable; skipping distro check", h.Name)
			findings = append(findings, f)
			continue
		}
		id, _ := h.Attributes["distro_id"].(string)
		pretty, _ := h.Attributes["distro_pretty_name"].(string)
		if id == "" {
			osErr, _ := h.Attributes["os_release_error"].(string)
			f.Status = compliancekit.StatusError
			f.Message = fmt.Sprintf("host %q: /etc/os-release unreadable: %s",
				h.Name, ifEmpty(osErr, "no distro_id captured"))
			findings = append(findings, f)
			continue
		}
		if supportedDistros[strings.ToLower(id)] {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("host %q: distro %q is on the supported allowlist", h.Name, pretty)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("host %q: distro %q (id=%q) is NOT on the supported allowlist", h.Name, pretty, id)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func ifEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func init() {
	compliancekit.Register(CheckDistroSupported, DistroSupported)
}
