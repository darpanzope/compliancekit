package linux

import (
	"context"
	"fmt"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func kernelIntOf(host compliancekit.Resource, key string) (int, bool) {
	if !host.AttrBool("reachable") {
		return 0, false
	}
	raw, ok := host.Attributes["kernel"]
	if !ok {
		return 0, false
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return 0, false
	}
	v, ok := m[key].(int)
	return v, ok
}

func kernelSkip(check compliancekit.Check, host compliancekit.Resource, sysctl string) compliancekit.Finding {
	return compliancekit.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Status:   compliancekit.StatusSkip,
		Resource: host.Ref(),
		Message:  fmt.Sprintf("sysctl %s unavailable", sysctl),
		Tags:     check.Tags,
	}
}

// ============================================================
// linux-aslr-enabled
// ============================================================

// CheckASLREnabled requires kernel.randomize_va_space=2.
var CheckASLREnabled = compliancekit.Check{
	ID:           "linux-aslr-enabled",
	Title:        "Address Space Layout Randomization must be fully enabled",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "linux",
	Service:      "kernel",
	ResourceType: linuxcol.HostType,
	Description: "ASLR randomizes the address space of running " +
		"processes, raising the cost of memory-corruption exploits. " +
		"kernel.randomize_va_space=2 is the full-strength setting " +
		"(stack + heap + brk + vdso + mmap). 0 disables; 1 is a " +
		"weakened subset. CIS Ubuntu 3.2.1.",
	Remediation: "sysctl -w kernel.randomize_va_space=2 (runtime) and " +
		"add the line to /etc/sysctl.conf or a drop-in under " +
		"/etc/sysctl.d/ for persistence.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.8"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"kernel", "exploit-mitigation"},
	Scanner: "kernel.ASLREnabled",
}

// ASLREnabled is the CheckFunc for CheckASLREnabled.
func ASLREnabled(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	hosts := g.ByType(linuxcol.HostType)
	findings := make([]compliancekit.Finding, 0, len(hosts))
	for _, h := range hosts {
		v, ok := kernelIntOf(h, "randomize_va_space")
		if !ok {
			findings = append(findings, kernelSkip(CheckASLREnabled, h, "kernel.randomize_va_space"))
			continue
		}
		f := compliancekit.Finding{
			CheckID:  CheckASLREnabled.ID,
			Severity: CheckASLREnabled.Severity,
			Resource: h.Ref(),
			Tags:     CheckASLREnabled.Tags,
		}
		if v == 2 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("host %q: kernel.randomize_va_space=2", h.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("host %q: kernel.randomize_va_space=%d (want 2)", h.Name, v)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ============================================================
// linux-no-source-routing
// ============================================================

// CheckNoSourceRouting requires net.ipv4.conf.all.accept_source_route=0.
var CheckNoSourceRouting = compliancekit.Check{
	ID:           "linux-no-source-routing",
	Title:        "Kernel must not accept source-routed packets",
	Severity:     compliancekit.SeverityLow,
	Provider:     "linux",
	Service:      "kernel",
	ResourceType: linuxcol.HostType,
	Description: "Source-routed packets let a sender dictate the path " +
		"taken across the network, defeating egress filtering and " +
		"enabling spoofing. Modern Linux defaults to 0 (drop); this " +
		"check confirms the default has not been overridden. " +
		"CIS Ubuntu 3.3.1.",
	Remediation: "sysctl -w net.ipv4.conf.all.accept_source_route=0 " +
		"and persist via /etc/sysctl.d/.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"12.2"},
	},
	Tags:    []string{"kernel", "network"},
	Scanner: "kernel.NoSourceRouting",
}

// NoSourceRouting is the CheckFunc for CheckNoSourceRouting.
func NoSourceRouting(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	hosts := g.ByType(linuxcol.HostType)
	findings := make([]compliancekit.Finding, 0, len(hosts))
	for _, h := range hosts {
		v, ok := kernelIntOf(h, "accept_source_route_all")
		if !ok {
			findings = append(findings, kernelSkip(CheckNoSourceRouting, h, "net.ipv4.conf.all.accept_source_route"))
			continue
		}
		f := compliancekit.Finding{
			CheckID:  CheckNoSourceRouting.ID,
			Severity: CheckNoSourceRouting.Severity,
			Resource: h.Ref(),
			Tags:     CheckNoSourceRouting.Tags,
		}
		if v == 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("host %q: net.ipv4.conf.all.accept_source_route=0", h.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("host %q: net.ipv4.conf.all.accept_source_route=%d (want 0)", h.Name, v)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckASLREnabled, ASLREnabled)
	compliancekit.Register(CheckNoSourceRouting, NoSourceRouting)
}
