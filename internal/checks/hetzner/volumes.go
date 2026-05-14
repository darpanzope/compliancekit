package hetzner

import (
	"context"
	"fmt"

	hetznercol "github.com/darpanzope/compliancekit/internal/collectors/hetzner"
	"github.com/darpanzope/compliancekit/internal/core"
)

// CheckVolumeOrphan flags volumes with no attached server.
// Hetzner volumes bill regardless of attachment status.
var CheckVolumeOrphan = core.Check{
	ID:           "hetzner-volume-orphan",
	Title:        "Hetzner volumes should be attached to a server",
	Severity:     core.SeverityLow,
	Provider:     "hetzner",
	Service:      "volumes",
	ResourceType: hetznercol.VolumeType,
	Description: "A Hetzner Cloud volume bills regardless of whether " +
		"it's attached to a server. Unattached volumes accumulate when " +
		"servers are deleted but their volumes are left behind; they " +
		"cost money for nothing.",
	Remediation: "Either attach to a server ('hcloud volume attach " +
		"--server <name> <volume>') or delete ('hcloud volume delete " +
		"<volume>'). If the data matters, snapshot first.",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"volume", "hygiene", "cost"},
	Scanner: "volumes.Orphan",
}

func VolumeOrphan(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, v := range g.ByType(hetznercol.VolumeType) {
		attached, _ := v.Attributes["attached"].(bool)
		f := core.Finding{
			CheckID:  CheckVolumeOrphan.ID,
			Severity: CheckVolumeOrphan.Severity,
			Resource: v.Ref(),
			Tags:     CheckVolumeOrphan.Tags,
		}
		if attached {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("volume %q: attached", v.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("volume %q: orphan (unattached)", v.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckVolumeFormatted flags volumes with no filesystem format
// AND no attached server. These are failed-provision artifacts.
var CheckVolumeFormatted = core.Check{
	ID:           "hetzner-volume-unformatted-orphan",
	Title:        "Unformatted detached Hetzner volumes should be cleaned up",
	Severity:     core.SeverityLow,
	Provider:     "hetzner",
	Service:      "volumes",
	ResourceType: hetznercol.VolumeType,
	Description: "A Hetzner Cloud volume with no filesystem format AND " +
		"no attached server has never been mounted. These are almost " +
		"always failed-provision artifacts or test-and-forget " +
		"leftovers — they bill forever and contain no data.",
	Remediation: "'hcloud volume delete <volume>'. If you intend to use " +
		"the volume, attach it ('hcloud volume attach --server <name> " +
		"<volume>') and mkfs.",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"volume", "hygiene"},
	Scanner: "volumes.UnformattedOrphan",
}

func VolumeFormatted(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, v := range g.ByType(hetznercol.VolumeType) {
		attached, _ := v.Attributes["attached"].(bool)
		format, _ := v.Attributes["format"].(string)
		f := core.Finding{
			CheckID:  CheckVolumeFormatted.ID,
			Severity: CheckVolumeFormatted.Severity,
			Resource: v.Ref(),
			Tags:     CheckVolumeFormatted.Tags,
		}
		if !attached && format == "" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("volume %q: unformatted + unattached", v.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("volume %q: formatted (%s) or attached", v.Name, format)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckVolumeOrphan, VolumeOrphan)
	core.Register(CheckVolumeFormatted, VolumeFormatted)
}
