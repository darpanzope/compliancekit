// Package hetzner holds Hetzner Cloud check implementations.
//
// Each check is a compliancekit.Check metadata value plus a compliancekit.CheckFunc
// that queries the ResourceGraph and emits Findings. Checks
// register themselves into compliancekit.DefaultRegistry via the init
// function so the scan command picks them up automatically.
package hetzner

import (
	"context"
	"fmt"
	"time"

	hetznercol "github.com/darpanzope/compliancekit/internal/collectors/hetzner"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

const (
	serverImageMaxAgeDays = 365
)

// CheckServerBackups requires every server have a BackupWindow
// scheduled. Hetzner backups are taken once a day in the
// configured window; an empty window means no automated backups
// are running.
var CheckServerBackups = compliancekit.Check{
	ID:           "hetzner-server-no-backups",
	Title:        "Hetzner servers should have automated backups enabled",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "hetzner",
	Service:      "servers",
	ResourceType: hetznercol.ServerType,
	Description: "Hetzner Cloud servers expose a BackupWindow setting; " +
		"non-empty means a daily snapshot runs in that window. Empty " +
		"means no automated backups. SOC 2 A1.2 and ISO 27001 A.8.13 " +
		"both prescribe backup capability for production data.",
	Remediation: "Enable backups via the Hetzner Cloud Console " +
		"(Server > Backups > Enable Backups) or `hcloud server " +
		"enable-backup <name>`. Backups carry a 20% surcharge but " +
		"that's the standard cost of recoverable production.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2", "CC6.6"},
		"iso27001": {"A.8.13", "A.8.14"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"server", "backup", "recovery"},
	Scanner: "servers.Backups",
}

func ServerBackups(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, s := range g.ByType(hetznercol.ServerType) {
		win, _ := s.Attributes["backup_window"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckServerBackups.ID,
			Severity: CheckServerBackups.Severity,
			Resource: s.Ref(),
			Tags:     CheckServerBackups.Tags,
		}
		if win != "" {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("server %q: backups enabled (window %s)", s.Name, win)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("server %q: no backup window scheduled", s.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckServerRescueDisabled flags servers running with rescue
// mode enabled outside maintenance. Rescue mode bypasses the
// normal boot disk and exposes a temporary root shell — a
// legitimate ops state for hours, but a permanent posture
// problem.
var CheckServerRescueDisabled = compliancekit.Check{
	ID:           "hetzner-server-rescue-enabled",
	Title:        "Hetzner servers should not run with rescue mode enabled",
	Severity:     compliancekit.SeverityLow,
	Provider:     "hetzner",
	Service:      "servers",
	ResourceType: hetznercol.ServerType,
	Description: "Hetzner's rescue mode replaces the boot disk with a " +
		"recovery image granting temporary root, intended for short " +
		"maintenance windows. A server stuck in rescue mode is either " +
		"a forgotten recovery session or a live operator typing into " +
		"a non-persistent shell — both indicate the resource is not " +
		"in steady production state.",
	Remediation: "Power-cycle the server out of rescue: `hcloud server " +
		"disable-rescue <name>` followed by `hcloud server reset <name>`. " +
		"Confirm that the underlying issue that triggered rescue mode " +
		"has been resolved.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"server", "ops-hygiene"},
	Scanner: "servers.RescueDisabled",
}

func ServerRescueDisabled(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, s := range g.ByType(hetznercol.ServerType) {
		on, _ := s.Attributes["rescue_enabled"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckServerRescueDisabled.ID,
			Severity: CheckServerRescueDisabled.Severity,
			Resource: s.Ref(),
			Tags:     CheckServerRescueDisabled.Tags,
		}
		if on {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("server %q: rescue mode enabled", s.Name)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("server %q: rescue mode disabled", s.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckServerImageAge flags servers running from an image more
// than 1 year old. Patch baseline + supply-chain freshness signal.
var CheckServerImageAge = compliancekit.Check{
	ID:           "hetzner-server-old-image",
	Title:        "Hetzner servers should not run from images older than 1 year",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "hetzner",
	Service:      "servers",
	ResourceType: hetznercol.ServerType,
	Description: "A Hetzner server built from a base image more than a " +
		"year old will be missing roughly a year of OS-vendor patches " +
		"unless ongoing apt-upgrade / dnf-upgrade has been bringing the " +
		"running system forward. Even with package upgrades, kernel + " +
		"base userland drift is real. Rebuilding from a fresh image " +
		"forces a clean baseline.",
	Remediation: "Snapshot the server, build a new server from a current " +
		"image, restore any custom config, switch DNS / load balancer " +
		"targets. Hetzner doesn't support in-place rebase. Schedule per " +
		"server in routine maintenance.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1"},
		"iso27001": {"A.8.8"},
		"cis-v8":   {"7.4"},
	},
	Tags:    []string{"server", "patching", "supply-chain"},
	Scanner: "servers.ImageAge",
}

func ServerImageAge(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	threshold := time.Now().UTC().Add(-serverImageMaxAgeDays * 24 * time.Hour)
	for _, s := range g.ByType(hetznercol.ServerType) {
		f := compliancekit.Finding{
			CheckID:  CheckServerImageAge.ID,
			Severity: CheckServerImageAge.Severity,
			Resource: s.Ref(),
			Tags:     CheckServerImageAge.Tags,
		}
		t, ok := s.Attributes["image_created"].(time.Time)
		imageName, _ := s.Attributes["image_name"].(string)
		switch {
		case !ok || t.IsZero():
			f.Status = compliancekit.StatusSkip
			f.Message = fmt.Sprintf("server %q: image creation time unavailable", s.Name)
		case t.Before(threshold):
			days := int(time.Since(t).Hours() / 24)
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("server %q: image %q is %d days old (> %d)", s.Name, imageName, days, serverImageMaxAgeDays)
		default:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("server %q: image %q current", s.Name, imageName)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckServerStatusRunning flags servers in non-running states.
// A stopped server still bills (Hetzner pricing is per-hour-of-
// allocation, not per-hour-of-running), so an "off" server is a
// pay-for-nothing leak.
var CheckServerStatusRunning = compliancekit.Check{
	ID:           "hetzner-server-not-running",
	Title:        "Hetzner servers should be in 'running' status",
	Severity:     compliancekit.SeverityLow,
	Provider:     "hetzner",
	Service:      "servers",
	ResourceType: hetznercol.ServerType,
	Description: "A Hetzner Cloud server bills regardless of whether " +
		"it's powered on. A server in `off` or `initializing` status " +
		"is either a forgotten ops experiment, a half-finished " +
		"provision, or a fleet item that should have been deleted. " +
		"Worth reviewing each non-running server.",
	Remediation: "List + filter: `hcloud server list --output " +
		"columns=name,status,location`. For each non-running server, " +
		"either restart it (`hcloud server poweron <name>`) or delete " +
		"it (`hcloud server delete <name>`).",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"server", "hygiene", "cost"},
	Scanner: "servers.StatusRunning",
}

func ServerStatusRunning(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, s := range g.ByType(hetznercol.ServerType) {
		status, _ := s.Attributes["status"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckServerStatusRunning.ID,
			Severity: CheckServerStatusRunning.Severity,
			Resource: s.Ref(),
			Tags:     CheckServerStatusRunning.Tags,
		}
		if status == "running" {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("server %q: running", s.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("server %q: status=%q", s.Name, status)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckServerNotLocked flags servers with the delete-protection
// flag still set after the protection window has likely passed.
// Locked = true is a legitimate operator choice for prod, BUT
// dev / staging servers that stay locked indefinitely indicate
// forgotten protection that blocks cleanup.
var CheckServerNotLocked = compliancekit.Check{
	ID:           "hetzner-server-locked",
	Title:        "Non-production Hetzner servers should not stay locked indefinitely",
	Severity:     compliancekit.SeverityLow,
	Provider:     "hetzner",
	Service:      "servers",
	ResourceType: hetznercol.ServerType,
	Description: "Hetzner servers expose a delete-protection lock flag. " +
		"It's correct to leave prod servers locked. It's a hygiene " +
		"problem to leave dev/staging/test servers locked — operators " +
		"typically apply the lock during a sensitive change and forget " +
		"to remove it, which then blocks routine cleanup. This check " +
		"is informational; expect to skip it for true prod assets via " +
		"a profile or a waiver from v0.18 onwards.",
	Remediation: "Audit locks: `hcloud server list --selector " +
		"environment=production` (and inverse). For each non-prod " +
		"locked server, unlock via `hcloud server disable-protection " +
		"<name> --delete`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"server", "hygiene"},
	Scanner: "servers.NotLocked",
}

func ServerNotLocked(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, s := range g.ByType(hetznercol.ServerType) {
		locked, _ := s.Attributes["locked"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckServerNotLocked.ID,
			Severity: CheckServerNotLocked.Severity,
			Resource: s.Ref(),
			Tags:     CheckServerNotLocked.Tags,
		}
		if locked {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("server %q: delete-protection enabled (review for prod intent)", s.Name)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("server %q: not delete-protected", s.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckServerBackups, ServerBackups)
	compliancekit.Register(CheckServerRescueDisabled, ServerRescueDisabled)
	compliancekit.Register(CheckServerImageAge, ServerImageAge)
	compliancekit.Register(CheckServerStatusRunning, ServerStatusRunning)
	compliancekit.Register(CheckServerNotLocked, ServerNotLocked)
}
