package digitalocean

import (
	"context"
	"fmt"
	"time"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

const snapshotMaxAgeDays = 365

// CheckVolumeOrphan flags block volumes with zero droplet
// attachments. Unattached volumes bill forever and are a common
// post-droplet-delete leftover.
var CheckVolumeOrphan = core.Check{
	ID:           "do-volume-orphan",
	Title:        "Block volumes should be attached to a droplet",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "volumes",
	ResourceType: docol.VolumeType,
	Description: "A DO block volume bills regardless of whether it is " +
		"attached to a droplet. Unattached volumes accumulate when " +
		"droplets are destroyed without their volumes; they cost " +
		"money for nothing and clutter the resource list.",
	Remediation: "Inspect: 'doctl compute volume list --format Name," +
		"DropletIDs,SizeGigabytes'. If the data is no longer needed, " +
		"'doctl compute volume delete <id>'. If it is, take a snapshot " +
		"and document where the data lives.",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1", "1.2"},
	},
	Tags:    []string{"volume", "hygiene", "cost"},
	Scanner: "volumes.Orphan",
}

func VolumeOrphan(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, v := range g.ByType(docol.VolumeType) {
		ids, _ := v.Attributes["droplet_ids"].([]int)
		f := core.Finding{
			CheckID:  CheckVolumeOrphan.ID,
			Severity: CheckVolumeOrphan.Severity,
			Resource: v.Ref(),
			Tags:     CheckVolumeOrphan.Tags,
		}
		if len(ids) == 0 {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("volume %q: no droplet attached", v.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("volume %q: attached to %d droplet(s)", v.Name, len(ids))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckVolumeNotEmpty flags volumes whose filesystem type is empty
// AND that are not attached to any droplet -- almost always a
// failed-provision or test-and-forget artifact.
var CheckVolumeNotEmpty = core.Check{
	ID:           "do-volume-unformatted-orphan",
	Title:        "Unformatted detached volumes should be cleaned up",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "volumes",
	ResourceType: docol.VolumeType,
	Description: "A volume with no filesystem_type set AND no droplet " +
		"attached has never been mounted by anything. These are almost " +
		"always failed-provision artifacts or test-and-forget leftovers; " +
		"they bill forever, contain no data, and confuse the audit trail.",
	Remediation: "'doctl compute volume delete <id>' for any unformatted, " +
		"detached volume. If you intend to use the volume, attach it " +
		"to a droplet and mkfs.",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"volume", "hygiene"},
	Scanner: "volumes.UnformattedOrphan",
}

func VolumeUnformattedOrphan(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, v := range g.ByType(docol.VolumeType) {
		ids, _ := v.Attributes["droplet_ids"].([]int)
		fsType, _ := v.Attributes["filesystem_type"].(string)
		f := core.Finding{
			CheckID:  CheckVolumeNotEmpty.ID,
			Severity: CheckVolumeNotEmpty.Severity,
			Resource: v.Ref(),
			Tags:     CheckVolumeNotEmpty.Tags,
		}
		if len(ids) == 0 && fsType == "" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("volume %q: unformatted + unattached", v.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("volume %q: formatted (%s) or attached", v.Name, fsType)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckSnapshotAge flags snapshots older than snapshotMaxAgeDays.
// Old snapshots are usually obsolete (the base image has rotated)
// and bill silently.
var CheckSnapshotAge = core.Check{
	ID:           "do-snapshot-too-old",
	Title:        "Snapshots older than one year should be reviewed",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "snapshots",
	ResourceType: docol.SnapshotType,
	Description: "Snapshots are normally taken before a risky change or " +
		"as part of a weekly backup rotation. A snapshot older than a " +
		"year is almost always obsolete: the source droplet's base " +
		"image has long since shifted, restoring it would produce a " +
		"system way out of patch compliance, and it still bills.",
	Remediation: "List + filter: 'doctl compute snapshot list --format " +
		"Name,ResourceType,Created'. Decide whether each old snapshot " +
		"is needed; delete the rest with 'doctl compute snapshot " +
		"delete <id>'. Document the retention policy for the rest.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.8.13"},
		"cis-v8":   {"11.2", "11.5"},
	},
	Tags:    []string{"snapshot", "hygiene", "cost"},
	Scanner: "snapshots.Age",
}

func SnapshotAge(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	threshold := time.Now().UTC().Add(-snapshotMaxAgeDays * 24 * time.Hour)
	for _, s := range g.ByType(docol.SnapshotType) {
		created, _ := s.Attributes["created_at"].(string)
		f := core.Finding{
			CheckID:  CheckSnapshotAge.ID,
			Severity: CheckSnapshotAge.Severity,
			Resource: s.Ref(),
			Tags:     CheckSnapshotAge.Tags,
		}
		t, err := time.Parse(time.RFC3339, created)
		switch {
		case err != nil:
			f.Status = core.StatusSkip
			f.Message = fmt.Sprintf("snapshot %q: unparsable created_at=%q", s.Name, created)
		case t.Before(threshold):
			days := int(time.Since(t).Hours() / 24)
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("snapshot %q: %d days old (> %d)", s.Name, days, snapshotMaxAgeDays)
		default:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("snapshot %q: created %s", s.Name, created)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckSnapshotResourceExists flags snapshots whose source resource
// (droplet or volume) is no longer present in this account. These
// are "ghost" snapshots whose source has been deleted, leaving the
// snapshot as the only copy of the data.
var CheckSnapshotResourceExists = core.Check{
	ID:           "do-snapshot-orphan-source",
	Title:        "Snapshots should have a still-existing source resource",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "snapshots",
	ResourceType: docol.SnapshotType,
	Description: "A snapshot whose source resource (droplet or volume) " +
		"has been deleted is the only copy of that data. This is " +
		"sometimes intentional (cold-storage snapshot of a retired " +
		"workload) but often indicates a forgotten cleanup. Worth " +
		"reviewing in case the data still matters.",
	Remediation: "List: 'doctl compute snapshot list --format Name," +
		"ResourceType,ResourceID'. Cross-reference each ResourceID " +
		"with the active droplets/volumes. For genuinely cold-storage " +
		"snapshots, document the retention reason; for forgotten ones, " +
		"delete.",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.8.13"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"snapshot", "hygiene"},
	Scanner: "snapshots.ResourceExists",
}

func SnapshotResourceExists(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	// Build live-resource id sets for droplet + volume snapshots.
	liveDroplets := map[string]bool{}
	for _, d := range g.ByType(docol.DropletType) {
		// DropletType resource IDs are "digitalocean.droplet.<num>".
		// Snapshot.resource_id is the numeric droplet id as string.
		parts := splitLast(d.ID, ".")
		liveDroplets[parts] = true
	}
	liveVolumes := map[string]bool{}
	for _, v := range g.ByType(docol.VolumeType) {
		parts := splitLast(v.ID, ".")
		liveVolumes[parts] = true
	}

	findings := []core.Finding{}
	for _, s := range g.ByType(docol.SnapshotType) {
		rt, _ := s.Attributes["resource_type"].(string)
		rid, _ := s.Attributes["resource_id"].(string)
		f := core.Finding{
			CheckID:  CheckSnapshotResourceExists.ID,
			Severity: CheckSnapshotResourceExists.Severity,
			Resource: s.Ref(),
			Tags:     CheckSnapshotResourceExists.Tags,
		}
		var live bool
		switch rt {
		case "droplet":
			live = liveDroplets[rid]
		case "volume":
			live = liveVolumes[rid]
		default:
			f.Status = core.StatusSkip
			f.Message = fmt.Sprintf("snapshot %q: unknown resource_type=%q", s.Name, rt)
			findings = append(findings, f)
			continue
		}
		if live {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("snapshot %q: source %s/%s still exists", s.Name, rt, rid)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("snapshot %q: source %s/%s no longer exists", s.Name, rt, rid)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// splitLast returns the last "."-separated piece of a string.
// Used for extracting the trailing godo numeric id from a
// core.Resource ID.
func splitLast(s, sep string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if string(s[i]) == sep {
			return s[i+1:]
		}
	}
	return s
}

func init() {
	core.Register(CheckVolumeOrphan, VolumeOrphan)
	core.Register(CheckVolumeNotEmpty, VolumeUnformattedOrphan)
	core.Register(CheckSnapshotAge, SnapshotAge)
	core.Register(CheckSnapshotResourceExists, SnapshotResourceExists)
}
