// Package digitalocean holds the DigitalOcean check implementations.
//
// Each check is a compliancekit.Check metadata value plus a compliancekit.CheckFunc that
// queries the ResourceGraph and emits Findings. Checks register
// themselves into compliancekit.DefaultRegistry via the init function so the
// scan command picks them up automatically.
//
// At v0.1 metadata lives as Go vars next to the function. v0.3 will
// migrate to side-by-side YAML files (per CHECKS.md) once the
// `checks list` and `checks show` commands need a browseable catalog.
// The metadata struct shape is the same either way, so this is purely
// a serialization change.
package digitalocean

import (
	"context"
	"fmt"
	"time"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// CheckBackupsDisabled flags droplets without weekly backups enabled.
var CheckBackupsDisabled = compliancekit.Check{
	ID:           "do-droplet-backups-disabled",
	Title:        "Droplet backups must be enabled",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "droplets",
	ResourceType: docol.DropletType,
	Description: "DigitalOcean droplet backups take a weekly snapshot used to " +
		"recover from incidents, ransomware, or accidental deletion. " +
		"SOC 2 CC6.6 and CIS Controls v8 11.2 both require some form of " +
		"backup capability for production data.",
	Remediation: "Enable backups for the droplet via " +
		"'doctl compute droplet-action enable-backups <id>' or set " +
		"'backups: true' in your Terraform digitalocean_droplet resource.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6", "A1.2"},
		"iso27001": {"A.8.13", "A.5.30"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"backup", "recovery"},
	Scanner: "droplets.BackupsDisabled",
}

// BackupsDisabled is the CheckFunc for CheckBackupsDisabled.
func BackupsDisabled(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	droplets := g.ByType(docol.DropletType)
	findings := make([]compliancekit.Finding, 0, len(droplets))
	for _, d := range droplets {
		features, _ := d.Attributes["features"].([]string)
		hasBackups := containsString(features, "backups")

		f := compliancekit.Finding{
			CheckID:  CheckBackupsDisabled.ID,
			Severity: CheckBackupsDisabled.Severity,
			Resource: d.Ref(),
			Tags:     CheckBackupsDisabled.Tags,
		}
		if hasBackups {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("droplet %q has backups enabled", d.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("droplet %q has backups disabled", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckNoTags flags droplets without any tags, an attribution gap that
// makes ownership and environment classification ambiguous.
var CheckNoTags = compliancekit.Check{
	ID:           "do-droplet-no-tags",
	Title:        "Droplets should carry attribution tags",
	Severity:     compliancekit.SeverityLow,
	Provider:     "digitalocean",
	Service:      "droplets",
	ResourceType: docol.DropletType,
	Description: "Tags are how DigitalOcean resources are grouped for " +
		"firewall membership, cost attribution, and operational queries. " +
		"A droplet without any tags is effectively orphaned: incidents " +
		"are harder to triage, costs harder to allocate, and bulk " +
		"operations harder to scope. SOC 2 CC1.4 and CIS Controls v8 1.1 " +
		"both expect inventory attribution.",
	Remediation: "Add at least one tag identifying environment and owner: " +
		"'doctl compute droplet tag <id> --tag-name prod' or set 'tags' " +
		"in your Terraform digitalocean_droplet resource.",
	Frameworks: map[string][]string{
		"soc2":     {"CC1.4", "CC6.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"inventory", "attribution"},
	Scanner: "droplets.NoTags",
}

// NoTags is the CheckFunc for CheckNoTags.
func NoTags(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	droplets := g.ByType(docol.DropletType)
	findings := make([]compliancekit.Finding, 0, len(droplets))
	for _, d := range droplets {
		f := compliancekit.Finding{
			CheckID:  CheckNoTags.ID,
			Severity: CheckNoTags.Severity,
			Resource: d.Ref(),
			Tags:     CheckNoTags.Tags,
		}
		if len(d.Tags) == 0 {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("droplet %q has no tags", d.Name)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("droplet %q has %d tag(s)", d.Name, len(d.Tags))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// OldImageAgeLimit is the cutoff age above which a droplet image is
// considered stale. Exposed as a var so tests can override it without
// crafting fixtures with cleverly-aged timestamps.
var OldImageAgeLimit = 365 * 24 * time.Hour

// CheckOldImage flags droplets whose base image is older than
// OldImageAgeLimit (default: 1 year).
var CheckOldImage = compliancekit.Check{
	ID:           "do-droplet-old-image",
	Title:        "Droplet base image should be less than one year old",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "droplets",
	ResourceType: docol.DropletType,
	Description: "A droplet running an image older than one year is likely " +
		"missing patches for vulnerabilities disclosed since the image was " +
		"built. Rebuilding from a current image (or rotating the droplet) " +
		"is the cleanest mitigation. SOC 2 CC7.1 and CIS Controls v8 7.5 " +
		"both require a documented patch cadence.",
	Remediation: "Rebuild the droplet from a current image " +
		"('doctl compute droplet-action rebuild <id> --image ubuntu-22-04-x64') " +
		"or rotate it via an updated Terraform digitalocean_droplet block.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1", "CC7.2"},
		"iso27001": {"A.8.8", "A.8.19"},
		"cis-v8":   {"7.5"},
	},
	Tags:    []string{"patching", "vulnerability"},
	Scanner: "droplets.OldImage",
}

// OldImage is the CheckFunc for CheckOldImage.
func OldImage(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	droplets := g.ByType(docol.DropletType)
	findings := make([]compliancekit.Finding, 0, len(droplets))
	now := time.Now().UTC()

	for _, d := range droplets {
		f := compliancekit.Finding{
			CheckID:  CheckOldImage.ID,
			Severity: CheckOldImage.Severity,
			Resource: d.Ref(),
			Tags:     CheckOldImage.Tags,
		}

		imgCreated := d.Attr("image_created_at")
		if imgCreated == "" {
			f.Status = compliancekit.StatusSkip
			f.Message = "image creation timestamp unknown"
			findings = append(findings, f)
			continue
		}

		t, err := time.Parse(time.RFC3339, imgCreated)
		if err != nil {
			f.Status = compliancekit.StatusError
			f.Message = fmt.Sprintf("could not parse image_created_at %q: %v", imgCreated, err)
			findings = append(findings, f)
			continue
		}

		age := now.Sub(t)
		if age > OldImageAgeLimit {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("droplet %q image is %d days old (limit: %d)",
				d.Name, int(age.Hours()/24), int(OldImageAgeLimit.Hours()/24))
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("droplet %q image is %d days old",
				d.Name, int(age.Hours()/24))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// init registers all checks in this package into the default registry.
// The scan command's binary import (`_ "internal/checks/digitalocean"`)
// triggers this at startup so checks are available without explicit
// wiring at every call site.
func init() {
	compliancekit.Register(CheckBackupsDisabled, BackupsDisabled)
	compliancekit.Register(CheckNoTags, NoTags)
	compliancekit.Register(CheckOldImage, OldImage)
}

// containsString reports whether ss contains the exact string s.
// Small helper used by checks reading []string attribute values.
func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
