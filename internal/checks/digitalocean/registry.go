package digitalocean

import (
	"context"
	"fmt"
	"time"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

const registryGCMaxAgeDays = 30

var CheckRegistryGarbageCollection = core.Check{
	ID:           "do-registry-no-recent-gc",
	Title:        "Container registries should run garbage collection regularly",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "registry",
	ResourceType: docol.RegistryType,
	Description: "DO Container Registry does not auto-delete untagged or " +
		"overwritten image layers; only an explicit garbage-collection " +
		"run reclaims that storage. A registry with no GC for more " +
		"than 30 days is paying for orphan blobs and accumulating " +
		"untracked image content -- both a cost and an audit-trail " +
		"problem.",
	Remediation: "'doctl registry garbage-collection start <registry>'. " +
		"Schedule this in CI on a weekly cadence (e.g. a GitHub Actions " +
		"cron job). The DO control panel also exposes a manual run.",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"3.5"},
	},
	Tags:    []string{"registry", "hygiene", "cost"},
	Scanner: "registry.GC",
}

func RegistryGarbageCollection(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	threshold := time.Now().UTC().Add(-registryGCMaxAgeDays * 24 * time.Hour)
	for _, r := range g.ByType(docol.RegistryType) {
		f := core.Finding{
			CheckID:  CheckRegistryGarbageCollection.ID,
			Severity: CheckRegistryGarbageCollection.Severity,
			Resource: r.Ref(),
			Tags:     CheckRegistryGarbageCollection.Tags,
		}
		raw := r.Attributes["last_gc_at"]
		t, ok := raw.(time.Time)
		switch {
		case !ok || t.IsZero():
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("registry %q: no garbage-collection run on record", r.Name)
		case t.Before(threshold):
			days := int(time.Since(t).Hours() / 24)
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("registry %q: last GC %d days ago (> %d)", r.Name, days, registryGCMaxAgeDays)
		default:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("registry %q: last GC %s", r.Name, t.Format(time.RFC3339))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckRegistryHasRepositories = core.Check{
	ID:           "do-registry-empty",
	Title:        "Container registries should host at least one repository",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "registry",
	ResourceType: docol.RegistryType,
	Description: "An empty container registry pays its subscription tier " +
		"for nothing. Either delete the registry or push the images it " +
		"was provisioned for.",
	Remediation: "Inspect: 'doctl registry repository list-v2 " +
		"<registry>'. If genuinely unused, 'doctl registry delete'. " +
		"Otherwise complete the image-pipeline setup.",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"registry", "hygiene", "cost"},
	Scanner: "registry.HasRepositories",
}

func RegistryHasRepositories(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, r := range g.ByType(docol.RegistryType) {
		n, _ := r.Attributes["repository_count"].(int)
		f := core.Finding{
			CheckID:  CheckRegistryHasRepositories.ID,
			Severity: CheckRegistryHasRepositories.Severity,
			Resource: r.Ref(),
			Tags:     CheckRegistryHasRepositories.Tags,
		}
		if n > 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("registry %q: %d repository/repositories", r.Name, n)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("registry %q: empty", r.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckRegistryNotStarterTier = core.Check{
	ID:           "do-registry-starter-tier",
	Title:        "Production container registries should not run on the Starter tier",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "registry",
	ResourceType: docol.RegistryType,
	Description: "The Starter subscription tier is capped at 500 MB " +
		"storage + 1 repository -- adequate for evaluation, not for " +
		"production. A production registry stuck on Starter is one " +
		"image push from a quota-exhaustion outage. Upgrade to Basic " +
		"or Professional before scale matters.",
	Remediation: "'doctl registry options subscription-tiers' lists the " +
		"available tiers. Upgrade via the control panel " +
		"(Registry > Settings > Plan).",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"11.1"},
	},
	Tags:    []string{"registry", "capacity"},
	Scanner: "registry.NotStarterTier",
}

func RegistryNotStarterTier(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, r := range g.ByType(docol.RegistryType) {
		tier, _ := r.Attributes["subscription_tier"].(string)
		f := core.Finding{
			CheckID:  CheckRegistryNotStarterTier.ID,
			Severity: CheckRegistryNotStarterTier.Severity,
			Resource: r.Ref(),
			Tags:     CheckRegistryNotStarterTier.Tags,
		}
		if tier == "starter" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("registry %q: on Starter tier (500MB limit)", r.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("registry %q: tier=%q", r.Name, tier)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckRegistryGarbageCollection, RegistryGarbageCollection)
	core.Register(CheckRegistryHasRepositories, RegistryHasRepositories)
	core.Register(CheckRegistryNotStarterTier, RegistryNotStarterTier)
}
