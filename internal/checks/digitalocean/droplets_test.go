package digitalocean

import (
	"context"
	"testing"
	"time"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func newDropletGraph(t *testing.T, droplets ...compliancekit.Resource) *compliancekit.ResourceGraph {
	t.Helper()
	g := compliancekit.NewResourceGraph()
	for _, d := range droplets {
		g.Add(d)
	}
	return g
}

func droplet(id, name string, features []string, tags []string, imageCreatedAt string) compliancekit.Resource {
	return compliancekit.Resource{
		ID:       "digitalocean.droplet." + id,
		Type:     docol.DropletType,
		Name:     name,
		Provider: "digitalocean",
		Attributes: map[string]any{
			"features":         features,
			"image_created_at": imageCreatedAt,
		},
		Tags: tags,
	}
}

func TestBackupsDisabled(t *testing.T) {
	g := newDropletGraph(t,
		droplet("1", "web-01", []string{"backups", "ipv6"}, nil, ""),
		droplet("2", "db-01", []string{}, nil, ""),
		droplet("3", "cache-01", []string{"ipv6"}, nil, ""),
	)

	findings, err := BackupsDisabled(context.Background(), g)
	if err != nil {
		t.Fatalf("BackupsDisabled: %v", err)
	}
	if got, want := len(findings), 3; got != want {
		t.Fatalf("len(findings) = %d, want %d", got, want)
	}

	statusByResource := map[string]compliancekit.Status{}
	for _, f := range findings {
		statusByResource[f.Resource.ID] = f.Status
		if f.Severity != compliancekit.SeverityMedium {
			t.Errorf("%s: severity = %s, want medium", f.Resource.ID, f.Severity)
		}
	}
	if got := statusByResource["digitalocean.droplet.1"]; got != compliancekit.StatusPass {
		t.Errorf("web-01 status = %s, want pass", got)
	}
	if got := statusByResource["digitalocean.droplet.2"]; got != compliancekit.StatusFail {
		t.Errorf("db-01 status = %s, want fail", got)
	}
	if got := statusByResource["digitalocean.droplet.3"]; got != compliancekit.StatusFail {
		t.Errorf("cache-01 status = %s, want fail (no 'backups' in features)", got)
	}
}

func TestNoTags(t *testing.T) {
	g := newDropletGraph(t,
		droplet("1", "web-01", nil, []string{"prod", "web"}, ""),
		droplet("2", "orphan", nil, nil, ""),
	)

	findings, err := NoTags(context.Background(), g)
	if err != nil {
		t.Fatalf("NoTags: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2", len(findings))
	}

	for _, f := range findings {
		switch f.Resource.ID {
		case "digitalocean.droplet.1":
			if f.Status != compliancekit.StatusPass {
				t.Errorf("web-01: %s, want pass", f.Status)
			}
		case "digitalocean.droplet.2":
			if f.Status != compliancekit.StatusFail {
				t.Errorf("orphan: %s, want fail", f.Status)
			}
		}
	}
}

func TestOldImage(t *testing.T) {
	now := time.Now().UTC()
	fresh := now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	ancient := now.Add(-2 * 365 * 24 * time.Hour).Format(time.RFC3339)

	g := newDropletGraph(t,
		droplet("1", "fresh", nil, nil, fresh),
		droplet("2", "ancient", nil, nil, ancient),
		droplet("3", "unknown-time", nil, nil, ""),
		droplet("4", "bad-time", nil, nil, "not a date"),
	)

	findings, err := OldImage(context.Background(), g)
	if err != nil {
		t.Fatalf("OldImage: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("len(findings) = %d, want 4", len(findings))
	}

	byID := map[string]compliancekit.Status{}
	for _, f := range findings {
		byID[f.Resource.ID] = f.Status
	}
	if got := byID["digitalocean.droplet.1"]; got != compliancekit.StatusPass {
		t.Errorf("fresh: %s, want pass", got)
	}
	if got := byID["digitalocean.droplet.2"]; got != compliancekit.StatusFail {
		t.Errorf("ancient: %s, want fail", got)
	}
	if got := byID["digitalocean.droplet.3"]; got != compliancekit.StatusSkip {
		t.Errorf("unknown-time: %s, want skip", got)
	}
	if got := byID["digitalocean.droplet.4"]; got != compliancekit.StatusError {
		t.Errorf("bad-time: %s, want error", got)
	}
}

func TestChecks_RegisterIntoDefaultRegistry(t *testing.T) {
	// init() ran when the test binary loaded this package. Verify the
	// three checks are present in the default registry.
	for _, id := range []string{
		CheckBackupsDisabled.ID,
		CheckNoTags.ID,
		CheckOldImage.ID,
	} {
		if _, ok := compliancekit.Lookup(id); !ok {
			t.Errorf("check %q not registered in default registry", id)
		}
	}
}
