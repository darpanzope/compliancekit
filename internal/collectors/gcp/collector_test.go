package gcp

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/oauth2/google"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
)

func TestNew_ExplicitProjects(t *testing.T) {
	override := &DefaultCredentials{
		ProjectID:   "credential-default",
		Credentials: &google.Credentials{ProjectID: "credential-default"},
	}
	c, err := New(context.Background(), Options{
		Projects:            []string{"explicit-a", "explicit-b"},
		CredentialsOverride: override,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := c.Projects()
	if len(got) != 2 || got[0] != "explicit-a" || got[1] != "explicit-b" {
		t.Errorf("got %+v, want [explicit-a explicit-b]", got)
	}
}

func TestNew_FallsBackToCredentialProject(t *testing.T) {
	override := &DefaultCredentials{
		ProjectID:   "my-default",
		Credentials: &google.Credentials{ProjectID: "my-default"},
	}
	c, err := New(context.Background(), Options{
		CredentialsOverride: override,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Projects(); len(got) != 1 || got[0] != "my-default" {
		t.Errorf("got %+v, want [my-default]", got)
	}
}

func TestNew_NoProjectErrors(t *testing.T) {
	override := &DefaultCredentials{
		ProjectID:   "",
		Credentials: &google.Credentials{},
	}
	_, err := New(context.Background(), Options{
		CredentialsOverride: override,
	})
	if err == nil || !strings.Contains(err.Error(), "no projects specified") {
		t.Errorf("expected 'no projects specified' error, got %v", err)
	}
}

// TestProjectResource_Shape covers the project-anchor emission
// directly. The full Collect() integration test belongs at v1.1
// behind a build tag against a real GCP test project; faking out
// every service client in unit tests would duplicate the SDK
// surface for no gain.
func TestProjectResource_Shape(t *testing.T) {
	c := &Collector{projects: []string{"p1", "p2"}}
	for _, projectID := range c.projects {
		r := c.projectResource(projectID)
		if r.Type != ProjectType {
			t.Errorf("type: %q, want %q", r.Type, ProjectType)
		}
		if r.Provider != "gcp" {
			t.Errorf("provider: %q", r.Provider)
		}
		coord := cloudcommon.CoordOf(r)
		if coord.AccountID != projectID {
			t.Errorf("project %q: account_id = %q, want %q", projectID, coord.AccountID, projectID)
		}
		if coord.Region != "" {
			t.Errorf("project %q: region should be empty (project is location-agnostic), got %q", projectID, coord.Region)
		}
	}
}

func TestCollector_Name(t *testing.T) {
	c := &Collector{}
	if c.Name() != "gcp" {
		t.Errorf("Name() = %q, want gcp", c.Name())
	}
}
