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

func TestCollect_EmitsProjectResource(t *testing.T) {
	override := &DefaultCredentials{
		ProjectID:   "p1",
		Credentials: &google.Credentials{ProjectID: "p1"},
	}
	c, err := New(context.Background(), Options{
		Projects:            []string{"p1", "p2"},
		CredentialsOverride: override,
	})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 2 {
		t.Fatalf("got %d resources, want 2 (one per project)", len(resources))
	}
	for _, r := range resources {
		if r.Type != ProjectType {
			t.Errorf("type: %q, want %q", r.Type, ProjectType)
		}
		if r.Provider != "gcp" {
			t.Errorf("provider: %q", r.Provider)
		}
		coord := cloudcommon.CoordOf(r)
		if coord.AccountID == "" {
			t.Errorf("project %q: account_id not stamped", r.Name)
		}
		if coord.Region != "" {
			t.Errorf("project %q: region should be empty (project is location-agnostic), got %q", r.Name, coord.Region)
		}
	}
}

func TestCollector_Name(t *testing.T) {
	c := &Collector{}
	if c.Name() != "gcp" {
		t.Errorf("Name() = %q, want gcp", c.Name())
	}
}
