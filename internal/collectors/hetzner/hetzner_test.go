package hetzner

import (
	"testing"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// Compile-time assertion that *Collector satisfies core.Collector.
var _ core.Collector = (*Collector)(nil)

func TestNew_ProjectFingerprint(t *testing.T) {
	c := New("hcloud-tok-abc12345-xyz")
	if got, want := c.projectID, "hetzner-hcloud-t"; got != want {
		t.Errorf("projectID = %q, want %q", got, want)
	}
}

func TestNew_ShortToken(t *testing.T) {
	c := New("abc")
	if got, want := c.projectID, "hetzner-project"; got != want {
		t.Errorf("projectID = %q, want %q", got, want)
	}
}

// TestProjectResource_Shape covers the project-anchor emission
// directly. The full Collect() integration test belongs at v1.1
// behind a build tag against a real Hetzner project; faking out
// every hcloud service client in unit tests would duplicate the
// SDK surface for no gain (same approach as GCP at v0.8).
func TestProjectResource_Shape(t *testing.T) {
	c := &Collector{projectID: "hetzner-test-fp"}
	r := c.projectResource()
	if r.Type != ProjectType {
		t.Errorf("anchor type = %q, want %q", r.Type, ProjectType)
	}
	coord := cloudcommon.CoordOf(r)
	if coord.AccountID != "hetzner-test-fp" {
		t.Errorf("account_id = %q, want hetzner-test-fp", coord.AccountID)
	}
}

func TestCollector_Name(t *testing.T) {
	c := &Collector{}
	if c.Name() != "hetzner" {
		t.Errorf("Name() = %q, want hetzner", c.Name())
	}
}
