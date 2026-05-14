package hetzner

import (
	"context"
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

func TestCollect_ProjectAnchorEmitted(t *testing.T) {
	c := NewWithClient(nil, "hetzner-test-fp")
	out, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d resources, want 1 (just the project anchor)", len(out))
	}
	if out[0].Type != ProjectType {
		t.Errorf("anchor type = %q, want %q", out[0].Type, ProjectType)
	}
	coord := cloudcommon.CoordOf(out[0])
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
