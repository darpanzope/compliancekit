package digitalocean

import (
	"context"
	"testing"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

func mkAccount(name string, attrs map[string]any) core.Resource {
	return core.Resource{
		ID:         "digitalocean.account." + name,
		Type:       docol.AccountType,
		Name:       name,
		Provider:   "digitalocean",
		Attributes: attrs,
	}
}

func newAccountGraph(resources ...core.Resource) *core.ResourceGraph {
	g := core.NewResourceGraph()
	for _, r := range resources {
		g.Add(r)
	}
	return g
}

func TestAccountStatusActive(t *testing.T) {
	cases := []struct {
		name   string
		status string
		want   core.Status
	}{
		{"active", "active", core.StatusPass},
		{"warning", "warning", core.StatusFail},
		{"locked", "locked", core.StatusFail},
		{"empty", "", core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkAccount("a", map[string]any{"status": c.status}))
			findings, _ := AccountStatusActive(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestAccountEmailVerified(t *testing.T) {
	g := newAccountGraph(
		mkAccount("ok", map[string]any{"email_verified": true}),
		mkAccount("bad", map[string]any{"email_verified": false}),
	)
	findings, _ := AccountEmailVerified(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "bad" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestAccountUsesNamedTeam(t *testing.T) {
	cases := []struct {
		team string
		want core.Status
	}{
		{"Personal", core.StatusFail},
		{"", core.StatusFail},
		{"Acme Inc", core.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.team, func(t *testing.T) {
			g := newAccountGraph(mkAccount("a", map[string]any{"team_name": c.team}))
			findings, _ := AccountUsesNamedTeam(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}
