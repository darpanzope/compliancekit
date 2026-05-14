package digitalocean

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
)

// Compile-time assertion that *Collector satisfies core.Collector.
var _ core.Collector = (*Collector)(nil)

func TestCollector_Collect_Droplets(t *testing.T) {
	server := newFixtureServer(t, map[string]string{
		"/v2/account":        "testdata/account.json",
		"/v2/droplets":       "testdata/droplets.json",
		"/v2/firewalls":      "testdata/firewalls.json",
		"/v2/vpcs":           "testdata/empty_vpcs.json",
		"/v2/vpcs/peerings":  "testdata/empty_vpc_peerings.json",
		"/v2/load_balancers": "testdata/empty_load_balancers.json",
		"/v2/domains":        "testdata/empty_domains.json",
		"/v2/certificates":   "testdata/empty_certificates.json",
		"/v2/volumes":        "testdata/empty_volumes.json",
		"/v2/snapshots":      "testdata/empty_snapshots.json",
	})
	defer server.Close()

	client, err := newClient("test-token", server.URL)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	c := NewWithClient(client)

	resources, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// 1 account anchor + 2 droplets + 1 firewall = 4 resources.
	// (VPC + LB services return empty arrays from the fixtures.)
	if got, want := len(resources), 4; got != want {
		t.Fatalf("len(resources) = %d, want %d", got, want)
	}

	// Account anchor is first.
	if got, want := resources[0].Type, AccountType; got != want {
		t.Errorf("resources[0].Type = %q, want %q", got, want)
	}

	// Droplet 1: web-01, has backups + tags + recent image
	d1 := resources[1]
	if want := "digitalocean.droplet.123456"; d1.ID != want {
		t.Errorf("d1.ID = %q, want %q", d1.ID, want)
	}
	if d1.Name != "web-01" {
		t.Errorf("d1.Name = %q, want web-01", d1.Name)
	}
	if d1.Provider != "digitalocean" {
		t.Errorf("d1.Provider = %q, want digitalocean", d1.Provider)
	}
	if d1.Region != "nyc3" {
		t.Errorf("d1.Region = %q, want nyc3", d1.Region)
	}
	if got := d1.Attr("image_slug"); got != "ubuntu-22-04-x64" {
		t.Errorf(`d1.Attr("image_slug") = %q, want ubuntu-22-04-x64`, got)
	}
	if got := d1.Attr("public_ipv4"); got != "203.0.113.10" {
		t.Errorf(`d1.Attr("public_ipv4") = %q, want 203.0.113.10`, got)
	}
	if !d1.HasTag("prod") {
		t.Error("d1 missing 'prod' tag")
	}
	if features, ok := d1.Attributes["features"].([]string); !ok {
		t.Errorf(`d1.Attributes["features"] type = %T, want []string`, d1.Attributes["features"])
	} else if !contains(features, "backups") {
		t.Errorf("d1.features = %v, want to include 'backups'", features)
	}

	// Droplet 1 should have a firewall edge populated (web-fw protects it).
	// Edge values are full Resource IDs so ResourceGraph.Related can look
	// the target up directly via ByID.
	wantFWID := "digitalocean.firewall.fw-aaaa-1111"
	if got := d1.Relations[EdgeFirewall]; len(got) != 1 || got[0] != wantFWID {
		t.Errorf("d1.Relations[firewall] = %v, want [%s]", got, wantFWID)
	}

	// Droplet 2: db-01, no public IP, no backups, no tags, older image
	d2 := resources[2]
	if d2.Name != "db-01" {
		t.Errorf("d2.Name = %q, want db-01", d2.Name)
	}
	// Droplet 2 is not in any firewall's droplet_ids; should have no edge.
	if got := d2.Relations[EdgeFirewall]; len(got) != 0 {
		t.Errorf("d2.Relations[firewall] = %v, want empty", got)
	}
	if got := d2.Attr("public_ipv4"); got != "" {
		t.Errorf(`d2.Attr("public_ipv4") = %q, want empty (private only)`, got)
	}
	if len(d2.Tags) != 0 {
		t.Errorf("d2.Tags = %v, want empty", d2.Tags)
	}
	if features, _ := d2.Attributes["features"].([]string); len(features) != 0 {
		t.Errorf("d2.features = %v, want empty (no backups)", features)
	}

	// Firewall resource should be present and well-formed.
	fw := resources[3]
	if fw.Type != FirewallType {
		t.Errorf("fw.Type = %q, want %q", fw.Type, FirewallType)
	}
	if fw.Name != "web-fw" {
		t.Errorf("fw.Name = %q, want web-fw", fw.Name)
	}
	if got, _ := fw.Attributes["droplet_ids"].([]int); len(got) != 1 || got[0] != 123456 {
		t.Errorf(`fw.Attributes["droplet_ids"] = %v, want [123456]`, fw.Attributes["droplet_ids"])
	}
}

func TestLinkDropletsToFirewalls(t *testing.T) {
	droplets := []core.Resource{
		{ID: "digitalocean.droplet.1", Type: DropletType},
		{ID: "digitalocean.droplet.2", Type: DropletType},
	}
	firewalls := []core.Resource{
		{
			ID:   "digitalocean.firewall.fw1",
			Type: FirewallType,
			Attributes: map[string]any{
				"droplet_ids": []int{1},
			},
		},
		{
			ID:   "digitalocean.firewall.fw2",
			Type: FirewallType,
			Attributes: map[string]any{
				"droplet_ids": []int{1, 2},
			},
		},
	}

	linkDropletsToFirewalls(droplets, firewalls)

	if got := droplets[0].Relations[EdgeFirewall]; len(got) != 2 {
		t.Errorf("droplet 1 firewall edges = %v, want 2", got)
	}
	if got := droplets[1].Relations[EdgeFirewall]; len(got) != 1 {
		t.Errorf("droplet 2 firewall edges = %v, want 1", got)
	}
	// Edges must store full Resource IDs, not raw godo IDs.
	for _, edge := range droplets[0].Relations[EdgeFirewall] {
		if edge != "digitalocean.firewall.fw1" && edge != "digitalocean.firewall.fw2" {
			t.Errorf("unexpected edge value %q", edge)
		}
	}
}

func TestCollector_Collect_PropagatesAPIErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"id":"unauthorized","message":"Unable to authenticate you"}`))
	}))
	defer server.Close()

	client, err := newClient("bad-token", server.URL)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	c := NewWithClient(client)

	_, err = c.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error when API returns 401")
	}
}

// newFixtureServer returns an httptest.Server that serves canned JSON
// from testdata files keyed by request path. Used by both this file
// and probe_test.go.
func newFixtureServer(t *testing.T, paths map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for path, fixture := range paths {
		fixturePath := fixture // pin for closure
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			data, err := os.ReadFile(filepath.Join(".", fixturePath))
			if err != nil {
				t.Errorf("read fixture %s: %v", fixturePath, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)
		})
	}
	return httptest.NewServer(mux)
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
