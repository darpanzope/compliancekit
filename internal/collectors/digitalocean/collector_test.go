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
		"/v2/droplets": "testdata/droplets.json",
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

	if got, want := len(resources), 2; got != want {
		t.Fatalf("len(resources) = %d, want %d", got, want)
	}

	// Droplet 1: web-01, has backups + tags + recent image
	d1 := resources[0]
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

	// Droplet 2: db-01, no public IP, no backups, no tags, older image
	d2 := resources[1]
	if d2.Name != "db-01" {
		t.Errorf("d2.Name = %q, want db-01", d2.Name)
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
