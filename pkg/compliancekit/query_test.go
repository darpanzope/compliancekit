package compliancekit

import (
	"strings"
	"testing"
)

func sampleGraph() *ResourceGraph {
	g := NewResourceGraph()
	g.Add(Resource{
		ID: "do.droplet.1", Type: "digitalocean.droplet", Name: "web-1",
		Provider: "digitalocean", Region: "nyc1",
		Tags:       []string{"prod", "web"},
		Attributes: map[string]any{"backups": true, "image_age_days": 30},
	})
	g.Add(Resource{
		ID: "do.droplet.2", Type: "digitalocean.droplet", Name: "db-1",
		Provider: "digitalocean", Region: "nyc3",
		Tags:       []string{"prod", "db"},
		Attributes: map[string]any{"backups": false, "image_age_days": 400},
	})
	g.Add(Resource{
		ID: "do.droplet.3", Type: "digitalocean.droplet", Name: "staging",
		Provider: "digitalocean", Region: "ams3",
		Tags:       []string{"staging"},
		Attributes: map[string]any{"backups": true, "image_age_days": 60},
	})
	g.Add(Resource{
		ID: "linux.host.1", Type: "linux.host", Name: "bastion",
		Provider:   "linux",
		Tags:       []string{},
		Attributes: map[string]any{"reachable": true},
	})
	return g
}

func TestQuery_TypeEquality(t *testing.T) {
	g := sampleGraph()
	got, err := g.Query(`type = "digitalocean.droplet"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Errorf("got %d, want 3", len(got))
	}
}

func TestQuery_ProviderAndRegion(t *testing.T) {
	g := sampleGraph()
	got, err := g.Query(`provider = "digitalocean" AND region = "nyc1"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "web-1" {
		t.Errorf("got %+v, want web-1 only", names(got))
	}
}

func TestQuery_TagContains(t *testing.T) {
	g := sampleGraph()
	got, err := g.Query(`tag CONTAINS "prod"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d, want 2 (web-1 + db-1)", len(got))
	}
}

func TestQuery_BoolAttr(t *testing.T) {
	g := sampleGraph()
	got, err := g.Query(`type = "digitalocean.droplet" AND backups = true`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d, want 2 (backups-enabled droplets)", len(got))
	}
}

func TestQuery_IntAttr(t *testing.T) {
	g := sampleGraph()
	got, err := g.Query(`image_age_days = 400`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "db-1" {
		t.Errorf("got %+v, want db-1 only", names(got))
	}
}

func TestQuery_NotExpr(t *testing.T) {
	g := sampleGraph()
	got, err := g.Query(`type = "digitalocean.droplet" AND NOT region = "nyc1"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d, want 2 (db-1, staging)", len(got))
	}
}

func TestQuery_GroupedOr(t *testing.T) {
	g := sampleGraph()
	got, err := g.Query(`type = "digitalocean.droplet" AND (region = "nyc1" OR region = "nyc3")`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d, want 2 (web-1 + db-1)", len(got))
	}
}

func TestQuery_NotEquals(t *testing.T) {
	g := sampleGraph()
	got, err := g.Query(`type = "digitalocean.droplet" AND name != "staging"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d, want 2 (not staging)", len(got))
	}
}

func TestQuery_ParseErrors(t *testing.T) {
	g := sampleGraph()
	cases := []string{
		`type =`,         // missing value
		`type "x"`,       // missing operator
		`type = "x" AND`, // dangling AND
		`(type = "x"`,    // unclosed paren
		`type FOO "x"`,   // unknown operator
		``,               // empty
	}
	for _, c := range cases {
		_, err := g.Query(c)
		if err == nil {
			t.Errorf("expected error for %q, got nil", c)
		}
	}
}

func TestQuery_UnknownAttrYieldsZero(t *testing.T) {
	// Resources that lack the attribute simply don't match.
	g := sampleGraph()
	got, err := g.Query(`nonexistent_attr = "anything"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %d, want 0", len(got))
	}
}

func TestQuery_ProviderFilter(t *testing.T) {
	g := sampleGraph()
	got, err := g.Query(`provider = "linux"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Provider != "linux" {
		t.Errorf("got %+v, want linux host only", names(got))
	}
}

func TestQuery_Reachable(t *testing.T) {
	g := sampleGraph()
	got, err := g.Query(`reachable = true`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Provider != "linux" {
		t.Errorf("got %+v, want only reachable linux host", names(got))
	}
}

func TestTokenize_StringWithSpaces(t *testing.T) {
	toks := tokenize(`type = "digitalocean.droplet"`)
	if len(toks) != 3 || toks[0].kind != "ident" || toks[1].value != "=" || toks[2].kind != "string" {
		t.Errorf("unexpected tokens: %+v", toks)
	}
	if !strings.Contains(toks[2].value, "digitalocean") {
		t.Errorf("string value: %q", toks[2].value)
	}
}

func names(rs []Resource) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Name
	}
	return out
}
