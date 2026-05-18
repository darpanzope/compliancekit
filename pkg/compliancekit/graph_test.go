package compliancekit

import "testing"

func TestResourceGraph_AddAndByID(t *testing.T) {
	g := NewResourceGraph()
	g.Add(Resource{ID: "a", Type: "x"})
	g.Add(Resource{ID: "b", Type: "x"})

	got, ok := g.ByID("a")
	if !ok {
		t.Fatal("ByID(a) not found")
	}
	if got.ID != "a" {
		t.Errorf("ByID(a).ID = %q, want a", got.ID)
	}

	if _, ok := g.ByID("nope"); ok {
		t.Error("ByID(nope) should return false")
	}

	if g.Count() != 2 {
		t.Errorf("Count() = %d, want 2", g.Count())
	}
}

func TestResourceGraph_ByType_OrdersByInsertion(t *testing.T) {
	g := NewResourceGraph()
	g.Add(Resource{ID: "a", Type: "x"})
	g.Add(Resource{ID: "b", Type: "y"})
	g.Add(Resource{ID: "c", Type: "x"})

	xs := g.ByType("x")
	if len(xs) != 2 {
		t.Fatalf("ByType(x) returned %d, want 2", len(xs))
	}
	if xs[0].ID != "a" || xs[1].ID != "c" {
		t.Errorf("ByType(x) order = [%s,%s], want [a,c]", xs[0].ID, xs[1].ID)
	}

	if got := g.ByType("missing"); len(got) != 0 {
		t.Errorf("ByType(missing) returned %d, want 0", len(got))
	}
}

func TestResourceGraph_Related(t *testing.T) {
	g := NewResourceGraph()
	droplet := Resource{
		ID:        "do.droplet.1",
		Type:      "digitalocean.droplet",
		Relations: map[string][]string{"firewall": {"do.fw.1", "do.fw.2"}},
	}
	g.Add(droplet)
	g.Add(Resource{ID: "do.fw.1", Type: "digitalocean.firewall"})
	g.Add(Resource{ID: "do.fw.2", Type: "digitalocean.firewall"})

	related := g.Related(droplet, "firewall")
	if len(related) != 2 {
		t.Fatalf("Related(droplet, firewall) returned %d, want 2", len(related))
	}
	if related[0].ID != "do.fw.1" || related[1].ID != "do.fw.2" {
		t.Errorf("Related order = [%s,%s], want [do.fw.1,do.fw.2]", related[0].ID, related[1].ID)
	}

	if got := g.Related(droplet, "missing"); len(got) != 0 {
		t.Errorf("Related(droplet, missing) returned %d, want 0", len(got))
	}
}

func TestResourceGraph_AddReplacesByID(t *testing.T) {
	g := NewResourceGraph()
	g.Add(Resource{ID: "a", Type: "x", Name: "first"})
	g.Add(Resource{ID: "a", Type: "x", Name: "second"})

	got, _ := g.ByID("a")
	if got.Name != "second" {
		t.Errorf("after replace, Name = %q, want second", got.Name)
	}
	if g.Count() != 1 {
		t.Errorf("Count() = %d, want 1 after replace", g.Count())
	}
}

func TestResourceGraph_Related_IgnoresUnknownIDs(t *testing.T) {
	// Stale edges (pointing at resources not in the graph) must be silently
	// skipped rather than panicking. This matters at v0.6+ when state files
	// may reference a resource that has since been deleted.
	g := NewResourceGraph()
	droplet := Resource{
		ID:        "do.droplet.1",
		Type:      "digitalocean.droplet",
		Relations: map[string][]string{"firewall": {"missing-id"}},
	}
	g.Add(droplet)

	got := g.Related(droplet, "firewall")
	if len(got) != 0 {
		t.Errorf("Related with unknown edge target returned %d, want 0", len(got))
	}
}

func TestResource_AttrHelpers(t *testing.T) {
	r := Resource{
		Attributes: map[string]any{
			"acl":        "public-read",
			"size_bytes": float64(1024),
			"encrypted":  true,
		},
	}

	if got := r.Attr("acl"); got != "public-read" {
		t.Errorf(`Attr("acl") = %q, want "public-read"`, got)
	}
	if got := r.Attr("missing"); got != "" {
		t.Errorf(`Attr("missing") = %q, want ""`, got)
	}
	if got := r.AttrInt("size_bytes"); got != 1024 {
		t.Errorf(`AttrInt("size_bytes") = %d, want 1024`, got)
	}
	if got := r.AttrInt("missing"); got != 0 {
		t.Errorf(`AttrInt("missing") = %d, want 0`, got)
	}
	if got := r.AttrBool("encrypted"); !got {
		t.Errorf(`AttrBool("encrypted") = false, want true`)
	}
	if got := r.AttrBool("missing"); got {
		t.Errorf(`AttrBool("missing") = true, want false`)
	}
}

func TestResource_HasTag(t *testing.T) {
	r := Resource{Tags: []string{"prod", "web"}}
	if !r.HasTag("prod") {
		t.Error(`HasTag("prod") = false, want true`)
	}
	if r.HasTag("missing") {
		t.Error(`HasTag("missing") = true, want false`)
	}
}

func TestResource_Ref(t *testing.T) {
	r := Resource{
		ID:       "do.droplet.1",
		Type:     "digitalocean.droplet",
		Name:     "web-01",
		Provider: "digitalocean",
		Region:   "nyc3", // intentionally omitted from Ref
	}
	ref := r.Ref()
	if ref.ID != r.ID || ref.Type != r.Type || ref.Name != r.Name || ref.Provider != r.Provider {
		t.Errorf("Ref() = %+v, want lightweight copy of identity fields", ref)
	}
}
