package compliancekit

// ResourceGraph is the in-memory store of collected Resources.
//
// Collectors call Add to register resources; Evaluators read them via
// ByType / ByID / Related. The graph is built once per scan and is
// effectively immutable from the moment evaluation begins.
//
// ResourceGraph is NOT safe for concurrent writes -- collectors finish
// before evaluators start, and the engine enforces this ordering.
// Concurrent reads after the build phase are safe (maps are read-only
// at that point).
//
// At v1.1 (`serve` mode), the in-memory graph remains the working set
// while a separate StateStore persists snapshots between scans.
type ResourceGraph struct {
	byID   map[string]Resource
	byType map[string][]string // type -> ordered list of resource IDs (insertion order)
}

// NewResourceGraph returns an empty graph ready to be populated.
func NewResourceGraph() *ResourceGraph {
	return &ResourceGraph{
		byID:   make(map[string]Resource),
		byType: make(map[string][]string),
	}
}

// Add inserts a resource. If a resource with the same ID already exists,
// it is replaced; the type index is not duplicated.
func (g *ResourceGraph) Add(r Resource) {
	if _, exists := g.byID[r.ID]; !exists {
		g.byType[r.Type] = append(g.byType[r.Type], r.ID)
	}
	g.byID[r.ID] = r
}

// ByID returns the resource with the given ID and whether it exists.
func (g *ResourceGraph) ByID(id string) (Resource, bool) {
	r, ok := g.byID[id]
	return r, ok
}

// ByType returns all resources of the given type, in insertion order.
// Stable ordering matters because findings are produced in graph order
// and we want diffs across runs to be readable.
func (g *ResourceGraph) ByType(t string) []Resource {
	ids := g.byType[t]
	out := make([]Resource, 0, len(ids))
	for _, id := range ids {
		out = append(out, g.byID[id])
	}
	return out
}

// Related returns resources reachable from r along the named edge.
// A missing edge or an edge pointing at unknown IDs returns nil rather
// than an error -- callers typically just range over the result.
func (g *ResourceGraph) Related(r Resource, edge string) []Resource {
	ids, ok := r.Relations[edge]
	if !ok {
		return nil
	}
	out := make([]Resource, 0, len(ids))
	for _, id := range ids {
		if rel, ok := g.byID[id]; ok {
			out = append(out, rel)
		}
	}
	return out
}

// All returns every resource in the graph, ordered first by type
// (in insertion order of types) and then by insertion order within each type.
func (g *ResourceGraph) All() []Resource {
	out := make([]Resource, 0, len(g.byID))
	for _, ids := range g.byType {
		for _, id := range ids {
			out = append(out, g.byID[id])
		}
	}
	return out
}

// Count returns the total number of resources in the graph.
func (g *ResourceGraph) Count() int {
	return len(g.byID)
}
