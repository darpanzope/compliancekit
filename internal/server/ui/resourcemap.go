package ui

// v1.5 Phase 5 — Interactive resource map.
//
// /resources/map renders the daemon's resources + findings as a
// hierarchical SVG graph: provider → service → resource → findings.
// Each resource node carries a severity-tinted badge counting its
// open critical/high findings. Clicking a node filters /findings.
//
// Phase 5 ships vanilla SVG (no framework dep per ADR-015) — the
// graph is a top-down tree with viewBox-based pan + zoom. If
// pan/zoom/layout grows beyond a 1500 LoC budget, cytoscape.js
// (~150KB vanilla, no React) is the documented escape hatch per
// ROADMAP v1.5 row. v1.5.x can switch the renderer without changing
// the data shape this handler emits.

import (
	"context"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"
)

// resourceMapNode is one row in the hierarchy. Type discriminates
// the level (provider / service / resource); CountByLevel surfaces
// the severity histogram for resources.
type resourceMapNode struct {
	ID           string
	Type         string // "provider" / "service" / "resource"
	Label        string
	Provider     string
	Service      string
	ResourceType string
	Critical     int
	High         int
	Medium       int
	Low          int
	HasFindings  bool
}

// resourceMapView is the page payload.
type resourceMapView struct {
	View
	Providers []resourceMapProvider
	Total     int
}

type resourceMapProvider struct {
	resourceMapNode
	Services []resourceMapService
}

type resourceMapService struct {
	resourceMapNode
	Resources []resourceMapNode
}

// mountResourceMapRoutes registers Phase 5 endpoints.
func (u *UI) mountResourceMapRoutes(r chi.Router) {
	r.Get("/resources/map", u.resourceMapView)
}

func (u *UI) resourceMapView(w http.ResponseWriter, r *http.Request) {
	providers, total, err := u.loadResourceMap(r.Context())
	if err != nil {
		u.fail(w, "load map: "+err.Error())
		return
	}
	view := resourceMapView{
		View:      u.viewFor(r, "Resource map", "findings", View{}),
		Providers: providers,
		Total:     total,
	}
	u.render(w, "resource_map.html", view)
}

// loadResourceMap walks the findings table once, building the
// provider → service → resource tree along with per-node severity
// counts. Returns the tree + total resource count for the page
// header.
func (u *UI) loadResourceMap(ctx context.Context) ([]resourceMapProvider, int, error) {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT provider, COALESCE(resource_type,''), resource_id, resource_name, severity
		 FROM findings WHERE status = 'fail'`)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()

	type resKey struct{ provider, service, id string }
	resAgg := map[resKey]*resourceMapNode{}
	svcKeys := map[string]map[string]struct{}{} // provider → set of services
	provSet := map[string]struct{}{}
	for rows.Next() {
		var provider, resourceType, resourceID, resourceName, severity string
		if err := rows.Scan(&provider, &resourceType, &resourceID, &resourceName, &severity); err != nil {
			return nil, 0, err
		}
		service := resourceType
		k := resKey{provider, service, resourceID}
		node, ok := resAgg[k]
		if !ok {
			node = &resourceMapNode{
				ID:           resourceID,
				Type:         "resource",
				Label:        resourceName,
				Provider:     provider,
				Service:      service,
				ResourceType: resourceType,
			}
			resAgg[k] = node
		}
		node.HasFindings = true
		switch severity {
		case sevCritical:
			node.Critical++
		case sevHigh:
			node.High++
		case sevMedium:
			node.Medium++
		case sevLow:
			node.Low++
		}

		provSet[provider] = struct{}{}
		if _, ok := svcKeys[provider]; !ok {
			svcKeys[provider] = map[string]struct{}{}
		}
		svcKeys[provider][service] = struct{}{}
	}

	// Assemble the tree.
	out := []resourceMapProvider{}
	provNames := keysSorted(provSet)
	for _, prov := range provNames {
		p := resourceMapProvider{
			resourceMapNode: resourceMapNode{
				ID: prov, Type: "provider", Label: prov, Provider: prov,
			},
		}
		svcNames := keysSorted(svcKeys[prov])
		for _, svc := range svcNames {
			s := resourceMapService{
				resourceMapNode: resourceMapNode{
					ID: prov + "/" + svc, Type: "service", Label: svc,
					Provider: prov, Service: svc,
				},
			}
			for k, n := range resAgg {
				if k.provider != prov || k.service != svc {
					continue
				}
				s.Resources = append(s.Resources, *n)
				// Roll up severity counts into the service + provider.
				p.Critical += n.Critical
				p.High += n.High
				p.Medium += n.Medium
				p.Low += n.Low
				s.Critical += n.Critical
				s.High += n.High
				s.Medium += n.Medium
				s.Low += n.Low
			}
			sort.Slice(s.Resources, func(i, j int) bool { return s.Resources[i].Label < s.Resources[j].Label })
			p.Services = append(p.Services, s)
		}
		out = append(out, p)
	}

	return out, len(resAgg), nil
}

// keysSorted returns the sorted key set of any string-keyed map.
func keysSorted[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
