package ui

// v1.5 Phase 6 — Resource inventory table.
//
// /resources is the flat-table alternative to /resources/map. Same
// underlying aggregation, different presentation: one row per
// resource with provider / type / open-findings count / max-severity
// columns; sortable + filterable; click → /findings?q=name.
//
// Backs the same use case as the map for operators who prefer dense
// tables over visual hierarchies.

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
)

// resourceInventoryRow is the per-row payload.
type resourceInventoryRow struct {
	ResourceID   string
	ResourceName string
	ResourceType string
	Provider     string
	Total        int
	Critical     int
	High         int
	Medium       int
	Low          int
	MaxSeverity  string // for the sort + badge — highest-severity finding on this resource
}

type resourcesView struct {
	View
	Items []resourceInventoryRow
	Total int
	Query string
	Sort  string
}

func (u *UI) mountResourcesRoutes(r chi.Router) {
	r.Get("/resources", u.resourcesList)
}

func (u *UI) resourcesList(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	sortKey := r.URL.Query().Get("sort")
	if sortKey == "" {
		sortKey = "severity"
	}
	items, err := u.loadResourceInventory(r.Context())
	if err != nil {
		u.fail(w, "load resources: "+err.Error())
		return
	}
	if query != "" {
		filtered := items[:0]
		needle := strings.ToLower(query)
		for _, r := range items {
			hay := strings.ToLower(r.ResourceName + " " + r.ResourceID + " " + r.ResourceType + " " + r.Provider)
			if strings.Contains(hay, needle) {
				filtered = append(filtered, r)
			}
		}
		items = filtered
	}
	sortResourceInventory(items, sortKey)

	view := resourcesView{
		View:  u.viewFor(r, "Resources", "findings", View{}),
		Items: items,
		Total: len(items),
		Query: query,
		Sort:  sortKey,
	}
	u.render(w, "resources.html", view)
}

// loadResourceInventory aggregates findings by resource — same source
// as loadResourceMap but flattened into rows.
func (u *UI) loadResourceInventory(ctx context.Context) ([]resourceInventoryRow, error) {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT provider, COALESCE(resource_type,''), resource_id, resource_name, severity
		 FROM findings WHERE status = 'fail'`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	type k struct{ provider, id string }
	agg := map[k]*resourceInventoryRow{}
	for rows.Next() {
		var p, rt, rid, rn, sev string
		if err := rows.Scan(&p, &rt, &rid, &rn, &sev); err != nil {
			return nil, err
		}
		key := k{p, rid}
		row, ok := agg[key]
		if !ok {
			row = &resourceInventoryRow{
				ResourceID: rid, ResourceName: rn, ResourceType: rt, Provider: p,
			}
			agg[key] = row
		}
		row.Total++
		switch sev {
		case sevCritical:
			row.Critical++
		case sevHigh:
			row.High++
		case sevMedium:
			row.Medium++
		case sevLow:
			row.Low++
		}
		row.MaxSeverity = maxSeverity(row.MaxSeverity, sev)
	}

	out := make([]resourceInventoryRow, 0, len(agg))
	for _, v := range agg {
		out = append(out, *v)
	}
	return out, rows.Err()
}

// maxSeverity returns whichever of (a, b) has higher rank.
func maxSeverity(a, b string) string {
	if severityRank(b) > severityRank(a) {
		return b
	}
	return a
}

func severityRank(s string) int {
	switch s {
	case sevCritical:
		return 5
	case sevHigh:
		return 4
	case sevMedium:
		return 3
	case sevLow:
		return 2
	case sevInfo:
		return 1
	}
	return 0
}

// sortResourceInventory sorts in-place by the picked key. Default
// "severity" puts the most-impacted resources at the top.
func sortResourceInventory(items []resourceInventoryRow, key string) {
	switch key {
	case "name":
		sort.SliceStable(items, func(i, j int) bool { return items[i].ResourceName < items[j].ResourceName })
	case "provider":
		sort.SliceStable(items, func(i, j int) bool { return items[i].Provider < items[j].Provider })
	case "type":
		sort.SliceStable(items, func(i, j int) bool { return items[i].ResourceType < items[j].ResourceType })
	case "findings":
		sort.SliceStable(items, func(i, j int) bool { return items[i].Total > items[j].Total })
	default: // "severity"
		sort.SliceStable(items, func(i, j int) bool {
			ri := severityRank(items[i].MaxSeverity)
			rj := severityRank(items[j].MaxSeverity)
			if ri != rj {
				return ri > rj
			}
			return items[i].Total > items[j].Total
		})
	}
}
