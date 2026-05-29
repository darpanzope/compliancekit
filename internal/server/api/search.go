package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// search handles GET /api/v1/search?q=&types=&limit=&cursor=. Fuzzy-
// ranks the v1.19 global index + returns one cursor-paginated page.
// Requires findings:read (the broadest read scope a search caller
// already holds). v1.19 phase 5.
func (a *API) search(w http.ResponseWriter, r *http.Request) {
	if a.searchIdx == nil {
		http.Error(w, "search index unavailable", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	var types []compliancekit.SearchType
	if raw := strings.TrimSpace(q.Get("types")); raw != "" {
		for _, t := range strings.Split(raw, ",") {
			if t = strings.TrimSpace(t); t != "" {
				types = append(types, compliancekit.SearchType(t))
			}
		}
	}
	limit := 0
	if v := q.Get("limit"); v != "" {
		limit, _ = strconv.Atoi(v)
	}
	resp := a.searchIdx.Search(q.Get("q"), types, limit, q.Get("cursor"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

// searchScope is the scope the /search route gates on. Split out so the
// Mount wiring reads cleanly.
const searchScope = auth.ScopeFindingsRead
