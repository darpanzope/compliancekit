package compliancekit

// SearchType enumerates the kinds of entities the daemon's global
// search index can return. v1.19 phase 5 — added to the public surface
// (ADR-014 additive) so external embedders + the daemon's API share one
// result shape.
type SearchType string

const (
	SearchTypeFinding  SearchType = "finding"
	SearchTypeResource SearchType = "resource"
	SearchTypeScan     SearchType = "scan"
	SearchTypeUser     SearchType = "user"
	SearchTypeWaiver   SearchType = "waiver"
	SearchTypeSetting  SearchType = "setting"
	SearchTypeDoc      SearchType = "doc"
)

// SearchResult is one hit from the daemon's global search. Score is a
// relative rank (higher = better) combining fuzzy-match closeness with a
// recency weight; callers should treat it as an ordering hint, not an
// absolute measure. Href is the in-app path that opens the entity.
type SearchResult struct {
	Type     SearchType `json:"type"`
	ID       string     `json:"id"`
	Title    string     `json:"title"`
	Subtitle string     `json:"subtitle,omitempty"`
	Href     string     `json:"href"`
	Score    float64    `json:"score"`
}

// SearchResponse is the envelope the daemon's GET /api/v1/search returns:
// the page of results + an opaque cursor for the next page ("" when the
// result set is exhausted).
type SearchResponse struct {
	Query      string         `json:"query"`
	Results    []SearchResult `json:"results"`
	NextCursor string         `json:"next_cursor,omitempty"`
}
