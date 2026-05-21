package api

// v1.11 phase 0 — Cursor-based pagination.
//
// Replaces OFFSET/LIMIT across every list endpoint. Cursor encodes
// the `(sort_key, id)` tuple of the last row of the previous page;
// the next page selects rows lexicographically AFTER (sort_key DESC
// + id DESC ordering) so the SQL stays index-friendly + scales
// linearly to 100k+ rows.
//
// The cursor format is opaque-by-design: base64-encoded JSON. Not
// part of the v1.x SemVer contract — we reserve the right to change
// the encoding in any minor release. Callers MUST treat it as a
// black-box string + only re-send what they got from a previous
// response.
//
// Backwards compatibility: page/per_page still works. Cursor and
// page/per_page coexist for one minor release (v1.11 + v1.11.x);
// `?page=` overrides `?cursor=` when both present so older callers
// don't break unexpectedly.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
)

// Cursor is the opaque pagination token. SortKey + ID together form
// the (last-row-of-previous-page) tuple; the next query selects
// rows strictly after this pair under the documented sort order.
type Cursor struct {
	SortKey string `json:"k"` // RFC3339 timestamp or other monotonic key
	ID      string `json:"i"`
}

// IsZero reports whether the cursor is empty — first-page request.
func (c Cursor) IsZero() bool { return c.SortKey == "" && c.ID == "" }

// Encode returns the opaque base64 token. Empty cursor returns "".
func (c Cursor) Encode() string {
	if c.IsZero() {
		return ""
	}
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeCursor parses an opaque token. Invalid input returns a zero
// Cursor — the caller treats that as a first-page request rather
// than failing, so a corrupted bookmark doesn't soft-lock the UI.
func decodeCursor(tok string) Cursor {
	if tok == "" {
		return Cursor{}
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return Cursor{}
	}
	var c Cursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return Cursor{}
	}
	return c
}

// pageCursor mirrors page[T] but for the cursor-based response.
// NextCursor is the opaque token the client passes back as
// `?cursor=...` to fetch the next page; empty means "no more rows".
type pageCursor[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	PerPage    int    `json:"per_page"`
}

// parseCursorMode reads ?per_page=M&cursor=X from the request +
// returns (cursor, perPage, useCursor). useCursor is true when the
// caller sent a cursor or omitted ?page=; false when they sent
// ?page= (the legacy path). Per-page caps at 500 like the v1.0
// parsePage helper.
func parseCursorMode(r *http.Request) (Cursor, int, bool) {
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 {
		perPage = 50
	}
	if perPage > 500 {
		perPage = 500
	}
	// Cursor path: explicit ?cursor= or absent ?page= (default to
	// cursor mode for clients that just want page 1).
	pageParam := r.URL.Query().Get("page")
	cursorParam := r.URL.Query().Get("cursor")
	if pageParam != "" {
		// Caller is using the legacy OFFSET path.
		return Cursor{}, perPage, false
	}
	return decodeCursor(cursorParam), perPage, true
}
