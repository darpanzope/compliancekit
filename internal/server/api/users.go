package api

// v1.8 phase 4 — /api/v1/users/search powers the @mention
// autocomplete in the comments composer. Returns a short list of
// users whose email or display_name fuzzy-matches q. Capped at 10
// rows — the autocomplete UI shows at most that many in the dropdown.

import (
	"context"
	"net/http"
	"strings"

	"github.com/darpanzope/compliancekit/internal/server/auth"
)

// userSearchRow is the dropdown's per-row payload.
type userSearchRow struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Label string `json:"label"`
}

func (a *API) searchUsers(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	rows, err := loadUserSearch(r.Context(), a.users, q)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "load users: "+err.Error())
		return
	}
	respondJSON(w, r, http.StatusOK, struct {
		Items []userSearchRow `json:"items"`
	}{Items: rows})
}

// loadUserSearch is split out so tests can exercise the matching
// logic without standing up the HTTP layer.
func loadUserSearch(ctx context.Context, users *auth.Users, q string) ([]userSearchRow, error) {
	all, err := users.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]userSearchRow, 0, 10)
	needle := strings.ToLower(q)
	for _, u := range all {
		if needle != "" {
			haystack := strings.ToLower(u.Email + " " + u.DisplayName)
			if !strings.Contains(haystack, needle) {
				continue
			}
		}
		label := u.DisplayName
		if label == "" {
			label = u.Email
		}
		out = append(out, userSearchRow{ID: u.ID, Email: u.Email, Label: label})
		if len(out) == 10 {
			break
		}
	}
	return out, nil
}
