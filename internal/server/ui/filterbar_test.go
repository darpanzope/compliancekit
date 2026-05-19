package ui

import "testing"

// TestActiveFilterCount sums populated dimensions only.
func TestActiveFilterCount(t *testing.T) {
	cases := []struct {
		name string
		in   findingFilters
		want int
	}{
		{"empty", findingFilters{}, 0},
		{"severity only", findingFilters{Severities: []string{"critical"}}, 1},
		{"multi-dim", findingFilters{
			Severities: []string{"critical", "high"},
			Providers:  []string{"aws"},
			NameQuery:  "foo",
			SinceDays:  7,
		}, 4},
		{"empty slice still counts as zero", findingFilters{Severities: []string{}}, 0},
		{"per-page never counted", findingFilters{PerPage: 50}, 0},
		{"cursor never counted", findingFilters{Cursor: "abc"}, 0},
	}
	for _, c := range cases {
		if got := activeFilterCount(c.in); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}
