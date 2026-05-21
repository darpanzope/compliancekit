package api

import (
	"net/http/httptest"
	"testing"
)

// TestCursor_RoundTrip confirms encode/decode is symmetric for the
// happy path + first-page (zero cursor) handling.
func TestCursor_RoundTrip(t *testing.T) {
	c := Cursor{SortKey: "2026-05-21T08:00:00Z", ID: "scan-abc-123"}
	tok := c.Encode()
	if tok == "" {
		t.Fatal("Encode of non-zero cursor returned empty token")
	}
	back := decodeCursor(tok)
	if back != c {
		t.Errorf("round trip: got %+v, want %+v", back, c)
	}

	if !(Cursor{}).IsZero() {
		t.Error("zero cursor IsZero should be true")
	}
	if (Cursor{ID: "x"}).IsZero() {
		t.Error("Cursor with ID set should not be IsZero")
	}
	if (Cursor{}).Encode() != "" {
		t.Error("zero cursor encodes to empty string")
	}
}

// TestCursor_DecodeJunk returns zero cursor (rather than failing)
// so corrupted bookmarks don't soft-lock the UI.
func TestCursor_DecodeJunk(t *testing.T) {
	for _, junk := range []string{"!!!notbase64", "Zm9v", "{}"} {
		c := decodeCursor(junk)
		if c.SortKey != "" || c.ID != "" {
			t.Errorf("junk %q decoded to %+v; want zero", junk, c)
		}
	}
}

// TestParseCursorMode disambiguates between legacy ?page= callers and
// cursor-mode callers per the v1.11 phase 0 contract.
func TestParseCursorMode(t *testing.T) {
	tok := Cursor{SortKey: "t", ID: "i"}.Encode()
	cases := []struct {
		name      string
		url       string
		wantCur   Cursor
		wantPer   int
		wantUseCu bool
	}{
		{"empty", "/?per_page=20", Cursor{}, 20, true},
		{"explicit_cursor", "/?cursor=" + tok, Cursor{SortKey: "t", ID: "i"}, 50, true},
		{"legacy_page", "/?page=1&per_page=10", Cursor{}, 10, false},
		{"per_page_cap", "/?per_page=9999", Cursor{}, 500, true},
		{"per_page_min", "/?per_page=0", Cursor{}, 50, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", c.url, nil)
			cur, per, useCu := parseCursorMode(r)
			if cur != c.wantCur {
				t.Errorf("cursor = %+v, want %+v", cur, c.wantCur)
			}
			if per != c.wantPer {
				t.Errorf("per = %d, want %d", per, c.wantPer)
			}
			if useCu != c.wantUseCu {
				t.Errorf("useCursor = %v, want %v", useCu, c.wantUseCu)
			}
		})
	}
}
