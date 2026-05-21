package i18n

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/text/language"
)

// TestDefault_LoadsAllLocales boots the package-global bundle +
// confirms every available locale has at least the nav.scans key.
// Missing keys would fail the bundle parse at boot per the
// "panic on bad catalog" invariant.
func TestDefault_LoadsAllLocales(t *testing.T) {
	b := Default()
	if got := len(b.Languages()); got != 6 {
		t.Errorf("Languages = %d, want 6 (en/es/fr/de/ja/pt-BR)", got)
	}
	for _, tag := range b.Languages() {
		// nav.scans is in the English catalog; locales without a
		// translation fall back to the messageID itself ("nav.scans"),
		// not the English value — that's correct per Localize's
		// docstring. So we just confirm the call doesn't panic.
		got := b.Localize(tag, "nav.scans")
		if got == "" {
			t.Errorf("Localize(%s, nav.scans) = empty", tag)
		}
	}
}

// TestLocalize_EnglishHit returns the source value for a known key.
func TestLocalize_EnglishHit(t *testing.T) {
	got := Default().Localize(language.English, "nav.scans")
	if got != "Scans" {
		t.Errorf("Localize(en, nav.scans) = %q, want Scans", got)
	}
}

// TestLocalize_UnknownKey returns the messageID itself so missing
// strings are visible in the UI rather than silently empty.
func TestLocalize_UnknownKey(t *testing.T) {
	got := Default().Localize(language.English, "no.such.key")
	if got != "no.such.key" {
		t.Errorf("unknown key = %q, want passthrough", got)
	}
}

// TestMatchAcceptLanguage handles the documented header shapes:
// empty, English-only, mixed-quality, unsupported fallback.
func TestMatchAcceptLanguage(t *testing.T) {
	b := Default()
	cases := []struct {
		header string
		want   string
	}{
		{"", "en"},
		{"en-US,en;q=0.9", "en"},
		{"de-DE,de;q=0.9,en;q=0.6", "de"},
		{"ja,en-US;q=0.5", "ja"},
		{"zh-CN", "en"}, // unsupported → English
	}
	for _, c := range cases {
		got := TagString(b.MatchAcceptLanguage(c.header))
		if got != c.want {
			t.Errorf("Accept-Language=%q matched %q, want %q", c.header, got, c.want)
		}
	}
}

// TestLocaleFromRequest_CookieWins: a valid ck-locale cookie wins
// over the Accept-Language header.
func TestLocaleFromRequest_CookieWins(t *testing.T) {
	b := Default()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Language", "de-DE,de;q=0.9")
	r.AddCookie(&http.Cookie{Name: "ck-locale", Value: "ja"})
	if got := TagString(b.LocaleFromRequest(r)); got != "ja" {
		t.Errorf("cookie ja header de → got %q, want ja", got)
	}
}

// TestLocaleFromRequest_BadCookieFallsBack: a malformed cookie
// silently falls through to the header.
func TestLocaleFromRequest_BadCookieFallsBack(t *testing.T) {
	b := Default()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Language", "fr-FR")
	r.AddCookie(&http.Cookie{Name: "ck-locale", Value: "🌍"})
	if got := TagString(b.LocaleFromRequest(r)); got != "fr" {
		t.Errorf("bad cookie + fr header → %q, want fr", got)
	}
}

// TestLocaleCoverage verifies every non-English catalog covers the
// load-bearing nav + common + severity keys with a non-empty value
// (i.e. not falling back to the messageID). Stub catalogs would fail
// this gate, which is what we want — phase 8's job is to populate
// every locale before v1.10.0 ships.
func TestLocaleCoverage(t *testing.T) {
	b := Default()
	mustHave := []string{
		"nav.scans", "nav.findings", "nav.rules", "nav.settings",
		"common.save", "common.cancel", "common.delete",
		"severity.critical", "severity.high", "severity.low",
		"status.pass", "status.fail",
		"a11y.skip_to_main",
	}
	for _, tag := range b.Languages() {
		for _, key := range mustHave {
			got := b.Localize(tag, key)
			if got == key {
				t.Errorf("locale %s: key %q falls back (catalog gap)", tag, key)
			}
		}
	}
}

// TestT_ContextRoundtrip exercises the context helpers + canonical
// T() entry point.
func TestT_ContextRoundtrip(t *testing.T) {
	ctx := ContextWithLocale(context.Background(), language.English)
	if got := T(ctx, "common.cancel"); got != "Cancel" {
		t.Errorf("T(en, common.cancel) = %q, want Cancel", got)
	}
	// Nil-context safety: ensure background fallback is English.
	if got := T(context.Background(), "common.save"); got != "Save" {
		t.Errorf("T(bg, common.save) = %q, want Save (en fallback)", got)
	}
}
