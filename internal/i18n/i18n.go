// Package i18n is the v1.10+ runtime translation surface. Operators
// configure their preferred language under /settings/account; the
// HTTP Accept-Language header is the fallback for unauthenticated
// pages (/login + chrome-less surfaces).
//
// Translation catalogs live at internal/i18n/locales/<lang>/messages.json
// and are embedded into the binary via go:embed. Adding a new locale
// is a four-file change: drop a messages.json + a smoke test +
// register the BCP-47 tag in availableTags + the v1.10 phase 9 help
// tooltip translation (when shipped).
//
// The API is deliberately tiny: T(ctx, "key", optionalArgs) — that's
// the only call surface every handler + template will use.
package i18n

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

//go:embed locales/*/messages.json
var catalogsFS embed.FS

// Available locales. Adding one means: drop the catalog file,
// extend this slice, regenerate the api.txt smoke test.
//
//   - en: English (United States) — the source-of-truth catalog
//   - es: Spanish
//   - fr: French
//   - de: German
//   - ja: Japanese
//   - pt-BR: Portuguese (Brazil)
var availableTags = []language.Tag{
	language.English,
	language.Spanish,
	language.French,
	language.German,
	language.Japanese,
	language.BrazilianPortuguese,
}

// Bundle is the package-global i18n bundle, lazily initialized by
// Default(). Tests call NewBundle directly to construct an
// isolated bundle from a custom catalog set.
type Bundle struct {
	inner   *i18n.Bundle
	matcher language.Matcher
	tags    []language.Tag
}

var (
	defaultOnce sync.Once
	defaultB    *Bundle
)

// Default returns the package-global bundle, constructing it on
// first call. Loads every embedded catalog under locales/. Any
// catalog that fails to parse panics — translations are load-
// bearing and we'd rather fail at daemon boot than silently fall
// back to English.
func Default() *Bundle {
	defaultOnce.Do(func() {
		b, err := NewBundle(catalogsFS)
		if err != nil {
			panic("i18n: load catalogs: " + err.Error())
		}
		defaultB = b
	})
	return defaultB
}

// NewBundle constructs a Bundle from the given filesystem. The FS
// must follow the locales/<lang>/messages.json layout.
func NewBundle(fsys embed.FS) (*Bundle, error) {
	b := i18n.NewBundle(language.English)
	b.RegisterUnmarshalFunc("json", json.Unmarshal)
	for _, tag := range availableTags {
		path := "locales/" + tag.String() + "/messages.json"
		body, err := fsys.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		// go-i18n derives the language tag from the path basename, so
		// we pass "active.<tag>.json" rather than the read-from path.
		// Without this the parser registers messages under the
		// default English locale regardless of which catalog we
		// loaded — silent fallback that's hard to debug at runtime.
		if _, err := b.ParseMessageFileBytes(body, "active."+tag.String()+".json"); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	return &Bundle{
		inner:   b,
		matcher: language.NewMatcher(availableTags),
		tags:    availableTags,
	}, nil
}

// Languages returns every available locale. Used by the
// /settings/account locale picker.
func (b *Bundle) Languages() []language.Tag {
	out := make([]language.Tag, len(b.tags))
	copy(out, b.tags)
	return out
}

// Localize resolves a translation key against a language tag. Args
// is the optional template-data bag for messages with substitutions.
// Returns the messageID itself when no translation matches — that
// way a missing key is visible in the UI ("invariant.unknown_key")
// instead of silently showing an empty string.
func (b *Bundle) Localize(tag language.Tag, messageID string, args ...map[string]any) string {
	loc := i18n.NewLocalizer(b.inner, tag.String(), "en")
	cfg := &i18n.LocalizeConfig{MessageID: messageID}
	if len(args) > 0 {
		cfg.TemplateData = args[0]
	}
	msg, err := loc.Localize(cfg)
	if err != nil || msg == "" {
		return messageID
	}
	return msg
}

// MatchAcceptLanguage parses the HTTP Accept-Language header against
// the available locales + returns the best match. Empty / missing
// header falls back to English.
func (b *Bundle) MatchAcceptLanguage(header string) language.Tag {
	if header == "" {
		return language.English
	}
	accepted, _, err := language.ParseAcceptLanguage(header)
	if err != nil {
		return language.English
	}
	tag, _, _ := b.matcher.Match(accepted...)
	return tag
}

// LocaleFromRequest is the canonical "what language should this
// request see" helper. Operators can pin via the `ck-locale` cookie
// (set by /settings/account); the HTTP Accept-Language header is
// the fallback.
func (b *Bundle) LocaleFromRequest(r *http.Request) language.Tag {
	if c, err := r.Cookie("ck-locale"); err == nil && c.Value != "" {
		if tag, err := language.Parse(c.Value); err == nil {
			// Match against the available set so an unsupported
			// cookie value falls back gracefully.
			matched, _, _ := b.matcher.Match(tag)
			return matched
		}
	}
	return b.MatchAcceptLanguage(r.Header.Get("Accept-Language"))
}

// ─── Context helpers ───────────────────────────────────────────────────

type contextKey int

const localeKey contextKey = 0

// ContextWithLocale stores a language tag on the context so deep
// callers (template funcs, internal helpers) can resolve translations
// without re-parsing the request.
func ContextWithLocale(ctx context.Context, tag language.Tag) context.Context {
	return context.WithValue(ctx, localeKey, tag)
}

// LocaleFromContext returns the stored locale or English when none
// was set (e.g. CLI / CLI-only embedders).
func LocaleFromContext(ctx context.Context) language.Tag {
	if v, ok := ctx.Value(localeKey).(language.Tag); ok {
		return v
	}
	return language.English
}

// T is the canonical translate-by-key helper. Reads the locale from
// ctx + delegates to Default().Localize.
func T(ctx context.Context, messageID string, args ...map[string]any) string {
	return Default().Localize(LocaleFromContext(ctx), messageID, args...)
}

// IsAvailable reports whether a locale tag is in the supported set.
// Used by /settings/account when validating the picker submit.
func IsAvailable(tag language.Tag) bool {
	for _, t := range availableTags {
		if t == tag {
			return true
		}
	}
	return false
}

// LanguageNames returns a stable display map of tag → English name
// for picker rendering. Native-language names (Español / Français /
// 日本語) come in a v1.10.x polish pass.
func LanguageNames() map[string]string {
	return map[string]string{
		"en":    "English",
		"es":    "Spanish",
		"fr":    "French",
		"de":    "German",
		"ja":    "Japanese",
		"pt-BR": "Portuguese (Brazil)",
	}
}

// TagString returns the BCP-47 base+region form, stripping the
// extension subtags (-u-rg-*, -x-*) that language.Matcher tacks
// onto matched results. Operators see "fr" / "pt-BR" / "ja" — not
// "fr-u-rg-frzzzz". Used in cookies + URL fragments + debug logs.
func TagString(t language.Tag) string {
	base, _ := t.Base()
	region, _ := t.Region()
	s := base.String()
	// Keep the region tag only when it's part of the BCP-47 name —
	// pt-BR is meaningful (vs pt-PT); fr-FR vs fr-CA we don't ship,
	// so fold to the base. Listed tags drive the keep decision.
	if region.String() != "" && region.String() != "ZZ" {
		full := base.String() + "-" + region.String()
		for _, supported := range availableTags {
			if supported.String() == full {
				return full
			}
		}
	}
	return s
}
