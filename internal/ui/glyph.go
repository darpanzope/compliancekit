package ui

// Glyphs are the single source of truth for the small unicode
// characters that prefix severity-/status-colored rows. Colored +
// shaped together they stay grep-able by color-blind readers and
// scriptable pipelines that pre-process the output.
//
// ASCII fallbacks are returned by [Styler.Glyph] when color /
// unicode is disabled (NO_COLOR, non-TTY, --no-color). The mapping
// keeps the column width stable across both modes.
const (
	glyphPass    = "✓" // ascii: " ok "
	glyphFail    = "✗" // ascii: "FAIL"
	glyphSkip    = "–" // ascii: "skip"
	glyphError   = "⚠" // ascii: "ERR "
	glyphInfo    = "·" // ascii: " .. "
	glyphBullet  = "•" // ascii: " *  "
	glyphArrow   = "→" // ascii: "->"
	glyphAdded   = "+"
	glyphRemoved = "-"
	glyphExist   = "="
)
