package ui

import (
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Styler renders short strings with consistent color + glyph
// treatment across compliancekit subcommands. It is the only thing
// subcommands need to hold to render styled output; pass one
// constructed via [NewStyler] down to the renderer.
//
// A Styler with Color==false strips ANSI and substitutes ASCII
// fallback glyphs so its output is suitable for CI logs, file
// redirects, and `grep` pipelines. Width-stable: the column a
// glyph occupies is the same in both modes.
type Styler struct {
	// Color reports whether the receiver emits ANSI escapes.
	// Determined once at construction via [IsColorEnabled].
	Color bool

	// r is the underlying lipgloss renderer, configured with a forced
	// color profile so ANSI emission is driven by the Color flag,
	// not by lipgloss/termenv's environment auto-detection (which
	// disables color under `go test`, breaking snapshot tests of
	// the styled output).
	r *lipgloss.Renderer
}

// NewStyler returns a Styler whose Color flag matches the result of
// [IsColorEnabled] for w with the given --no-color flag. Pass the
// same w the caller will be writing styled output to.
func NewStyler(w io.Writer, forceOff bool) *Styler {
	color := IsColorEnabled(w, forceOff)
	return newStylerWithProfile(w, color)
}

// newStylerWithProfile constructs a Styler with an explicit color
// decision, used by NewStyler and by tests that need to assert
// ANSI emission under non-TTY conditions.
func newStylerWithProfile(w io.Writer, color bool) *Styler {
	r := lipgloss.NewRenderer(w)
	if color {
		// ANSI256 covers the AdaptiveColor pairs in palette.go on
		// every reasonable modern terminal without requiring true
		// color. Operators on locked-down ANSI-16 terminals can
		// set NO_COLOR.
		r.SetColorProfile(termenv.ANSI256)
	} else {
		r.SetColorProfile(termenv.Ascii)
	}
	return &Styler{Color: color, r: r}
}

// Severity renders the severity name padded for column alignment and
// colored per the palette. Unknown severities render in muted grey.
func (s *Styler) Severity(sev compliancekit.Severity) string {
	name := sev.String()
	pad := padRight(strings.ToUpper(name), 8)
	if !s.Color {
		return pad
	}
	return s.r.NewStyle().Foreground(severityColor(sev)).Bold(sev >= compliancekit.SeverityHigh).Render(pad)
}

// SeverityChip renders the severity as a compact uppercase chip
// (e.g. "[HIGH]") suitable for inline use in a finding row.
func (s *Styler) SeverityChip(sev compliancekit.Severity) string {
	chip := "[" + strings.ToUpper(sev.String()) + "]"
	if !s.Color {
		return chip
	}
	return s.r.NewStyle().Foreground(severityColor(sev)).Bold(sev >= compliancekit.SeverityHigh).Render(chip)
}

// InSeverity renders text in the color of sev without the chip
// brackets — useful for rendering numeric scores / counts in a
// band-appropriate color. No-op when Color is false.
func (s *Styler) InSeverity(text string, sev compliancekit.Severity) string {
	if !s.Color {
		return text
	}
	return s.r.NewStyle().Foreground(severityColor(sev)).Bold(sev >= compliancekit.SeverityHigh).Render(text)
}

// Status renders the status glyph + colored name. ASCII fallback
// substitutes the glyph and drops color when Color is false. Pad
// width is stable across modes so columns line up in both forms.
func (s *Styler) Status(st compliancekit.Status) string {
	g := s.Glyph(string(st))
	name := padRight(string(st), 5)
	if !s.Color {
		return g + " " + name
	}
	return s.r.NewStyle().Foreground(statusColor(st)).Render(g + " " + name)
}

// Glyph returns the unicode glyph for a known token (status name,
// "added", "removed", etc.) or the ASCII fallback when color /
// unicode is disabled.
func (s *Styler) Glyph(token string) string {
	if !s.Color {
		return asciiGlyph(token)
	}
	return unicodeGlyph(token)
}

// Muted dims structural text — frame characters, separator dashes,
// "(empty)" hints. No-op when Color is false.
func (s *Styler) Muted(text string) string {
	if !s.Color {
		return text
	}
	return s.r.NewStyle().Foreground(colorMuted).Render(text)
}

// Accent highlights the one thing the reader's eye should land on
// first — a command name in help text, a count of new findings.
func (s *Styler) Accent(text string) string {
	if !s.Color {
		return text
	}
	return s.r.NewStyle().Foreground(colorAccent).Bold(true).Render(text)
}

// Bold is plain bold without color. Used for section headers in
// `--help` output and the doctor pretty-printer.
func (s *Styler) Bold(text string) string {
	if !s.Color {
		return text
	}
	return s.r.NewStyle().Bold(true).Render(text)
}

// DiffKindAdded / Removed / Existing are the three valid kind values
// for DiffMark + the Glyph map. Exported so callers don't repeat the
// string literals (and goconst keeps its peace about the triple
// occurrence in DiffMark).
const (
	DiffKindAdded    = "added"
	DiffKindRemoved  = "removed"
	DiffKindExisting = "existing"
)

// DiffMark renders the leading +/-/= column of `compliancekit diff`
// with the new-green / resolved-grey / existing-muted treatment.
func (s *Styler) DiffMark(kind string) string {
	g := s.Glyph(kind)
	if !s.Color {
		return g
	}
	switch kind {
	case DiffKindAdded:
		return s.r.NewStyle().Foreground(colorAdded).Bold(true).Render(g)
	case DiffKindRemoved:
		return s.r.NewStyle().Foreground(colorRemoved).Strikethrough(true).Render(g)
	case DiffKindExisting:
		return s.r.NewStyle().Foreground(colorExisting).Render(g)
	}
	return g
}

// severityColor returns the palette color for a Severity, or the
// muted/unknown fallback when the value is outside the enum range.
func severityColor(sev compliancekit.Severity) lipgloss.TerminalColor {
	switch sev {
	case compliancekit.SeverityCritical:
		return colorCritical
	case compliancekit.SeverityHigh:
		return colorHigh
	case compliancekit.SeverityMedium:
		return colorMedium
	case compliancekit.SeverityLow:
		return colorLow
	case compliancekit.SeverityInfo:
		return colorInfo
	}
	return colorUnknown
}

// statusColor returns the palette color for a Status.
func statusColor(st compliancekit.Status) lipgloss.TerminalColor {
	switch st {
	case compliancekit.StatusPass:
		return colorPass
	case compliancekit.StatusFail:
		return colorFail
	case compliancekit.StatusSkip:
		return colorSkip
	case compliancekit.StatusError:
		return colorError
	}
	return colorUnknown
}

// unicodeGlyph maps a token to its unicode glyph. Width is intended
// to match asciiGlyph so columns line up across modes.
func unicodeGlyph(token string) string {
	switch token {
	case "pass":
		return glyphPass
	case "fail":
		return glyphFail
	case "skip":
		return glyphSkip
	case "error":
		return glyphError
	case "info":
		return glyphInfo
	case "bullet":
		return glyphBullet
	case "arrow":
		return glyphArrow
	case "added":
		return glyphAdded
	case "removed":
		return glyphRemoved
	case "existing":
		return glyphExist
	}
	return " "
}

// asciiGlyph maps a token to its plain-mode ASCII fallback. The
// width of each fallback matches the visual width of its unicode
// counterpart so a fixed-width column doesn't shift between modes.
func asciiGlyph(token string) string {
	switch token {
	case "pass":
		return "ok"
	case "fail":
		return "X"
	case "skip":
		return "-"
	case "error":
		return "!"
	case "info":
		return "."
	case "bullet":
		return "*"
	case "arrow":
		return "->"
	case "added":
		return "+"
	case "removed":
		return "-"
	case "existing":
		return "="
	}
	return " "
}

// padRight right-pads s with spaces to width n. Truncates with an
// ellipsis when s is strictly wider than n. Centralized so the
// table layout in every subcommand uses the same truncation glyph.
func padRight(s string, n int) string {
	if len(s) == n {
		return s
	}
	if len(s) > n {
		if n <= 1 {
			return s[:n]
		}
		return s[:n-1] + "…"
	}
	return s + strings.Repeat(" ", n-len(s))
}
