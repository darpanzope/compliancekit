package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// newStylerForTest builds a Styler with an explicit color decision,
// bypassing the TTY auto-detection that would always return false
// under `go test`. Tests that care about which mode they exercise
// pick one explicitly.
func newStylerForTest(color bool) *Styler {
	var buf bytes.Buffer
	return newStylerWithProfile(&buf, color)
}

// TestStyler_PlainMode asserts byte-stable output under Color=false.
// This is the surface piped CI runs / grep / log files see; any drift
// here breaks downstream parsers + dashboards built on the v0.x output
// shape.
func TestStyler_PlainMode(t *testing.T) {
	s := newStylerForTest(false)

	cases := []struct {
		name string
		got  string
		want string
	}{
		{"severity critical", s.Severity(compliancekit.SeverityCritical), "CRITICAL"},
		{"severity high padded", s.Severity(compliancekit.SeverityHigh), "HIGH    "},
		{"severity medium padded", s.Severity(compliancekit.SeverityMedium), "MEDIUM  "},
		{"severity low padded", s.Severity(compliancekit.SeverityLow), "LOW     "},
		{"severity info padded", s.Severity(compliancekit.SeverityInfo), "INFO    "},
		{"severity chip", s.SeverityChip(compliancekit.SeverityHigh), "[HIGH]"},
		{"status pass", s.Status(compliancekit.StatusPass), "ok pass "},
		{"status fail", s.Status(compliancekit.StatusFail), "X fail "},
		{"status skip", s.Status(compliancekit.StatusSkip), "- skip "},
		{"status error", s.Status(compliancekit.StatusError), "! error"},
		{"glyph arrow", s.Glyph("arrow"), "->"},
		{"glyph bullet", s.Glyph("bullet"), "*"},
		{"glyph unknown", s.Glyph("zzz"), " "},
		{"muted noop", s.Muted("foo"), "foo"},
		{"accent noop", s.Accent("bar"), "bar"},
		{"bold noop", s.Bold("baz"), "baz"},
		{"diff added", s.DiffMark("added"), "+"},
		{"diff removed", s.DiffMark("removed"), "-"},
		{"diff existing", s.DiffMark("existing"), "="},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %q want %q", c.name, c.got, c.want)
		}
	}
}

// TestStyler_ColorEmitsANSI asserts that the color mode actually
// wraps output in ANSI escape sequences. We do not pin the exact
// sequence (lipgloss may evolve its compaction strategy) — only that
// ESC is present and the underlying text + glyph are still readable.
func TestStyler_ColorEmitsANSI(t *testing.T) {
	s := newStylerForTest(true)

	cases := []struct {
		name        string
		got         string
		wantSubstr  string
		wantPrefix  string
		mustContain bool
	}{
		{"severity critical wraps", s.Severity(compliancekit.SeverityCritical), "CRITICAL", "\x1b[", true},
		{"severity chip wraps", s.SeverityChip(compliancekit.SeverityHigh), "[HIGH]", "\x1b[", true},
		{"status fail wraps glyph + name", s.Status(compliancekit.StatusFail), "✗", "\x1b[", true},
		{"muted wraps", s.Muted("foo"), "foo", "\x1b[", true},
		{"accent wraps", s.Accent("bar"), "bar", "\x1b[", true},
		{"bold wraps", s.Bold("baz"), "baz", "\x1b[", true},
		{"diff added", s.DiffMark("added"), "+", "\x1b[", true},
	}
	for _, c := range cases {
		if !strings.Contains(c.got, c.wantSubstr) {
			t.Errorf("%s: %q missing substring %q", c.name, c.got, c.wantSubstr)
		}
		if c.mustContain && !strings.Contains(c.got, c.wantPrefix) {
			t.Errorf("%s: %q missing ANSI escape prefix %q", c.name, c.got, c.wantPrefix)
		}
	}
}

// TestStyler_UnicodeGlyphsInColorMode asserts the four core status
// glyphs render to the documented unicode characters when color is
// on. Cheap protection against accidental glyph swaps.
func TestStyler_UnicodeGlyphsInColorMode(t *testing.T) {
	s := newStylerForTest(true)
	cases := map[string]string{
		"pass":  "✓",
		"fail":  "✗",
		"skip":  "–",
		"error": "⚠",
	}
	for token, want := range cases {
		if got := s.Glyph(token); got != want {
			t.Errorf("Glyph(%q) = %q want %q", token, got, want)
		}
	}
}

// TestPadRight pins the padding + truncation behavior the table
// renderers depend on for column alignment.
func TestPadRight(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"abc", 5, "abc  "},
		{"abc", 3, "abc"},
		{"abcdef", 4, "abc…"},
		{"a", 1, "a"},
		{"abcdef", 1, "a"},
		{"", 3, "   "},
	}
	for _, c := range cases {
		got := padRight(c.in, c.n)
		if got != c.want {
			t.Errorf("padRight(%q, %d) = %q want %q", c.in, c.n, got, c.want)
		}
	}
}

// TestIsColorEnabled_GatesByForceOff verifies the --no-color path
// short-circuits before any env-var check.
func TestIsColorEnabled_GatesByForceOff(t *testing.T) {
	t.Setenv("NO_COLOR", "") // make sure env state is clean
	t.Setenv("CLICOLOR", "")
	var buf bytes.Buffer // non-TTY writer; would be plain anyway
	if IsColorEnabled(&buf, true) {
		t.Error("forceOff=true should return false regardless of env")
	}
}

// TestIsColorEnabled_RespectsNO_COLOR walks the no-color.org spec:
// any value (including empty string) means color is off.
func TestIsColorEnabled_RespectsNO_COLOR(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var buf bytes.Buffer
	if IsColorEnabled(&buf, false) {
		t.Error("NO_COLOR set should disable color")
	}
}

// TestIsColorEnabled_RespectsCLICOLOR0 covers the legacy BSD / git
// "CLICOLOR=0" gate.
func TestIsColorEnabled_RespectsCLICOLOR0(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR", "0")
	var buf bytes.Buffer
	if IsColorEnabled(&buf, false) {
		t.Error("CLICOLOR=0 should disable color")
	}
}

// TestIsColorEnabled_NonTTYBuffer asserts that any plain io.Writer
// (e.g. bytes.Buffer) is treated as non-TTY → no color.
func TestIsColorEnabled_NonTTYBuffer(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR", "")
	var buf bytes.Buffer
	if IsColorEnabled(&buf, false) {
		t.Error("non-TTY writer should disable color")
	}
}
