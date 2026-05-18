package ui

import (
	"strings"
	"unicode/utf8"
)

// Table is a small Unicode box-drawing table renderer. Use it for
// structured-list output across subcommands (`checks list`,
// `doctor`, `waivers list`, `mapping list`, etc.) so the look is
// consistent without re-templating each command.
//
// Add header columns once, append rows, then call Render(styler).
// The styler picks colors for the frame characters; in plain mode
// the renderer drops to a simple ASCII frame with no separators
// inside the data rows so the output stays grep-friendly.
//
// Column widths auto-fit the longest cell. Cells wider than the
// per-column MaxWidth (when set) get truncated with the same
// ellipsis padRight uses.
type Table struct {
	headers []string
	rows    [][]string
	max     []int // per-column truncation width, 0 == unlimited
}

// NewTable returns an empty table with the given headers.
func NewTable(headers ...string) *Table {
	return &Table{
		headers: append([]string(nil), headers...),
		max:     make([]int, len(headers)),
	}
}

// AddRow appends one data row. The cell count must match the header
// count; extra cells are dropped, missing cells are filled with "".
func (t *Table) AddRow(cells ...string) {
	row := make([]string, len(t.headers))
	for i := range t.headers {
		if i < len(cells) {
			row[i] = cells[i]
		}
	}
	t.rows = append(t.rows, row)
}

// MaxWidth sets the truncation width for column index i (0-based).
// Cells wider than n get truncated with the project's standard
// ellipsis. Zero means "unlimited"; columns left unset have no cap.
func (t *Table) MaxWidth(i, n int) *Table {
	if i >= 0 && i < len(t.max) {
		t.max[i] = n
	}
	return t
}

// Render writes the table to a string using s's color decision.
// In color mode the frame is rendered in the muted color and the
// header is bold. In plain mode the frame uses plain ASCII (`+-|`).
func (t *Table) Render(s *Styler) string {
	if len(t.headers) == 0 {
		return ""
	}

	widths := t.computeWidths()
	frame := framePalette(s.Color)

	var b strings.Builder
	// Top border.
	b.WriteString(s.Muted(frame.top(widths)))
	b.WriteByte('\n')
	// Header row.
	b.WriteString(s.Muted(frame.v))
	for i, h := range t.headers {
		text := padRight(strings.ToUpper(h), widths[i])
		b.WriteByte(' ')
		b.WriteString(s.Bold(text))
		b.WriteByte(' ')
		b.WriteString(s.Muted(frame.v))
	}
	b.WriteByte('\n')
	// Header separator.
	b.WriteString(s.Muted(frame.mid(widths)))
	b.WriteByte('\n')
	// Data rows.
	for _, row := range t.rows {
		b.WriteString(s.Muted(frame.v))
		for i, cell := range row {
			text := padRight(cell, widths[i])
			b.WriteByte(' ')
			b.WriteString(text)
			b.WriteByte(' ')
			b.WriteString(s.Muted(frame.v))
		}
		b.WriteByte('\n')
	}
	// Bottom border.
	b.WriteString(s.Muted(frame.bot(widths)))
	b.WriteByte('\n')
	return b.String()
}

// computeWidths returns the rendered cell width per column. Each
// column is max(header, max-row-cell, configured-MaxWidth).
func (t *Table) computeWidths() []int {
	widths := make([]int, len(t.headers))
	for i, h := range t.headers {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, row := range t.rows {
		for i, cell := range row {
			if w := utf8.RuneCountInString(cell); w > widths[i] {
				widths[i] = w
			}
		}
	}
	for i, capW := range t.max {
		if capW > 0 && widths[i] > capW {
			widths[i] = capW
		}
	}
	return widths
}

// frame describes one set of corner / edge characters. The Unicode
// variant uses light box-drawing characters; the ASCII variant uses
// +-| so plain mode still parses on terminals without unicode.
type frame struct {
	tl, tr, bl, br string // corners
	h, v           string // edges
	tj, bj, mj     string // tee junctions (top, bottom, mid)
	cross          string
}

var (
	frameUnicode = frame{
		tl: "┌", tr: "┐", bl: "└", br: "┘",
		h: "─", v: "│",
		tj: "┬", bj: "┴", mj: "├",
		cross: "┼",
	}
	frameASCII = frame{
		tl: "+", tr: "+", bl: "+", br: "+",
		h: "-", v: "|",
		tj: "+", bj: "+", mj: "+",
		cross: "+",
	}
)

// framePalette returns the unicode frame in color mode and the
// ASCII fallback in plain mode.
func framePalette(color bool) frame {
	if color {
		return frameUnicode
	}
	return frameASCII
}

// top renders the top border row sized to the column widths
// (`┌───┬───┐` or `+---+---+`).
func (f frame) top(widths []int) string {
	return f.borderRow(f.tl, f.tj, f.tr, widths)
}

// bot renders the bottom border row.
func (f frame) bot(widths []int) string {
	return f.borderRow(f.bl, f.bj, f.br, widths)
}

// mid renders the header / data separator. Uses ├ ┼ ┤ for unicode.
func (f frame) mid(widths []int) string {
	// For the ASCII frame, every junction collapses to +. For the
	// unicode frame, left-tee + cross + right-tee. The right-tee
	// (┤) isn't in the frame struct because it's only used here;
	// materialized inline rather than widening the struct.
	if f.v == "|" {
		return f.borderRow("+", "+", "+", widths)
	}
	return f.borderRow(f.mj, f.cross, "┤", widths)
}

// borderRow assembles a horizontal border with the chosen
// left / junction / right characters.
func (f frame) borderRow(left, junc, right string, widths []int) string {
	var b strings.Builder
	b.WriteString(left)
	for i, w := range widths {
		b.WriteString(strings.Repeat(f.h, w+2))
		if i < len(widths)-1 {
			b.WriteString(junc)
		}
	}
	b.WriteString(right)
	return b.String()
}
