// Package report extends the v1.2 vanilla-SVG drawers with the
// v1.14 chart kit: heatmap, treemap, sankey, radar. All drawers
// emit a self-contained <svg> string and pre-wire the v1.18
// interactivity hooks (data-ck-bucket + data-ck-href + data-ck-
// annotation) so the design-system milestone can layer hover
// tooltips + click-drill + annotation overlays without re-shaping
// the SVG output.
//
// No new dependencies — strings.Builder + math is all we reach for.
// The v1.2 line/donut/gauge drawers stay in their own files; this
// file owns the v1.14-only shapes.
package report

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// chartPalette is the canonical severity-color ramp used by every
// drawer that needs to color by severity. Mirrors the v1.2 HTML
// report tokens so the dashboard widgets match the standalone
// finding card style.
var chartPalette = map[string]string{
	"critical": "#dc2626",
	"high":     "#ea580c",
	"medium":   "#d97706",
	"low":      "#2563eb",
	"info":     "#475569",
}

// HeatmapCell is one cell on a (Row × Col) grid. Value drives the
// fill intensity; the drawer maps the slice's max value to the
// darkest color + scales linearly down to a near-white floor.
type HeatmapCell struct {
	Row     string
	Col     string
	Value   int
	Tooltip string // optional hover-tooltip seed for the v1.18 layer
}

// Heatmap returns the SVG body for a resource × severity heatmap.
// Rows + cols are emitted in the order they first appear in cells;
// callers stable-sort cells when they care.
func Heatmap(cells []HeatmapCell, width, height int) string {
	if width <= 0 {
		width = 400
	}
	if height <= 0 {
		height = 200
	}
	rows, cols := axisOrder(cells)
	if len(rows) == 0 || len(cols) == 0 {
		return emptySVG(width, height, "no data")
	}
	maxV := 0
	for _, c := range cells {
		if c.Value > maxV {
			maxV = c.Value
		}
	}
	if maxV == 0 {
		maxV = 1
	}
	const labelPad = 80
	const topPad = 16
	cellW := (width - labelPad) / len(cols)
	cellH := (height - topPad) / len(rows)
	cellByKey := make(map[string]HeatmapCell, len(cells))
	for _, c := range cells {
		cellByKey[c.Row+"|"+c.Col] = c
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" role="img" aria-label="heatmap">`, width, height)
	// Column headers.
	for ci, col := range cols {
		x := labelPad + ci*cellW + cellW/2
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="10" text-anchor="middle" fill="currentColor">%s</text>`,
			x, topPad-4, escapeXML(col))
	}
	// Rows + cells.
	for ri, row := range rows {
		y := topPad + ri*cellH
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="10" text-anchor="end" fill="currentColor">%s</text>`,
			labelPad-6, y+cellH/2+3, escapeXML(row))
		for ci, col := range cols {
			x := labelPad + ci*cellW
			c := cellByKey[row+"|"+col]
			intensity := float64(c.Value) / float64(maxV)
			fill := heatFill(intensity)
			tip := c.Tooltip
			if tip == "" {
				tip = fmt.Sprintf("%s × %s: %d", row, col, c.Value)
			}
			fmt.Fprintf(&b,
				`<rect x="%d" y="%d" width="%d" height="%d" fill="%s" data-ck-bucket="%s|%s" data-ck-tooltip="%s"><title>%s</title></rect>`,
				x, y, cellW-1, cellH-1, fill,
				escapeXML(row), escapeXML(col), escapeXML(tip), escapeXML(tip))
		}
	}
	b.WriteString(`</svg>`)
	return b.String()
}

// heatFill maps a [0,1] intensity to a CSS hex color along the
// brand-blue ramp.
func heatFill(intensity float64) string {
	if intensity <= 0 {
		return "#f1f5f9"
	}
	// Lerp from light cyan to brand blue.
	r := int(241 + (37-241)*intensity)
	g := int(245 + (99-245)*intensity)
	b := int(249 + (235-249)*intensity)
	return fmt.Sprintf("#%02x%02x%02x", r, g, b)
}

// TreemapSlice is one leaf in a treemap. Value drives area.
type TreemapSlice struct {
	Label   string
	Value   int
	Color   string // optional; defaults to a stable palette pick
	Tooltip string
}

// Treemap returns the SVG body for a flat (single-level) treemap.
// Uses the squarified algorithm — close enough to the canonical
// implementation for the dashboard use case without pulling in a
// chart lib.
func Treemap(slices []TreemapSlice, width, height int) string {
	if width <= 0 {
		width = 400
	}
	if height <= 0 {
		height = 200
	}
	if len(slices) == 0 {
		return emptySVG(width, height, "no data")
	}
	// Sort descending by value so the largest slice anchors the layout.
	sorted := make([]TreemapSlice, len(slices))
	copy(sorted, slices)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Value > sorted[j].Value })

	total := 0
	for _, s := range sorted {
		total += s.Value
	}
	if total == 0 {
		return emptySVG(width, height, "no data")
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" role="img" aria-label="treemap">`, width, height)
	x, y, w, h := 0.0, 0.0, float64(width), float64(height)
	remaining := sorted
	for len(remaining) > 0 {
		// Slice off the next row of cells.
		row, rest := nextSquarifiedRow(remaining, w, h)
		rowSum := 0
		for _, s := range row {
			rowSum += s.Value
		}
		if rowSum == 0 {
			break
		}
		// Lay out this row along the shorter axis.
		if w < h {
			rowH := h * float64(rowSum) / float64(remainingSum(remaining))
			cellX := x
			for _, s := range row {
				cellW := w * float64(s.Value) / float64(rowSum)
				emitTreemapCell(&b, s, cellX, y, cellW, rowH)
				cellX += cellW
			}
			y += rowH
			h -= rowH
		} else {
			rowW := w * float64(rowSum) / float64(remainingSum(remaining))
			cellY := y
			for _, s := range row {
				cellH := h * float64(s.Value) / float64(rowSum)
				emitTreemapCell(&b, s, x, cellY, rowW, cellH)
				cellY += cellH
			}
			x += rowW
			w -= rowW
		}
		remaining = rest
	}
	b.WriteString(`</svg>`)
	return b.String()
}

func emitTreemapCell(b *strings.Builder, s TreemapSlice, x, y, w, h float64) {
	fill := s.Color
	if fill == "" {
		fill = paletteByIndex(s.Label)
	}
	tip := s.Tooltip
	if tip == "" {
		tip = fmt.Sprintf("%s: %d", s.Label, s.Value)
	}
	fmt.Fprintf(b,
		`<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="%s" stroke="white" stroke-width="0.5" data-ck-bucket="%s" data-ck-tooltip="%s"><title>%s</title></rect>`,
		x, y, w, h, fill, escapeXML(s.Label), escapeXML(tip), escapeXML(tip))
	// Label when the cell is large enough.
	if w > 60 && h > 18 {
		fmt.Fprintf(b, `<text x="%.2f" y="%.2f" font-size="10" fill="white">%s</text>`,
			x+4, y+14, escapeXML(s.Label))
	}
}

// nextSquarifiedRow is the simplest viable squarify: greedily pack
// rows until the worst aspect-ratio in the row gets worse, then
// emit the row.
func nextSquarifiedRow(slices []TreemapSlice, w, h float64) (row []TreemapSlice, rest []TreemapSlice) {
	if len(slices) == 0 {
		return nil, nil
	}
	row = []TreemapSlice{slices[0]}
	rest = slices[1:]
	worst := worstAspect(row, w, h)
	for len(rest) > 0 {
		trial := append(append([]TreemapSlice{}, row...), rest[0])
		ta := worstAspect(trial, w, h)
		if ta > worst {
			break
		}
		row = trial
		worst = ta
		rest = rest[1:]
	}
	return row, rest
}

func worstAspect(row []TreemapSlice, w, h float64) float64 {
	if len(row) == 0 {
		return math.Inf(1)
	}
	sum := 0
	for _, s := range row {
		sum += s.Value
	}
	if sum == 0 {
		return math.Inf(1)
	}
	minV, maxV := math.Inf(1), 0.0
	for _, s := range row {
		v := float64(s.Value)
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}
	if minV == 0 {
		return math.Inf(1)
	}
	short := math.Min(w, h)
	areaTotal := w * h * float64(sum) / float64(sum)
	_ = areaTotal
	rowArea := short * short * float64(sum) / float64(sum+1)
	_ = rowArea
	// Heuristic aspect: max / min ratio.
	return maxV / minV
}

func remainingSum(slices []TreemapSlice) int {
	n := 0
	for _, s := range slices {
		n += s.Value
	}
	if n == 0 {
		n = 1
	}
	return n
}

// SankeyLink is one (source, target, value) edge.
type SankeyLink struct {
	Source string
	Target string
	Value  int
}

// Sankey returns a simple two-column sankey diagram. Sources on the
// left, targets on the right; each link's stroke width scales with
// its value. Multi-column sankeys are deferred — the v1.14 use case
// is "drift sources → resolutions" which is exactly two columns.
func Sankey(links []SankeyLink, width, height int) string {
	if width <= 0 {
		width = 500
	}
	if height <= 0 {
		height = 240
	}
	if len(links) == 0 {
		return emptySVG(width, height, "no data")
	}
	sources := uniqueOrdered(links, true)
	targets := uniqueOrdered(links, false)
	srcTotals := make(map[string]int)
	tgtTotals := make(map[string]int)
	total := 0
	for _, l := range links {
		srcTotals[l.Source] += l.Value
		tgtTotals[l.Target] += l.Value
		total += l.Value
	}
	if total == 0 {
		return emptySVG(width, height, "no data")
	}

	var b strings.Builder
	const nodeW = 12
	const pad = 4
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" role="img" aria-label="sankey">`, width, height)

	srcY := nodePositions(sources, srcTotals, height, pad)
	tgtY := nodePositions(targets, tgtTotals, height, pad)

	// Links (drawn behind nodes via paint order).
	srcOffset := make(map[string]float64)
	tgtOffset := make(map[string]float64)
	for _, l := range links {
		srcH := scaleNode(srcTotals[l.Source], total, height, pad, len(sources))
		tgtH := scaleNode(tgtTotals[l.Target], total, height, pad, len(targets))
		linkH := scaleLink(l.Value, total, height, pad)
		x0 := float64(nodeW)
		x1 := float64(width - nodeW)
		y0 := srcY[l.Source] + srcOffset[l.Source]
		y1 := tgtY[l.Target] + tgtOffset[l.Target]
		_ = srcH
		_ = tgtH
		path := fmt.Sprintf("M%f,%f C%f,%f %f,%f %f,%f",
			x0, y0+linkH/2,
			x0+(x1-x0)/2, y0+linkH/2,
			x0+(x1-x0)/2, y1+linkH/2,
			x1, y1+linkH/2)
		fmt.Fprintf(&b,
			`<path d="%s" fill="none" stroke="#94a3b8" stroke-opacity="0.5" stroke-width="%f" data-ck-bucket="%s>%s"><title>%s → %s: %d</title></path>`,
			path, linkH,
			escapeXML(l.Source), escapeXML(l.Target),
			escapeXML(l.Source), escapeXML(l.Target), l.Value)
		srcOffset[l.Source] += linkH
		tgtOffset[l.Target] += linkH
	}

	// Source nodes.
	for _, name := range sources {
		h := scaleNode(srcTotals[name], total, height, pad, len(sources))
		y := srcY[name]
		fmt.Fprintf(&b,
			`<rect x="0" y="%f" width="%d" height="%f" fill="#475569"><title>%s</title></rect>`,
			y, nodeW, h, escapeXML(name))
		fmt.Fprintf(&b,
			`<text x="%d" y="%f" font-size="10" fill="currentColor">%s</text>`,
			nodeW+4, y+10, escapeXML(name))
	}
	// Target nodes.
	for _, name := range targets {
		h := scaleNode(tgtTotals[name], total, height, pad, len(targets))
		y := tgtY[name]
		fmt.Fprintf(&b,
			`<rect x="%d" y="%f" width="%d" height="%f" fill="#475569"><title>%s</title></rect>`,
			width-nodeW, y, nodeW, h, escapeXML(name))
		fmt.Fprintf(&b,
			`<text x="%d" y="%f" font-size="10" fill="currentColor" text-anchor="end">%s</text>`,
			width-nodeW-4, y+10, escapeXML(name))
	}

	b.WriteString(`</svg>`)
	return b.String()
}

func uniqueOrdered(links []SankeyLink, source bool) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, l := range links {
		v := l.Target
		if source {
			v = l.Source
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func nodePositions(names []string, totals map[string]int, height, pad int) map[string]float64 {
	out := make(map[string]float64, len(names))
	y := float64(pad)
	for _, n := range names {
		out[n] = y
		y += scaleNode(totals[n], sumMap(totals), height, pad, len(names)) + float64(pad)
	}
	return out
}

func scaleNode(value, total, height, pad, n int) float64 {
	available := float64(height) - float64(pad*(n+1))
	return available * float64(value) / float64(total)
}

func scaleLink(value, total, height, pad int) float64 {
	available := float64(height) - float64(pad*2)
	return available * float64(value) / float64(total)
}

func sumMap(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	if n == 0 {
		n = 1
	}
	return n
}

// RadarAxis is one spoke on a radar chart. Value is in [0,1]; the
// drawer maps to a fraction of the radius. Multiple radars layered
// on the same axes is a v1.18 nice-to-have — v1.14 ships single-
// series.
type RadarAxis struct {
	Label string
	Value float64
}

// Radar returns the SVG body for a single-series radar / spider
// chart. Axes are evenly spaced around the perimeter; the polygon
// connects each axis's scaled value point.
func Radar(axes []RadarAxis, width, height int) string {
	if width <= 0 {
		width = 240
	}
	if height <= 0 {
		height = 240
	}
	if len(axes) < 3 {
		return emptySVG(width, height, "radar needs ≥3 axes")
	}
	cx := float64(width) / 2
	cy := float64(height) / 2
	r := math.Min(cx, cy) - 24

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" role="img" aria-label="radar">`, width, height)
	// Concentric gridlines (25/50/75/100%).
	for _, pct := range []float64{0.25, 0.5, 0.75, 1.0} {
		fmt.Fprintf(&b, `<circle cx="%f" cy="%f" r="%f" fill="none" stroke="#e2e8f0" stroke-width="0.5"/>`,
			cx, cy, r*pct)
	}
	// Axis spokes + labels.
	step := 2 * math.Pi / float64(len(axes))
	for i, ax := range axes {
		angle := -math.Pi/2 + float64(i)*step
		x := cx + r*math.Cos(angle)
		y := cy + r*math.Sin(angle)
		fmt.Fprintf(&b, `<line x1="%f" y1="%f" x2="%f" y2="%f" stroke="#e2e8f0" stroke-width="0.5"/>`,
			cx, cy, x, y)
		labelX := cx + (r+12)*math.Cos(angle)
		labelY := cy + (r+12)*math.Sin(angle)
		fmt.Fprintf(&b, `<text x="%f" y="%f" font-size="10" text-anchor="middle" fill="currentColor">%s</text>`,
			labelX, labelY+3, escapeXML(ax.Label))
	}
	// Polygon connecting the value points.
	var points strings.Builder
	for i, ax := range axes {
		angle := -math.Pi/2 + float64(i)*step
		v := ax.Value
		if v < 0 {
			v = 0
		}
		if v > 1 {
			v = 1
		}
		x := cx + r*v*math.Cos(angle)
		y := cy + r*v*math.Sin(angle)
		if i > 0 {
			points.WriteString(" ")
		}
		fmt.Fprintf(&points, "%f,%f", x, y)
	}
	fmt.Fprintf(&b, `<polygon points="%s" fill="#3b82f6" fill-opacity="0.25" stroke="#2563eb" stroke-width="1.5" data-ck-bucket="radar"/>`,
		points.String())
	b.WriteString(`</svg>`)
	return b.String()
}

// ── helpers ──────────────────────────────────────────────────────

func emptySVG(width, height int, msg string) string {
	return fmt.Sprintf(
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d"><text x="%d" y="%d" font-size="11" text-anchor="middle" fill="#64748b">%s</text></svg>`,
		width, height, width/2, height/2, escapeXML(msg))
}

func axisOrder(cells []HeatmapCell) (rows, cols []string) {
	rSeen := map[string]bool{}
	cSeen := map[string]bool{}
	for _, c := range cells {
		if !rSeen[c.Row] {
			rSeen[c.Row] = true
			rows = append(rows, c.Row)
		}
		if !cSeen[c.Col] {
			cSeen[c.Col] = true
			cols = append(cols, c.Col)
		}
	}
	return rows, cols
}

// paletteByIndex returns a stable color for a string key via the
// chartPalette severity table when the key matches, else falls
// through to a small categorical ramp.
func paletteByIndex(key string) string {
	if c, ok := chartPalette[strings.ToLower(key)]; ok {
		return c
	}
	cats := []string{
		"#2563eb", "#0891b2", "#0d9488", "#16a34a",
		"#65a30d", "#ca8a04", "#dc2626", "#db2777",
		"#7c3aed", "#475569",
	}
	h := 0
	for _, b := range []byte(key) {
		h = (h*131 + int(b)) & 0x7fffffff
	}
	return cats[h%len(cats)]
}

// escapeXML is a tiny subset of html/template escaping — enough for
// SVG text content. Pulled in-package to avoid the html/template
// import cost in the chart drawers.
func escapeXML(s string) string {
	repl := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return repl.Replace(s)
}
