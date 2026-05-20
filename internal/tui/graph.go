package tui

// v1.7 phase 4 — resource-tree navigator. `R` in normal mode
// opens a full-screen indented tree: provider → resource_type →
// resource. Each row shows finding-count + worst severity.
// j/k navigates; Enter applies a resource filter; Esc returns.
//
// The issue text reserved `g` for this, but `g` + `G` are vim's
// top/bottom and shipped at phase 1. `R` (resource) is the
// alternative; documented in CLI.md + the help overlay (phase 7).

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// graphNode is one row in the tree. Three depths: provider (0),
// resource_type (1), resource (2). Counts roll up from children.
type graphNode struct {
	label       string
	depth       int // 0 / 1 / 2
	count       int
	worstSev    compliancekit.Severity
	providerKey string
	resourceKey string // populated for depth==2 — used as the activate filter
}

// resBucket / typeBucket / provBucket are concrete types for the
// nested aggregation; named so the sortedKeys helpers can range
// over them.
type resBucket struct {
	count int
	worst compliancekit.Severity
}

type typeBucket struct {
	resources map[string]*resBucket
	count     int
	worst     compliancekit.Severity
}

type provBucket struct {
	types map[string]*typeBucket
	count int
	worst compliancekit.Severity
}

// buildGraphRows walks findings + emits a flat slice of graphNodes
// in display order (provider → type → resource). Each level is
// sorted alphabetically; counts roll up to the parent.
func buildGraphRows(findings []compliancekit.Finding) []graphNode {
	providers := map[string]*provBucket{}
	for _, f := range findings {
		upsertFindingIntoBuckets(providers, f)
	}
	return flattenBuckets(providers)
}

// upsertFindingIntoBuckets attributes one finding into the nested
// provider → type → resource aggregation. Extracted from
// buildGraphRows to keep that function under gocyclo's 15-edge cap.
func upsertFindingIntoBuckets(providers map[string]*provBucket, f compliancekit.Finding) {
	p := f.Resource.Provider
	if p == "" {
		p = providerFromType(f.Resource.Type)
	}
	if p == "" {
		p = unknownLabel
	}
	t := f.Resource.Type
	if t == "" {
		t = unknownLabel
	}
	r := f.Resource.Name
	if r == "" {
		r = f.Resource.ID
	}
	if r == "" {
		r = "(unnamed)"
	}
	pb, ok := providers[p]
	if !ok {
		pb = &provBucket{types: map[string]*typeBucket{}}
		providers[p] = pb
	}
	tb, ok := pb.types[t]
	if !ok {
		tb = &typeBucket{resources: map[string]*resBucket{}}
		pb.types[t] = tb
	}
	rb, ok := tb.resources[r]
	if !ok {
		rb = &resBucket{}
		tb.resources[r] = rb
	}
	rb.count++
	pb.count++
	tb.count++
	if f.Severity > rb.worst {
		rb.worst = f.Severity
	}
	if f.Severity > tb.worst {
		tb.worst = f.Severity
	}
	if f.Severity > pb.worst {
		pb.worst = f.Severity
	}
}

// flattenBuckets walks the nested aggregation in sorted order and
// emits the display-flat row slice.
func flattenBuckets(providers map[string]*provBucket) []graphNode {
	out := make([]graphNode, 0, 64)
	for _, p := range sortedStringKeys(providers) {
		pb := providers[p]
		out = append(out, graphNode{label: p, depth: 0, count: pb.count, worstSev: pb.worst, providerKey: p})
		for _, t := range sortedTypeKeys(pb.types) {
			tb := pb.types[t]
			out = append(out, graphNode{label: t, depth: 1, count: tb.count, worstSev: tb.worst, providerKey: p})
			for _, r := range sortedResKeys(tb.resources) {
				rb := tb.resources[r]
				out = append(out, graphNode{label: r, depth: 2, count: rb.count, worstSev: rb.worst, providerKey: p, resourceKey: r})
			}
		}
	}
	return out
}

func sortedStringKeys(m map[string]*provBucket) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedTypeKeys(m map[string]*typeBucket) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedResKeys(m map[string]*resBucket) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// renderGraph builds the full-screen view string. cursor selects
// which row is highlighted; out-of-bounds clamps. width/height
// are the terminal cell extent.
func renderGraph(rows []graphNode, cursor, width, height int) string {
	title := lipgloss.NewStyle().Bold(true).Render("Resource tree — j/k navigate · Enter apply filter · Esc return")
	body := []string{title, strings.Repeat("─", imax(width-2, 10)), ""}
	if len(rows) == 0 {
		body = append(body, "  (no resources to display)")
		return strings.Join(body, "\n")
	}
	if cursor < 0 {
		cursor = 0
	}
	if cursor >= len(rows) {
		cursor = len(rows) - 1
	}
	// Window the rows around the cursor.
	maxRows := height - 5
	if maxRows < 5 {
		maxRows = 5
	}
	start := cursor - maxRows/2
	if start < 0 {
		start = 0
	}
	end := start + maxRows
	if end > len(rows) {
		end = len(rows)
	}
	if end-start < maxRows {
		start = end - maxRows
		if start < 0 {
			start = 0
		}
	}
	for i := start; i < end; i++ {
		n := rows[i]
		marker := "  "
		if i == cursor {
			marker = cursorMarker
		}
		indent := strings.Repeat("  ", n.depth)
		glyph := ""
		switch n.depth {
		case 0:
			glyph = "▾ "
		case 1:
			glyph = "├── "
		case 2:
			glyph = "│   "
		}
		line := fmt.Sprintf("%s%s%s%s  (%d findings · worst=%s)",
			marker, indent, glyph, n.label, n.count, severityShort(n.worstSev))
		body = append(body, line)
	}
	body = append(body, "",
		lipgloss.NewStyle().Faint(true).Render(fmt.Sprintf("%d / %d", cursor+1, len(rows))))
	return strings.Join(body, "\n")
}
