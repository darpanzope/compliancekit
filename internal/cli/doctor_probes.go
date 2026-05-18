package cli

import (
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/darpanzope/compliancekit/internal/ui"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// probeStatus classifies one doctor probe row so the renderer can
// pick a color + glyph + sort order. Lower numeric values bubble to
// the top of the rendered output.
type probeStatus int

const (
	probeFail probeStatus = iota // failures: pinned to the top so operators see them first
	probeWarn
	probePass
	probeInfo // informational rows render at the bottom
)

// probe is one row in doctor's output. children are emitted indented
// under their parent and inherit the parent's sort position so a
// failing provider's sub-bullets stay attached to it.
type probe struct {
	status   probeStatus
	name     string        // left-column label, e.g. "providers.digitalocean"
	detail   string        // free-text right-column body
	latency  time.Duration // optional badge; rendered as " (123ms)" when > 0
	children []probe
}

// probeBuf accumulates probes during the doctor run. Call Render at
// the end to emit the styled, failure-sorted view.
type probeBuf struct {
	probes []probe
}

// Fail / Warn / Pass / Info append a top-level probe.
func (b *probeBuf) Fail(name, detail string) { b.add(probeFail, name, detail, 0) }
func (b *probeBuf) Warn(name, detail string) { b.add(probeWarn, name, detail, 0) }
func (b *probeBuf) Pass(name, detail string) { b.add(probePass, name, detail, 0) }
func (b *probeBuf) Info(name, detail string) { b.add(probeInfo, name, detail, 0) }

// PassWithLatency adds a passing probe with a measured duration that
// renders as a muted "(123ms)" badge next to the detail.
func (b *probeBuf) PassWithLatency(name, detail string, d time.Duration) {
	b.add(probePass, name, detail, d)
}

func (b *probeBuf) add(s probeStatus, name, detail string, d time.Duration) {
	b.probes = append(b.probes, probe{status: s, name: name, detail: detail, latency: d})
}

// AddChild appends a sub-bullet to the most recently added top-level
// probe (the parent). Children inherit the parent's sort position so
// e.g. notify sink children stay grouped under "notify: 8 sinks…".
func (b *probeBuf) AddChild(s probeStatus, name, detail string) {
	if len(b.probes) == 0 {
		// No parent yet — promote to a top-level probe.
		b.add(s, name, detail, 0)
		return
	}
	parent := &b.probes[len(b.probes)-1]
	parent.children = append(parent.children, probe{status: s, name: name, detail: detail})
}

// Render writes every probe to w with the Styler's color + glyph
// treatment. Failures sort to the top; warn / pass / info groups
// follow. Insertion order is preserved within each group, and each
// parent's children render immediately after the parent regardless
// of the child statuses.
func (b *probeBuf) Render(w io.Writer, st *ui.Styler) {
	indexed := make([]int, len(b.probes))
	for i := range indexed {
		indexed[i] = i
	}
	// Stable-sort by status so the original order is preserved within
	// each status group.
	sort.SliceStable(indexed, func(i, j int) bool {
		return b.probes[indexed[i]].status < b.probes[indexed[j]].status
	})
	for _, idx := range indexed {
		p := b.probes[idx]
		fmt.Fprintln(w, renderProbeRow(st, p, 0))
		for _, c := range p.children {
			fmt.Fprintln(w, renderProbeRow(st, c, 4))
		}
	}
}

// HasFailures reports whether the buffer carries at least one
// probeFail row, including children. Used by runDoctor to translate
// into a non-zero exit code via NewExitCode.
func (b *probeBuf) HasFailures() bool {
	for _, p := range b.probes {
		if p.status == probeFail {
			return true
		}
		for _, c := range p.children {
			if c.status == probeFail {
				return true
			}
		}
	}
	return false
}

// renderProbeRow formats one probe as a single styled line. Indent
// shifts the row right (sub-items). The latency badge appears at
// the very end of the line so it's visually distinct from the name
// + detail.
func renderProbeRow(st *ui.Styler, p probe, indent int) string {
	prefix := ""
	for i := 0; i < indent; i++ {
		prefix += " "
	}
	glyph := probeGlyph(st, p.status)
	row := fmt.Sprintf("%s%s %s", prefix, glyph, st.Bold(p.name))
	if p.detail != "" {
		row += ": " + p.detail
	}
	if p.latency > 0 {
		row += " " + st.Muted(fmt.Sprintf("(%dms)", p.latency.Milliseconds()))
	}
	return row
}

// probeGlyph picks the styled glyph for a probe status. Glyph +
// color travel together so colorblind readers + grep-style
// pipelines both see the failure signal.
func probeGlyph(st *ui.Styler, s probeStatus) string {
	switch s {
	case probeFail:
		return st.InStatus(st.Glyph("fail"), compliancekit.StatusFail)
	case probeWarn:
		return st.InStatus(st.Glyph("error"), compliancekit.StatusError)
	case probePass:
		return st.InStatus(st.Glyph("pass"), compliancekit.StatusPass)
	}
	return st.InStatus(st.Glyph("info"), compliancekit.StatusSkip)
}
