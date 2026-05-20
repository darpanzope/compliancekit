package tui

// v1.7 phase 6 — diff-vs-baseline. `:diff <path>` loads a baseline
// findings.json + overlays gutter markers on the list pane:
//
//   +   new      (current has, baseline doesn't)
//   -   resolved (baseline has, current doesn't)
//   ~   changed  (same fingerprint, different status/severity)
//   (space)      stable
//
// Phase 6 minimum-viable ships the load + fingerprint diff + gutter
// render. Phase 8 teatest goldens cover the rendering.

import (
	"context"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// diffKind enumerates the per-finding gutter category vs. baseline.
type diffKind int

const (
	diffStable diffKind = iota
	diffNew
	diffResolved
	diffChanged
)

// glyph returns the one-char gutter marker for the kind.
func (d diffKind) glyph() string {
	switch d {
	case diffNew:
		return "+"
	case diffResolved:
		return "-"
	case diffChanged:
		return "~"
	default:
		return " "
	}
}

// loadBaseline reads a findings.json file + returns the parsed
// slice. Reuses the fileSource shape from phase 0 so the v0.3
// reporter contract + the bare-array escape hatch both work.
func loadBaseline(path string) ([]compliancekit.Finding, error) {
	src, err := NewFileSource(path)
	if err != nil {
		return nil, err
	}
	return src.LoadFindings(context.Background())
}

// computeDiff builds a per-fingerprint kind map for `current` vs.
// `baseline`. Resolved findings are returned separately (they need
// synthetic rows in the list since they're not in current).
func computeDiff(current, baseline []compliancekit.Finding) (perFingerprint map[string]diffKind, resolved []compliancekit.Finding) {
	baseMap := make(map[string]compliancekit.Finding, len(baseline))
	for _, f := range baseline {
		baseMap[f.Fingerprint()] = f
	}
	perFingerprint = make(map[string]diffKind, len(current))
	for _, f := range current {
		fp := f.Fingerprint()
		prev, hadBefore := baseMap[fp]
		switch {
		case !hadBefore:
			perFingerprint[fp] = diffNew
		case prev.Status != f.Status || prev.Severity != f.Severity:
			perFingerprint[fp] = diffChanged
		default:
			perFingerprint[fp] = diffStable
		}
		// Mark as seen so the resolved sweep doesn't double-count.
		delete(baseMap, fp)
	}
	// Whatever's left in baseMap is a baseline finding that's no
	// longer in current — resolved.
	resolved = make([]compliancekit.Finding, 0, len(baseMap))
	for _, f := range baseMap {
		resolved = append(resolved, f)
	}
	return perFingerprint, resolved
}
