package evidence

import (
	"embed"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
)

// summaryHTMLName is the filename used for the auditor-readable index
// at the pack root. ARCHITECTURE.md section 10 names it summary.html;
// kept literal so the spec stays grep-able.
const summaryHTMLName = "summary.html"

//go:embed assets/summary.html
var summaryAssets embed.FS

// summaryTemplate is parsed once at init; subsequent writes execute
// against this cached template. The HTML reporter at internal/report
// uses the same pattern for its assets.
var summaryTemplate = template.Must(template.ParseFS(summaryAssets, "assets/summary.html"))

// summaryView is what the template consumes. Top-level fields render
// in the header; Frameworks renders both the per-framework summary
// cards and the per-framework control tables below.
type summaryView struct {
	Period        string
	Generated     string
	TotalFindings int
	TotalControls int
	Redacted      bool
	Frameworks    []summaryFramework
}

type summaryFramework struct {
	ID               string
	Name             string
	ControlsCovered  int
	ControlsWithFail int
	Controls         []summaryControl
}

type summaryControl struct {
	ID                        string
	Name                      string
	Dir                       string // <framework>/<control-dir>
	Pass, Fail, Skip, Errored int
}

// writeSummaryHTML emits <out>/summary.html using the control index
// already populated by Generate's earlier phases. Returns the
// absolute path of the file written so the caller can stash it on
// Result for the CLI footer.
//
// Counts on the table rows are derived from the same ControlRef list
// the findings.json and control.md writers used, so the three views
// can never disagree.
func writeSummaryHTML(outDir string, result *Result, opts Options) (string, error) {
	view := buildSummaryView(result, opts)
	path := filepath.Join(outDir, summaryHTMLName)
	// G304: outDir is operator-controlled and the filename is constant.
	//nolint:gosec // operator-controlled output path
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := summaryTemplate.Execute(f, view); err != nil {
		return "", fmt.Errorf("render summary: %w", err)
	}
	return path, nil
}

// buildSummaryView assembles the template input from the per-control
// index. Sorts framework IDs and control IDs so re-renders over
// identical input produce byte-identical HTML.
func buildSummaryView(result *Result, opts Options) summaryView {
	view := summaryView{
		Period:    opts.Period,
		Generated: result.Generated.UTC().Format(time.RFC3339),
		Redacted:  !opts.IncludeRaw,
	}

	// Sort framework IDs deterministically. result.FrameworkResults is
	// already sorted by ID; we re-use that order for the controls
	// section directly below.
	for _, fr := range result.FrameworkResults {
		refs := result.ControlIndex[fr.FrameworkID]
		sort.Slice(refs, func(i, j int) bool { return refs[i].ControlID < refs[j].ControlID })

		fwView := summaryFramework{
			ID:               fr.FrameworkID,
			Name:             fr.FrameworkName,
			ControlsCovered:  fr.ControlsCovered,
			ControlsWithFail: fr.ControlsWithFail,
		}
		for _, c := range refs {
			fwView.Controls = append(fwView.Controls, summaryControl{
				ID:      c.ControlID,
				Name:    c.ControlName,
				Dir:     fmt.Sprintf("%s/%s", c.FrameworkID, c.DirName),
				Pass:    countStatus(c.Findings, core.StatusPass),
				Fail:    countStatus(c.Findings, core.StatusFail),
				Skip:    countStatus(c.Findings, core.StatusSkip),
				Errored: countStatus(c.Findings, core.StatusError),
			})
			view.TotalControls++
		}
		view.Frameworks = append(view.Frameworks, fwView)
	}
	// TotalFindings counts unique (check, resource) pairs the pack
	// contains. A finding appearing under multiple controls is the
	// same artifact in audit terms, so we de-duplicate via the
	// Fingerprint helper that the diff engine (v0.6+) will use.
	view.TotalFindings = countUniqueFindings(result.ControlIndex)
	return view
}

func countStatus(findings []core.Finding, status core.Status) int {
	n := 0
	for _, f := range findings {
		if f.Status == status {
			n++
		}
	}
	return n
}

func countUniqueFindings(index map[string][]ControlRef) int {
	seen := map[string]struct{}{}
	for _, refs := range index {
		for _, c := range refs {
			for _, f := range c.Findings {
				seen[f.Fingerprint()] = struct{}{}
			}
		}
	}
	return len(seen)
}
