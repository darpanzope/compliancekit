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
	"github.com/darpanzope/compliancekit/internal/frameworks"
	"github.com/darpanzope/compliancekit/internal/score"
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
	Period               string
	Generated            string
	TotalFindings        int
	TotalControls        int
	Score                int // v0.6 hardening score per DECISIONS.md ADR-008
	Coverage             int // v0.6 % of finding weight that was evaluable
	Redacted             bool
	TailoringCount       int                  // v0.12: number of controls scoped out
	TailoringEntries     []tailoringViewEntry // v0.12: human-readable list for the auditor card
	ComplianceFrameworks []summaryFramework   // v0.12: category=compliance frameworks
	ThreatModels         []summaryFramework   // v0.12: category=threat_model frameworks (ATT&CK)
}

type summaryFramework struct {
	ID               string
	Name             string
	Category         string // v0.12: "compliance" or "threat_model"
	ControlsCovered  int
	ControlsWithFail int
	Controls         []summaryControl
}

type summaryControl struct {
	ID                        string
	Name                      string
	Family                    string   // v0.12: control family for grouping
	Tags                      []string // v0.12: CIS IG / HIPAA req-vs-addr / ATT&CK tactic refs
	Dir                       string   // <framework>/<control-dir>
	Pass, Fail, Skip, Errored int
	Tailored                  bool   // v0.12: scoped out by operator
	TailoringJustification    string // v0.12: operator's reason when tailored
}

type tailoringViewEntry struct {
	FrameworkID   string
	FrameworkName string
	ControlID     string
	ControlName   string
	Justification string
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
	buildTailoringSection(&view, opts.Tailoring)

	all, _ := frameworks.All() // best-effort; per-control category lookups skip on error
	for _, fr := range result.FrameworkResults {
		refs := result.ControlIndex[fr.FrameworkID]
		sort.Slice(refs, func(i, j int) bool { return refs[i].ControlID < refs[j].ControlID })
		fwView, n := buildFrameworkView(fr, refs, all, opts.Tailoring)
		view.TotalControls += n
		if fwView.Category == frameworks.CategoryThreatModel {
			view.ThreatModels = append(view.ThreatModels, fwView)
		} else {
			view.ComplianceFrameworks = append(view.ComplianceFrameworks, fwView)
		}
	}
	// TotalFindings counts unique (check, resource) pairs the pack
	// contains. A finding appearing under multiple controls is the
	// same artifact in audit terms, so we de-duplicate via the
	// Fingerprint helper that the diff engine (v0.6+) will use.
	unique := uniqueFindings(result.ControlIndex)
	view.TotalFindings = len(unique)

	// v0.6 hardening score, computed over the de-duplicated finding
	// set so a finding referenced under three frameworks does not
	// triple-count against the score.
	s := score.Compute(unique)
	view.Score = s.Score
	view.Coverage = s.Coverage
	return view
}

// buildTailoringSection populates view.TailoringCount + entries from
// the operator-declared rules. No-op when Tailoring is nil/empty.
func buildTailoringSection(view *summaryView, t *frameworks.Tailoring) {
	if t == nil || t.Count() == 0 {
		return
	}
	view.TailoringCount = t.Count()
	all, err := frameworks.All()
	if err != nil {
		return
	}
	for _, r := range t.Rules {
		entry := tailoringViewEntry{
			FrameworkID:   r.Framework,
			ControlID:     r.Control,
			Justification: r.Justification,
		}
		if fw, ok := all[r.Framework]; ok {
			entry.FrameworkName = fw.Name
			if ctrl, ok := fw.Controls[r.Control]; ok {
				entry.ControlName = ctrl.Name
			}
		}
		view.TailoringEntries = append(view.TailoringEntries, entry)
	}
}

// buildFrameworkView builds the per-framework section + returns the
// view and number of controls added. buildSummaryView aggregates the
// counts into TotalControls.
func buildFrameworkView(fr FrameworkResult, refs []ControlRef, all map[string]*frameworks.Framework, t *frameworks.Tailoring) (view summaryFramework, controlCount int) {
	view = summaryFramework{
		ID:               fr.FrameworkID,
		Name:             fr.FrameworkName,
		Category:         frameworks.CategoryCompliance,
		ControlsCovered:  fr.ControlsCovered,
		ControlsWithFail: fr.ControlsWithFail,
	}
	var fw *frameworks.Framework
	if all != nil {
		fw = all[fr.FrameworkID]
		if fw != nil && fw.IsThreatModel() {
			view.Category = frameworks.CategoryThreatModel
		}
	}
	for _, c := range refs {
		view.Controls = append(view.Controls, buildControlView(c, fw, t))
	}
	return view, len(refs)
}

// buildControlView builds a single control row including the v0.12
// family/tags and tailoring annotations.
func buildControlView(c ControlRef, fw *frameworks.Framework, t *frameworks.Tailoring) summaryControl {
	v := summaryControl{
		ID:      c.ControlID,
		Name:    c.ControlName,
		Dir:     fmt.Sprintf("%s/%s", c.FrameworkID, c.DirName),
		Pass:    countStatus(c.Findings, core.StatusPass),
		Fail:    countStatus(c.Findings, core.StatusFail),
		Skip:    countStatus(c.Findings, core.StatusSkip),
		Errored: countStatus(c.Findings, core.StatusError),
	}
	if fw != nil {
		if ctrl, ok := fw.Controls[c.ControlID]; ok {
			v.Family = ctrl.Family
			v.Tags = ctrl.Tags
		}
	}
	if just, ok := t.Lookup(c.FrameworkID, c.ControlID); ok {
		v.Tailored = true
		v.TailoringJustification = just
	}
	return v
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

// uniqueFindings de-duplicates the pack's findings via their stable
// Fingerprint (check_id + resource_id + status). A finding referenced
// under multiple framework controls is the same artifact in audit
// terms; this helper returns the canonical set for downstream
// summarisation (total count, hardening score).
func uniqueFindings(index map[string][]ControlRef) []core.Finding {
	seen := map[string]struct{}{}
	out := []core.Finding{}
	for _, refs := range index {
		for _, c := range refs {
			for _, f := range c.Findings {
				fp := f.Fingerprint()
				if _, ok := seen[fp]; ok {
					continue
				}
				seen[fp] = struct{}{}
				out = append(out, f)
			}
		}
	}
	return out
}
