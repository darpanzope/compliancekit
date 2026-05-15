// Package evidence assembles an audit-ready folder from a set of
// scan findings. The output layout follows ARCHITECTURE.md section 10:
//
//	<out>/
//	  MANIFEST.sha256             // every file under <out> hashed
//	  control-mapping.csv         // (check, control, status, evidence path)
//	  summary.html                // auditor-readable index
//	  <framework>/<control-id>-<slug>/
//	    findings.json             // raw findings for this control
//	    control.md                // per-control human summary
//
// The pack is designed to survive auditor handoff: filenames carry
// the period prefix, MANIFEST.sha256 detects tampering, and
// control-mapping.csv is the row-per-evidence-artifact format that
// Drata, Vanta, and AuditBoard ingest. Per ADR-006 the pack is the
// differentiator versus Prowler / ScoutSuite / Steampipe -- those
// tools emit JSON; we emit a folder an auditor can sign off on.
//
// Layout is fixed (no plugins) at v0.4. v0.6+ may add tarballing,
// gpg signing, and S3 upload as separate post-generators.
package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/frameworks"
)

// schemaVersion is included in every JSON artifact so consumers can
// detect pack-schema drift across compliancekit versions independently
// of the scan-output schemaVersion in internal/report.
const schemaVersion = "compliancekit.evidence.v1"

// Options controls evidence pack generation. Period is a free-form
// label used in the pack header and the top-level directory name when
// the caller passes "" for OutDir; "2026-Q2", "2026-05", and
// "pre-audit-soak" are all valid.
type Options struct {
	// OutDir is the directory the pack is written into. Must not
	// exist or must be empty; Generate refuses to overwrite an
	// existing pack so a stale run cannot be silently merged with a
	// fresh one. Required.
	OutDir string

	// Period is the audit period label embedded in pack metadata and
	// the per-control Markdown. Optional; defaults to the current
	// year-quarter (e.g. "2026-Q2").
	Period string

	// IncludeRaw, when true, copies the raw collector payloads
	// pointed to by Finding.Evidence into the pack without
	// redaction. Default false: redacted summaries only. v0.4 ships
	// the toggle; the collector-side raw capture lands in v0.5.
	IncludeRaw bool

	// Generated overrides the timestamp embedded in the pack header.
	// Tests use this to produce byte-stable output; production
	// callers leave it zero (Generate substitutes time.Now().UTC()).
	Generated time.Time

	// Tailoring is the operator-declared list of (framework, control)
	// pairs scoped out of audit, each with a required justification.
	// When non-nil and non-empty, the evidence pack writes a
	// tailoring.json at the root and the control-mapping.csv gains
	// `tailored` + `tailoring_justification` columns. v0.12+.
	Tailoring *frameworks.Tailoring
}

// Result summarizes what Generate wrote so the CLI can render a
// human-readable footer without re-walking the pack.
type Result struct {
	OutDir           string                  // absolute path to the pack root
	FilesWritten     int                     // total files written, including MANIFEST
	FrameworkResults []FrameworkResult       // one per framework with at least one mapped finding
	ManifestPath     string                  // <OutDir>/MANIFEST.sha256
	MappingCSVPath   string                  // <OutDir>/control-mapping.csv
	SummaryHTMLPath  string                  // <OutDir>/summary.html (empty until phase 4 lands)
	TailoringPath    string                  // <OutDir>/tailoring.json (v0.12+); empty when no rules
	TailoringCount   int                     // number of tailoring rules recorded
	Generated        time.Time               // header timestamp actually used
	ControlIndex     map[string][]ControlRef // framework -> controls covered (display order)
}

// FrameworkResult is the per-framework rollup shown in the CLI footer.
type FrameworkResult struct {
	FrameworkID      string
	FrameworkName    string
	ControlsCovered  int
	ControlsWithFail int
}

// ControlRef pairs a control with the findings attributed to it. The
// per-control Markdown writer (Phase 3) consumes this; Phase 2 emits
// findings.json from the same data.
type ControlRef struct {
	FrameworkID   string
	FrameworkName string
	ControlID     string
	ControlName   string
	DirName       string // "<id>-<slug>" -- this control's directory under <framework>/
	Findings      []core.Finding
}

// Generate writes a complete evidence pack to opts.OutDir. The pack
// includes a per-control findings.json today; per-control Markdown,
// control-mapping.csv, and summary.html are added by subsequent
// phases of v0.4.
//
// The output directory must not exist or must be empty; Generate
// refuses to merge into a pre-existing pack so a stale run cannot
// taint a fresh one (per ARCHITECTURE.md section 10 -- every artifact
// is dated and the manifest must cover exactly the files of this run).
func Generate(_ context.Context, findings []core.Finding, opts Options) (Result, error) {
	if opts.OutDir == "" {
		return Result{}, fmt.Errorf("evidence: OutDir is required")
	}
	if err := ensureEmptyDir(opts.OutDir); err != nil {
		return Result{}, err
	}
	abs, err := filepath.Abs(opts.OutDir)
	if err != nil {
		return Result{}, fmt.Errorf("resolve out dir: %w", err)
	}

	if opts.Generated.IsZero() {
		opts.Generated = time.Now().UTC()
	}
	if opts.Period == "" {
		opts.Period = defaultPeriod(opts.Generated)
	}

	controls, err := groupByControl(findings)
	if err != nil {
		return Result{}, err
	}

	result := Result{
		OutDir:       abs,
		Generated:    opts.Generated,
		ControlIndex: map[string][]ControlRef{},
	}

	written, err := writeControlArtifacts(abs, controls, opts, &result)
	if err != nil {
		return Result{}, err
	}
	result.FilesWritten += written

	result.FrameworkResults = computeFrameworkResults(result.ControlIndex)

	mappingPath, err := writeMappingCSV(abs, controls, opts.Tailoring)
	if err != nil {
		return Result{}, err
	}
	result.MappingCSVPath = mappingPath
	result.FilesWritten++

	tailoringPath, err := writeTailoringJSON(abs, opts.Tailoring, opts)
	if err != nil {
		return Result{}, err
	}
	if tailoringPath != "" {
		result.TailoringPath = tailoringPath
		result.TailoringCount = opts.Tailoring.Count()
		result.FilesWritten++
	}

	summaryPath, err := writeSummaryHTML(abs, &result, opts)
	if err != nil {
		return Result{}, err
	}
	result.SummaryHTMLPath = summaryPath
	result.FilesWritten++

	manifestPath, err := WriteManifest(abs)
	if err != nil {
		return Result{}, err
	}
	result.ManifestPath = manifestPath
	result.FilesWritten++ // MANIFEST.sha256 itself

	return result, nil
}

// writeControlArtifacts creates the per-control directory tree and
// emits findings.json + control.md for each ControlRef. Returns the
// number of files written. The ControlIndex on result is populated
// here so downstream rollup helpers can read from a single source.
func writeControlArtifacts(root string, controls []ControlRef, opts Options, result *Result) (int, error) {
	count := 0
	for _, c := range controls {
		dir := filepath.Join(root, c.FrameworkID, c.DirName)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return count, fmt.Errorf("mkdir %s: %w", dir, err)
		}
		if err := writeFindingsJSON(filepath.Join(dir, "findings.json"), c, opts); err != nil {
			return count, err
		}
		count++
		if err := writeControlMarkdown(filepath.Join(dir, "control.md"), c, opts); err != nil {
			return count, err
		}
		count++
		result.ControlIndex[c.FrameworkID] = append(result.ControlIndex[c.FrameworkID], c)
	}
	return count, nil
}

// computeFrameworkResults rolls the per-control index up to a sorted
// per-framework summary. ControlsWithFail counts controls that have
// at least one actionable finding so the CLI footer can answer "how
// many controls have open work?".
func computeFrameworkResults(index map[string][]ControlRef) []FrameworkResult {
	out := make([]FrameworkResult, 0, len(index))
	for fwID, refs := range index {
		name := refs[0].FrameworkName
		failing := 0
		for _, c := range refs {
			for _, f := range c.Findings {
				if f.Status.IsActionable() {
					failing++
					break
				}
			}
		}
		out = append(out, FrameworkResult{
			FrameworkID:      fwID,
			FrameworkName:    name,
			ControlsCovered:  len(refs),
			ControlsWithFail: failing,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FrameworkID < out[j].FrameworkID })
	return out
}

// groupByControl walks every finding and emits one ControlRef per
// (framework, control) pair the underlying check references. A check
// referencing 2 frameworks * 3 controls each produces 6 ControlRef
// entries -- one finding can therefore appear in multiple control
// folders, which is exactly what an auditor needs: each control gets
// its own evidence even when one technical control satisfies several
// compliance controls.
//
// Unknown framework IDs and unknown control IDs are silently dropped
// (consistent with frameworks.ResolveCheckControls). Findings whose
// check has no framework mappings at all are also dropped -- the
// pack is organized by framework, so a finding with no framework
// home has no folder to live in.
//
// Output is sorted (framework ID, then control ID) so re-runs over
// identical input produce byte-identical pack contents.
func groupByControl(findings []core.Finding) ([]ControlRef, error) {
	type key struct{ fw, control string }
	bucket := map[key]*ControlRef{}

	all, err := frameworks.All()
	if err != nil {
		return nil, fmt.Errorf("load frameworks: %w", err)
	}

	for _, f := range findings {
		check, ok := core.LookupCheck(f.CheckID)
		if !ok {
			continue
		}
		for fwID, controlIDs := range check.Frameworks {
			fw, ok := all[fwID]
			if !ok {
				continue
			}
			for _, cid := range controlIDs {
				ctrl, ok := fw.Controls[cid]
				if !ok {
					continue
				}
				k := key{fwID, cid}
				ref, exists := bucket[k]
				if !exists {
					ref = &ControlRef{
						FrameworkID:   fw.ID,
						FrameworkName: fw.Name,
						ControlID:     ctrl.ID,
						ControlName:   ctrl.Name,
						DirName:       fmt.Sprintf("%s-%s", ctrl.ID, slugify(ctrl.Name)),
					}
					bucket[k] = ref
				}
				ref.Findings = append(ref.Findings, f)
			}
		}
	}

	out := make([]ControlRef, 0, len(bucket))
	for _, ref := range bucket {
		// Within a control, sort findings by (check_id, resource_id)
		// for byte-stable re-renders.
		sort.SliceStable(ref.Findings, func(i, j int) bool {
			if ref.Findings[i].CheckID != ref.Findings[j].CheckID {
				return ref.Findings[i].CheckID < ref.Findings[j].CheckID
			}
			return ref.Findings[i].Resource.ID < ref.Findings[j].Resource.ID
		})
		out = append(out, *ref)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FrameworkID != out[j].FrameworkID {
			return out[i].FrameworkID < out[j].FrameworkID
		}
		return out[i].ControlID < out[j].ControlID
	})
	return out, nil
}

// controlPayload is the JSON shape written to each
// <framework>/<control>/findings.json. It pins the schema version,
// the period, and the (framework, control) coordinates so the file is
// self-describing if an auditor exports a single control's folder.
type controlPayload struct {
	Schema        string         `json:"schema"`
	Generated     time.Time      `json:"generated_at"`
	Period        string         `json:"period"`
	FrameworkID   string         `json:"framework_id"`
	FrameworkName string         `json:"framework_name"`
	ControlID     string         `json:"control_id"`
	ControlName   string         `json:"control_name"`
	Findings      []core.Finding `json:"findings"`
}

func writeFindingsJSON(path string, c ControlRef, opts Options) error {
	payload := controlPayload{
		Schema:        schemaVersion,
		Generated:     opts.Generated,
		Period:        opts.Period,
		FrameworkID:   c.FrameworkID,
		FrameworkName: c.FrameworkName,
		ControlID:     c.ControlID,
		ControlName:   c.ControlName,
		Findings:      redactFindings(c.Findings, opts.IncludeRaw),
	}
	// G304: the path is constructed from operator-controlled OutDir
	// plus the framework / control slugs we just emitted -- not a
	// user-supplied input.
	//nolint:gosec // operator-controlled output path
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := writePrettyJSON(f, payload); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func writePrettyJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ensureEmptyDir succeeds when path either does not exist or exists
// and is an empty directory. We refuse to merge into a non-empty
// directory: a stale pack mixed with fresh output would break the
// manifest's tamper-evidence guarantee.
func ensureEmptyDir(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return os.MkdirAll(path, 0o750)
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("evidence: %s exists and is not a directory", path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("evidence: %s is not empty; pick a fresh directory", path)
	}
	return nil
}

// defaultPeriod produces a yyyy-Qn label from the timestamp. Chosen
// because audit-period boundaries are usually quarter-aligned and
// the label sorts lexicographically (handy when packs are listed
// side-by-side).
func defaultPeriod(t time.Time) string {
	q := (int(t.Month())-1)/3 + 1
	return fmt.Sprintf("%d-Q%d", t.Year(), q)
}
