// Package baseline reads and writes the baseline file that the v0.6
// drift workflow compares against. A baseline is the operator's
// declared "this is what's expected to be there." The next scan's
// findings are classified as new (not in baseline) / existing (same
// fingerprint) / resolved (in baseline but not in current scan).
//
// File location convention: `.compliancekit/baseline.json` in the
// scan working directory. Gitignored by default; commit it
// deliberately if you want PR-level drift gating.
//
// Schema versioning is explicit (`compliancekit.baseline.v1`) so a
// future change (waivers folded in, fingerprint salt added, etc.)
// can bump the schema without silently invalidating older files.
package baseline

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/darpanzope/compliancekit/internal/score"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// SchemaVersion pins the on-disk format. Bump on any breaking change.
const SchemaVersion = "compliancekit.baseline.v1"

// DefaultPath is the conventional baseline location relative to the
// scan working directory.
const DefaultPath = ".compliancekit/baseline.json"

// Baseline is the on-disk shape. CapturedAt + the score / coverage
// numbers double as a quick "is this baseline still fresh" sniff
// test; Entries is what the diff command joins against.
type Baseline struct {
	Schema     string    `json:"schema"`
	CapturedAt time.Time `json:"captured_at"`
	Score      int       `json:"score"`
	Coverage   int       `json:"coverage"`
	Entries    []Entry   `json:"entries"`
}

// Entry is one finding's worth of state captured in the baseline.
// Fingerprint is the join key with future scans; the surrounding
// fields are kept so the diff command can render meaningful output
// without re-loading the original scan ("- 1 resolved: high
// do-droplet-no-firewall on web-1" beats "- 1 resolved").
//
// The fields here MUST be a subset of compliancekit.Finding's stable shape;
// regenerating a baseline against a finding whose CheckID or
// resource changed is the correct "this is a different finding"
// signal because Fingerprint will differ.
type Entry struct {
	Fingerprint  string                 `json:"fingerprint"`
	CheckID      string                 `json:"check_id"`
	Severity     compliancekit.Severity `json:"severity"`
	Status       compliancekit.Status   `json:"status"`
	ResourceID   string                 `json:"resource_id"`
	ResourceName string                 `json:"resource_name"`
	ResourceType string                 `json:"resource_type"`
}

// Capture builds a Baseline from a slice of findings + the current
// timestamp. The slice is de-duplicated by fingerprint -- a finding
// referenced under multiple framework controls collapses to one
// entry, matching how the evidence pack already counts it.
//
// Entries are sorted by (fingerprint) for byte-stable re-renders --
// two captures of the same input produce byte-identical files,
// which makes the baseline diffable in `git diff` itself.
func Capture(findings []compliancekit.Finding, at time.Time) Baseline {
	seen := map[string]struct{}{}
	entries := []Entry{}
	for _, f := range findings {
		fp := f.Fingerprint()
		if _, dup := seen[fp]; dup {
			continue
		}
		seen[fp] = struct{}{}
		entries = append(entries, Entry{
			Fingerprint:  fp,
			CheckID:      f.CheckID,
			Severity:     f.Severity,
			Status:       f.Status,
			ResourceID:   f.Resource.ID,
			ResourceName: f.Resource.Name,
			ResourceType: f.Resource.Type,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Fingerprint < entries[j].Fingerprint
	})

	s := score.Compute(findings)
	return Baseline{
		Schema:     SchemaVersion,
		CapturedAt: at.UTC(),
		Score:      s.Score,
		Coverage:   s.Coverage,
		Entries:    entries,
	}
}

// Save writes the baseline to path, creating any parent directories
// at 0o750. The file itself is 0o600 since baselines may carry
// resource IDs / names that some operators consider sensitive.
func Save(b Baseline, path string) error {
	if err := os.MkdirAll(parentDir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir for baseline: %w", err)
	}
	// G304: path is operator-controlled (default DefaultPath or
	// --out flag); not a user-supplied input.
	//nolint:gosec // operator-controlled output path
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(b); err != nil {
		return fmt.Errorf("encode baseline: %w", err)
	}
	return nil
}

// Load reads a baseline from path. Returns an error if the file is
// missing, malformed, or has a schema string we do not recognize.
func Load(path string) (Baseline, error) {
	// G304: path is operator-controlled.
	//nolint:gosec // operator-controlled input path
	data, err := os.ReadFile(path)
	if err != nil {
		return Baseline{}, fmt.Errorf("read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse decodes a baseline from raw bytes. Split from Load so tests
// (and the diff command) can validate in-memory blobs without
// touching disk.
func Parse(data []byte) (Baseline, error) {
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return Baseline{}, fmt.Errorf("parse baseline: %w", err)
	}
	if b.Schema != SchemaVersion {
		return Baseline{}, fmt.Errorf("baseline schema %q is not supported (this build expects %q)", b.Schema, SchemaVersion)
	}
	return b, nil
}

// WriteJSON serializes a baseline to w in the canonical indented
// form. Used by tests; production code should call Save() directly.
func WriteJSON(b Baseline, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(b)
}

// FingerprintSet returns the entries indexed by fingerprint. Used
// by the diff command to join a current scan's findings against
// this baseline in O(n).
func (b Baseline) FingerprintSet() map[string]Entry {
	out := make(map[string]Entry, len(b.Entries))
	for _, e := range b.Entries {
		out[e.Fingerprint] = e
	}
	return out
}

// parentDir returns the directory portion of path. Tiny helper to
// avoid pulling filepath at this layer when the only need is the
// mkdir for the baseline output.
func parentDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			if i == 0 {
				return string(path[0])
			}
			return path[:i]
		}
	}
	return "."
}
