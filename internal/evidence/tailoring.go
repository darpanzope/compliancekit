package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/darpanzope/compliancekit/internal/frameworks"
)

// tailoringJSONName is the filename written at the pack root carrying
// the operator's per-control scope-out decisions and their auditor-
// facing justifications. Auditors who want to know "why is PCI 10.6.1
// not in scope" open this file rather than guessing from absence.
const tailoringJSONName = "tailoring.json"

// tailoringPayload is the JSON shape written to <out>/tailoring.json.
// Schema versioned so consumers can detect drift.
type tailoringPayload struct {
	Schema    string                  `json:"schema"`
	Generated time.Time               `json:"generated_at"`
	Period    string                  `json:"period"`
	Count     int                     `json:"count"`
	Rules     []tailoringPayloadEntry `json:"rules"`
}

type tailoringPayloadEntry struct {
	FrameworkID   string `json:"framework_id"`
	FrameworkName string `json:"framework_name,omitempty"`
	ControlID     string `json:"control_id"`
	ControlName   string `json:"control_name,omitempty"`
	Justification string `json:"justification"`
}

// writeTailoringJSON writes the operator's tailoring rules to the pack
// root. Returns the absolute path written, or "" + nil if there are no
// tailoring rules to record. Resolves framework + control names from
// the loaded catalog so an auditor opening tailoring.json without the
// scanner sees the human-readable label, not just an opaque ID.
func writeTailoringJSON(outDir string, t *frameworks.Tailoring, opts Options) (string, error) {
	if t == nil || t.Count() == 0 {
		return "", nil
	}
	all, err := frameworks.All()
	if err != nil {
		return "", fmt.Errorf("load frameworks for tailoring: %w", err)
	}

	entries := make([]tailoringPayloadEntry, 0, t.Count())
	for _, r := range t.Rules {
		entry := tailoringPayloadEntry{
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
		entries = append(entries, entry)
	}

	payload := tailoringPayload{
		Schema:    schemaVersion,
		Generated: opts.Generated,
		Period:    opts.Period,
		Count:     len(entries),
		Rules:     entries,
	}
	path := filepath.Join(outDir, tailoringJSONName)
	// G304: outDir is operator-controlled and the filename is constant.
	//nolint:gosec // operator-controlled output path
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}
