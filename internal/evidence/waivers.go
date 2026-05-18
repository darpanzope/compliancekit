package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// waiversJSONName is the per-pack artifact filename. Lives at the
// pack root next to vulnerabilities.csv + control-mapping.csv so
// auditors find it via the same `ls` command.
const waiversJSONName = "waivers.json"

// writeWaiversJSON emits <out>/waivers.json containing every
// waiver-muted finding from the scan. Skips writing when no
// waivers were applied — empty packs don't need the file.
//
// Schema (stable across pack-schema v1; governed by SemVer once
// v1.0 freezes the API):
//
//	{
//	  "schema":   "compliancekit.waivers.v1",
//	  "count":    N,
//	  "entries": [
//	    {
//	      "check_id":    "...",
//	      "resource_id": "...",
//	      "reason":      "...",
//	      "approver":    "...",
//	      "expires":     "2026-12-31T00:00:00Z",
//	      "source":      "file" | "annotation",
//	      "source_path": "waivers.yaml" or "main.tf:42",
//	      "finding":     { full compliancekit.Finding for cross-reference }
//	    }
//	  ]
//	}
//
// One entry per muted finding (not per waiver) so an auditor can
// trace exactly which resources a waiver covered during this run.
// Synthesized `compliancekit-waiver-expired` info-findings also
// appear in this artifact so the lapse audit-trail is one file.
func writeWaiversJSON(outDir string, findings []compliancekit.Finding) (string, error) {
	entries := make([]waiverEntry, 0)
	for _, f := range findings {
		if f.Waiver == nil {
			continue
		}
		entries = append(entries, waiverEntry{
			CheckID:    f.Waiver.CheckID,
			ResourceID: f.Waiver.ResourceID,
			Reason:     f.Waiver.Reason,
			Approver:   f.Waiver.Approver,
			Expires:    f.Waiver.Expires.Format("2006-01-02T15:04:05Z07:00"),
			Source:     f.Waiver.Source,
			SourcePath: f.Waiver.SourcePath,
			Finding:    f,
		})
	}
	if len(entries) == 0 {
		return "", nil
	}
	// Stable order across runs (CheckID then ResourceID).
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].CheckID != entries[j].CheckID {
			return entries[i].CheckID < entries[j].CheckID
		}
		return entries[i].ResourceID < entries[j].ResourceID
	})

	doc := waiverDoc{
		Schema:  "compliancekit.waivers.v1",
		Count:   len(entries),
		Entries: entries,
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("waivers.json marshal: %w", err)
	}
	path := filepath.Join(outDir, waiversJSONName)
	// #nosec G306 — evidence-pack artifact; mode matches other writers.
	if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
		return "", fmt.Errorf("waivers.json write: %w", err)
	}
	return path, nil
}

type waiverDoc struct {
	Schema  string        `json:"schema"`
	Count   int           `json:"count"`
	Entries []waiverEntry `json:"entries"`
}

type waiverEntry struct {
	CheckID    string                `json:"check_id"`
	ResourceID string                `json:"resource_id"`
	Reason     string                `json:"reason"`
	Approver   string                `json:"approver"`
	Expires    string                `json:"expires"`
	Source     string                `json:"source,omitempty"`
	SourcePath string                `json:"source_path,omitempty"`
	Finding    compliancekit.Finding `json:"finding"`
}
