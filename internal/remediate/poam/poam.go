// Package poam emits OSCAL v1.1.2 Plan of Action & Milestones (POA&M)
// JSON for findings whose remediation classifies as manual — either
// because no strategy is registered, or because the registered
// strategy declared RiskManual.
//
// The POA&M is the canonical compliance-audit artifact for "we know
// about it; here is the human action we have queued." Auditors
// expect one POA&M entry per non-fixable finding, with a stable UUID
// (so the entry survives across scans) and a control reference (so
// reviewers can pair the open action to the framework requirement
// it bears on).
//
// UUIDs are derived via the same SHA-256-prefix algorithm as the AR
// emitter in internal/evidence/oscal.go so a finding's identity stays
// stable across re-runs.
package poam

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/frameworks"
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Write generates poam.oscal.json under root from the findings whose
// remediation is manual. Returns the absolute path to the written
// file. Caller is responsible for ensuring root exists.
//
// "Manual" = strategy returned RiskManual OR no strategy was
// registered for the CheckID. Snippets is the slice the caller built
// via remediate.Default.RenderAll (or equivalent); unmatched is the
// findings slice the caller couldn't render at all. Both feed into
// the POA&M list — Snippet-with-RiskManual entries carry the
// strategy's Notes prose; unmatched-finding entries carry the
// finding's Message.
func Write(root string, manualSnippets []remediate.Snippet, unmatched []compliancekit.Finding, opts Options) (string, error) {
	if root == "" {
		return "", fmt.Errorf("poam: empty root")
	}
	doc := build(manualSnippets, unmatched, opts)
	path := filepath.Join(root, "poam.oscal.json")
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("poam: encode: %w", err)
	}
	// #nosec G306 — POA&M is a regular evidence-pack artifact.
	if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
		return "", fmt.Errorf("poam: write: %w", err)
	}
	return path, nil
}

// Options carries metadata passed through to the OSCAL header. All
// fields are optional; sensible defaults apply.
type Options struct {
	// GeneratedAt is the document's last-modified timestamp. Defaults
	// to time.Now() when zero — tests pass a fixed time.
	GeneratedAt time.Time
	// Period is the assessment period the POA&M corresponds to,
	// e.g. "2026-Q2". Threaded into UUID derivation for stability.
	Period string
	// Project optionally identifies the assessment subject; appears
	// in metadata.title. Defaults to "compliancekit".
	Project string
}

// build is the pure function the test suite exercises. It produces
// the document structure; Write serializes it.
func build(manualSnippets []remediate.Snippet, unmatched []compliancekit.Finding, opts Options) document {
	generated := opts.GeneratedAt
	if generated.IsZero() {
		generated = time.Now().UTC()
	}
	project := opts.Project
	if project == "" {
		project = "compliancekit"
	}
	period := periodOrDefault(opts.Period, generated)

	doc := document{
		PlanOfActionAndMilestones: poam{
			UUID: uuidFromContent("poam", project, period),
			Metadata: metadata{
				Title:        fmt.Sprintf("%s — Plan of Action & Milestones (%s)", project, period),
				LastModified: generated.Format(time.RFC3339),
				Version:      "1.0",
				OSCALVersion: "1.1.2",
			},
			Items: itemsFor(manualSnippets, unmatched, project, period),
		},
	}
	return doc
}

// itemsFor walks the inputs and produces sorted POA&M entries. Sort
// is by (CheckID, Resource.ID) for deterministic ordering.
func itemsFor(snippets []remediate.Snippet, unmatched []compliancekit.Finding, project, period string) []poamItem {
	type seed struct {
		checkID    string
		resourceID string
		notes      string
		message    string
		severity   string
		controls   []string
	}
	seeds := make([]seed, 0, len(snippets)+len(unmatched))

	for _, sn := range snippets {
		if sn.Risk != remediate.RiskManual {
			continue
		}
		s := seed{
			checkID:    sn.CheckID,
			resourceID: sn.Resource.ID,
			notes:      sn.Notes,
			controls:   controlIDsForCheck(sn.CheckID),
		}
		seeds = append(seeds, s)
	}
	for _, f := range unmatched {
		s := seed{
			checkID:    f.CheckID,
			resourceID: f.Resource.ID,
			notes:      "no remediation strategy registered for this CheckID",
			message:    f.Message,
			severity:   f.Severity.String(),
			controls:   controlIDsForCheck(f.CheckID),
		}
		seeds = append(seeds, s)
	}

	sort.SliceStable(seeds, func(i, j int) bool {
		if seeds[i].checkID != seeds[j].checkID {
			return seeds[i].checkID < seeds[j].checkID
		}
		return seeds[i].resourceID < seeds[j].resourceID
	})

	items := make([]poamItem, 0, len(seeds))
	for _, s := range seeds {
		item := poamItem{
			UUID:        uuidFromContent("poam-item", project, period, s.checkID, s.resourceID),
			Title:       fmt.Sprintf("Manual remediation: %s on %s", s.checkID, s.resourceID),
			Description: buildDescription(s.message, s.notes),
			Props: []prop{
				{Name: "check-id", Value: s.checkID},
				{Name: "resource-id", Value: s.resourceID},
				{Name: "severity", Value: stringOr(s.severity, "unknown")},
				{Name: "status", Value: "open"},
			},
		}
		for _, c := range s.controls {
			item.Props = append(item.Props, prop{Name: "related-control", Value: c})
		}
		items = append(items, item)
	}
	return items
}

func buildDescription(message, notes string) string {
	var parts []string
	if message != "" {
		parts = append(parts, message)
	}
	if notes != "" {
		parts = append(parts, notes)
	}
	if len(parts) == 0 {
		return "Manual remediation required."
	}
	return strings.Join(parts, "\n\n")
}

func stringOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// controlIDsForCheck resolves the framework controls the check
// satisfies, formatted as "framework:control". Returns an empty
// slice when the check is not registered in the catalog (e.g.
// ingest-only CheckIDs that don't appear in compliancekit.LookupCheck).
func controlIDsForCheck(checkID string) []string {
	c, ok := compliancekit.LookupCheck(checkID)
	if !ok {
		return nil
	}
	out := make([]string, 0, 8)
	for fwID, ctrls := range c.Frameworks {
		_, knownFW := frameworks.Get(fwID)
		if !knownFW {
			continue
		}
		for _, ctrl := range ctrls {
			out = append(out, fmt.Sprintf("%s:%s", fwID, ctrl))
		}
	}
	sort.Strings(out)
	return out
}

func periodOrDefault(period string, generated time.Time) string {
	if period != "" {
		return period
	}
	q := (int(generated.Month())-1)/3 + 1
	return fmt.Sprintf("%d-Q%d", generated.Year(), q)
}

// uuidFromContent is the same UUID-v5-from-SHA-256 helper used by
// internal/evidence/oscal.go. Mirrored here to keep this package
// dependency-free of the evidence package.
func uuidFromContent(parts ...string) string {
	h := sha256.New()
	h.Write([]byte(strings.Join(parts, "|")))
	digest := h.Sum(nil)[:16]
	digest[6] = (digest[6] & 0x0f) | 0x50
	digest[8] = (digest[8] & 0x3f) | 0x80
	hx := hex.EncodeToString(digest)
	return fmt.Sprintf("%s-%s-%s-%s-%s", hx[0:8], hx[8:12], hx[12:16], hx[16:20], hx[20:32])
}

// OSCAL POA&M document model (minimal subset matching v1.1.2 schema
// required fields and the props array we populate).

type document struct {
	PlanOfActionAndMilestones poam `json:"plan-of-action-and-milestones"`
}

type poam struct {
	UUID     string     `json:"uuid"`
	Metadata metadata   `json:"metadata"`
	Items    []poamItem `json:"poam-items"`
}

type metadata struct {
	Title        string `json:"title"`
	LastModified string `json:"last-modified"`
	Version      string `json:"version"`
	OSCALVersion string `json:"oscal-version"`
}

type poamItem struct {
	UUID        string `json:"uuid"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Props       []prop `json:"props,omitempty"`
}

type prop struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
