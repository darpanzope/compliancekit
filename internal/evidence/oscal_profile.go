package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/darpanzope/compliancekit/internal/frameworks"
)

const (
	// profileFileName is the filename written into the evidence pack
	// root. Per OSCAL convention the suffix is `.oscal.json` so
	// validators auto-detect the schema family.
	profileFileName = "profile.oscal.json"

	// catalogHrefBase is the per-framework URI used in profile
	// imports[].href. Since compliancekit's embedded frameworks
	// don't have published OSCAL catalog documents at this URL
	// yet, the value is a stable, monotonic reference that
	// downstream tooling can resolve manually or use as an opaque
	// identifier. v0.14+ may publish actual OSCAL catalogs and
	// retarget this base.
	catalogHrefBase = "https://github.com/darpanzope/compliancekit/blob/main/internal/frameworks/"
)

// writeProfileOSCAL writes an OSCAL Profile v1.1.2 document derived
// from the scan's framework set + tailoring. Lands as
// <pack>/profile.oscal.json. Returns the absolute path of the
// written file.
//
// One Import entry per framework the scan covered. Tailored controls
// (operator scope-outs) are emitted under exclude-controls so the
// Profile cleanly expresses "we assessed framework X except for
// these controls"; the AR emit (writeAssessmentResultsOSCAL) carries
// the per-tailoring justification, and the two documents reference
// the same control IDs for cross-doc auditor navigation.
func writeProfileOSCAL(root string, result *Result, opts Options) (string, error) {
	doc := buildProfile(result, opts)

	path := filepath.Join(root, profileFileName)
	f, err := os.Create(path) //nolint:gosec // root is operator-supplied evidence dir
	if err != nil {
		return "", fmt.Errorf("create %s: %w", path, err)
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("encode oscal-profile: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close %s: %w", path, err)
	}
	abs, _ := filepath.Abs(path)
	return abs, nil
}

func buildProfile(result *Result, opts Options) profileDocument {
	generated := opts.Generated
	if generated.IsZero() {
		generated = time.Now().UTC()
	}

	// Build per-framework exclusions from the tailoring rules.
	exclusions := map[string][]string{}
	if opts.Tailoring != nil {
		for _, rule := range opts.Tailoring.Rules {
			exclusions[rule.Framework] = append(exclusions[rule.Framework], rule.Control)
		}
	}

	// Build the set of frameworks the scan actually covered (any
	// control had at least one finding). Falls back to the
	// tailoring frameworks if the result lacks framework rollups
	// (e.g. zero actionable findings — Profile still meaningful for
	// "we scoped X out of Y").
	frameworkIDs := map[string]bool{}
	for _, fr := range result.FrameworkResults {
		frameworkIDs[fr.FrameworkID] = true
	}
	for fwID := range exclusions {
		frameworkIDs[fwID] = true
	}

	ids := make([]string, 0, len(frameworkIDs))
	for id := range frameworkIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	imports := make([]profileImport, 0, len(ids))
	for _, fwID := range ids {
		imp := profileImport{
			Href:       catalogHrefBase + fwID + ".yaml",
			IncludeAll: &profileIncludeAll{},
		}
		if excluded := exclusions[fwID]; len(excluded) > 0 {
			sort.Strings(excluded)
			imp.ExcludeControls = []profileExcludeControl{
				{WithIDs: excluded},
			}
		}
		// Include the framework's display name for human readers
		// of the profile.
		if fw, ok := frameworks.Get(fwID); ok {
			imp.Props = []arProp{
				{Name: "compliancekit-framework-id", Value: fwID},
				{Name: "compliancekit-framework-name", Value: fw.Name},
			}
			if fw.Version != "" {
				imp.Props = append(imp.Props, arProp{Name: "compliancekit-framework-version", Value: fw.Version})
			}
		}
		imports = append(imports, imp)
	}

	return profileDocument{
		Profile: profile{
			UUID: uuidFromContent("profile", generated.Format(time.RFC3339Nano), opts.Period),
			Metadata: arMetadata{
				Title:        fmt.Sprintf("compliancekit assessment profile — %s", periodOrDefault(opts.Period, generated)),
				LastModified: generated.UTC().Format(time.RFC3339),
				Version:      schemaVersion,
				OSCALVersion: oscalVersion,
			},
			Imports: imports,
		},
	}
}

// OSCAL Profile document model (subset of v1.1.2).

type profileDocument struct {
	Profile profile `json:"profile"`
}

type profile struct {
	UUID     string          `json:"uuid"`
	Metadata arMetadata      `json:"metadata"`
	Imports  []profileImport `json:"imports"`
}

type profileImport struct {
	Href            string                  `json:"href"`
	IncludeAll      *profileIncludeAll      `json:"include-all,omitempty"`
	IncludeControls []profileIncludeControl `json:"include-controls,omitempty"`
	ExcludeControls []profileExcludeControl `json:"exclude-controls,omitempty"`
	Props           []arProp                `json:"props,omitempty"`
}

type profileIncludeAll struct{}

type profileIncludeControl struct {
	WithIDs []string `json:"with-ids,omitempty"`
}

type profileExcludeControl struct {
	WithIDs []string `json:"with-ids,omitempty"`
}
