// Package report holds the Reporter implementations.
//
// One file per output format: json.go, html.go (v0.3), sarif.go (v0.3),
// markdown.go (v0.3), ocsf.go (v0.3), evidence.go (v0.4).
//
// Reporters are stateless. The scan command builds the active set from
// config.Output.Format and runs each against the same findings.
package report

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
)

// FormatJSON is the lowercase identifier used in config files and the
// --output flag.
const FormatJSON = "json"

// schemaVersion is included in every JSON output so consumers can
// detect schema drift across compliancekit versions.
const schemaVersion = "compliancekit.v1"

// JSONReporter renders findings as pretty-printed JSON with a top-level
// envelope containing schema version, generation timestamp, summary
// counts, and the findings array.
type JSONReporter struct{}

// NewJSON returns a JSON reporter. Stateless; reusable across scans.
func NewJSON() *JSONReporter { return &JSONReporter{} }

// Format implements core.Reporter.
func (r *JSONReporter) Format() string { return FormatJSON }

// Render implements core.Reporter. The graph parameter is currently
// unused by the JSON reporter but is part of the contract; v0.4's
// evidence pack reporter relies on it.
func (r *JSONReporter) Render(_ context.Context, findings []core.Finding, _ *core.ResourceGraph, w io.Writer) error {
	envelope := jsonEnvelope{
		Schema:    schemaVersion,
		Generated: time.Now().UTC(),
		Summary:   computeSummary(findings),
		Findings:  findings,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}

// New returns the Reporter for the given format identifier, or an error
// when the format is unknown. The scan command uses this factory to
// build the active reporter set from config.Output.Format.
func New(format string) (core.Reporter, error) {
	switch format {
	case FormatJSON:
		return NewJSON(), nil
	default:
		return nil, fmt.Errorf("unknown output format %q", format)
	}
}

// jsonEnvelope is the top-level shape of JSON output. Stable across
// patch releases of compliancekit; breaking changes bump schemaVersion.
type jsonEnvelope struct {
	Schema    string         `json:"schema"`
	Generated time.Time      `json:"generated_at"`
	Summary   summary        `json:"summary"`
	Findings  []core.Finding `json:"findings"`
}

// summary aggregates findings counts. Keys are stable strings so
// consumers can index into by_status / by_severity without enum decode.
type summary struct {
	Total      int            `json:"total"`
	ByStatus   map[string]int `json:"by_status"`
	BySeverity map[string]int `json:"by_severity"`
}

func computeSummary(findings []core.Finding) summary {
	s := summary{
		Total:      len(findings),
		ByStatus:   make(map[string]int),
		BySeverity: make(map[string]int),
	}
	for _, f := range findings {
		s.ByStatus[string(f.Status)]++
		s.BySeverity[f.Severity.String()]++
	}
	return s
}
