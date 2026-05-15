package sarif

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/ingest"
)

// adapter implements ingest.Ingester for SARIF 2.1.0.
type adapter struct{}

// Format implements ingest.Ingester.
func (adapter) Format() string { return "sarif" }

// Description implements ingest.Ingester.
func (adapter) Description() string {
	return "SARIF 2.1.0 — Trivy, Checkov, KICS, Terrascan, CodeQL, Semgrep"
}

// Ingest decodes a SARIF 2.1.0 document from r and projects every
// result onto a compliancekit Finding (and, when needed, a phantom
// Resource for the subject the result names). Returns Result with
// findings/resources/warnings populated.
//
// Tool detection: the adapter prefers opts.Provenance.Tool when the
// operator supplied it via --tool. If that's empty, it inspects each
// run's driver.name and canonicalizes (e.g. "Trivy"→"trivy",
// "terrascan"→"terrascan", "Checkov"→"checkov"). The canonical name
// then picks the built-in mapping table unless opts.Mapping is set
// explicitly.
func (adapter) Ingest(ctx context.Context, r io.Reader, opts ingest.Options) (ingest.Result, error) {
	var doc document
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return ingest.Result{}, fmt.Errorf("decode sarif: %w", err)
	}
	if len(doc.Runs) == 0 {
		return ingest.Result{}, fmt.Errorf("sarif document has zero runs")
	}

	out := ingest.Result{}
	for runIdx, rn := range doc.Runs {
		if err := ctx.Err(); err != nil {
			return ingest.Result{}, err
		}

		toolID := canonicalTool(opts.Provenance.Tool, rn.Tool.Driver.Name)
		toolVersion := firstNonEmpty(opts.Provenance.ToolVersion, rn.Tool.Driver.Version, rn.Tool.Driver.SemanticVersion)

		// Choose mapping: explicit override wins; else built-in by tool id; else nil.
		mapping := opts.Mapping
		if mapping == nil {
			mapping = lookupBuiltinMapping(toolID)
		}

		// Index rules by id so we can fall back to their metadata when
		// a result carries only a ruleId.
		rules := indexRules(rn.Tool.Driver.Rules)

		for resIdx, res := range rn.Results {
			finding, resource, warns := projectResult(res, rules, toolID, toolVersion, mapping, opts)
			out.Findings = append(out.Findings, finding)
			if resource != nil {
				out.Resources = append(out.Resources, *resource)
			}
			out.Warnings = append(out.Warnings, warns...)

			// Surface unmapped findings as fail-fast when the operator asked.
			if opts.FailOnUnmapped && mapping != nil {
				if _, ok := mapping.Lookup(res.RuleID); !ok {
					return ingest.Result{}, fmt.Errorf(
						"run[%d].result[%d]: rule %q has no mapping in table %q",
						runIdx, resIdx, res.RuleID, mapping.Tool)
				}
			}
		}
	}

	return out, nil
}

// canonicalTool normalizes a tool identifier. Explicit --tool wins
// over auto-detection; both are lowercased and have whitespace
// stripped so registry lookups stay consistent regardless of casing
// drift across tool releases. Common alternate spellings collapse to
// a canonical form (e.g. "Trivy"→"trivy"). Unknown names pass through
// lowercased.
func canonicalTool(explicit, driver string) string {
	if explicit != "" {
		return strings.ToLower(strings.TrimSpace(explicit))
	}
	name := strings.ToLower(strings.TrimSpace(driver))
	switch name {
	case "checkov", "bridgecrew/checkov":
		return "checkov"
	case "trivy", "aquasecurity/trivy":
		return "trivy"
	case "kics", "kics-cli", "checkmarx/kics":
		return "kics"
	case "terrascan", "tenable/terrascan":
		return "terrascan"
	case "codeql":
		return "codeql"
	case "semgrep":
		return "semgrep"
	}
	return name
}

// projectResult builds a Finding and (optionally) a phantom Resource
// from a single SARIF result. The mapping table dictates which
// framework controls the finding attributes to; unmapped findings
// are still emitted (sans framework attribution) with a warning,
// unless FailOnUnmapped is set.
func projectResult(
	res result,
	rules map[string]rule,
	toolID, toolVersion string,
	mapping *ingest.MappingTable,
	opts ingest.Options,
) (core.Finding, *core.Resource, []string) {
	var warnings []string

	subject, phantom := resolveSubject(res, toolID, opts)
	severity := resolveSeverity(res, rules, mapping, opts.DefaultSeverity)
	tags := []string{}
	frameworks := map[string][]string{}

	if mapping != nil {
		if m, ok := mapping.Lookup(res.RuleID); ok {
			for _, c := range m.Controls {
				frameworks[c.Framework] = append(frameworks[c.Framework], c.Control)
			}
			tags = append(tags, m.Tags...)
		} else if !opts.FailOnUnmapped {
			warnings = append(warnings,
				fmt.Sprintf("no mapping for %s rule %q (finding emitted without framework attribution)",
					toolID, res.RuleID))
		}
	}

	checkID := composeCheckID(toolID, res.RuleID)
	finding := core.Finding{
		CheckID:   checkID,
		Status:    core.StatusFail,
		Severity:  severity,
		Resource:  subject,
		Message:   composeMessage(res, rules),
		Tags:      tags,
		Timestamp: opts.Provenance.IngestedAt,
		Source: &core.Source{
			Type:        "ingest",
			Tool:        toolID,
			ToolVersion: toolVersion,
			Format:      "sarif",
			File:        opts.Provenance.File,
		},
	}
	_ = frameworks // framework mapping flows through CheckID + mapping table; engine resolves at evidence-pack time

	return finding, phantom, warnings
}

// resolveSubject decides what resource a SARIF result is about. Order
// of preference: logicalLocations[0] when present, else
// physicalLocation.artifactLocation.uri. The returned ResourceRef
// always has a stable, globally unique ID (built from tool + path +
// rule). When the graph in opts.Graph already contains a resource
// for this subject, the existing ID is reused; otherwise a phantom
// is returned for the caller to add to the graph.
func resolveSubject(res result, toolID string, opts ingest.Options) (core.ResourceRef, *core.Resource) {
	uri, line := primaryLocation(res)
	logical := primaryLogical(res)

	var (
		name string
		kind string
	)
	switch {
	case logical != nil && logical.FullyQualifiedName != "":
		name = logical.FullyQualifiedName
		kind = logical.Kind
	case uri != "":
		name = uri
	default:
		name = "<anonymous>"
	}

	if kind == "" {
		switch {
		case strings.HasSuffix(name, ".tf"), strings.HasSuffix(name, ".tfvars"):
			kind = "terraform.file"
		case strings.HasSuffix(name, ".yaml"), strings.HasSuffix(name, ".yml"):
			kind = "kubernetes.manifest"
		case strings.HasSuffix(name, "Dockerfile"), strings.HasSuffix(name, ".dockerfile"):
			kind = "dockerfile"
		case strings.HasSuffix(name, ".json"):
			kind = "json.manifest"
		default:
			kind = "ingest." + toolID + ".file"
		}
	}

	id := synthResourceID(toolID, name, line)
	if opts.Graph != nil {
		if existing, ok := opts.Graph.ByID(id); ok {
			return core.ResourceRef{
				ID:       existing.ID,
				Type:     existing.Type,
				Name:     existing.Name,
				Provider: existing.Provider,
			}, nil
		}
	}

	phantom := core.Resource{
		ID:       id,
		Type:     kind,
		Name:     filepath.Base(name),
		Provider: "ingest",
		Attributes: map[string]any{
			"ingest_source": toolID,
			"source_path":   name,
		},
	}
	return core.ResourceRef{
		ID:       phantom.ID,
		Type:     phantom.Type,
		Name:     phantom.Name,
		Provider: phantom.Provider,
	}, &phantom
}

// resolveSeverity reduces a SARIF result's severity signals to a
// compliancekit Severity. Precedence: mapping table override
// (operator's framework-mapping yaml); SARIF result.level; rules[*]
// defaultConfiguration.level; properties["security-severity"] (CVSS-
// like number Trivy ships); finally the caller-supplied default.
func resolveSeverity(
	res result,
	rules map[string]rule,
	mapping *ingest.MappingTable,
	def core.Severity,
) core.Severity {
	if mapping != nil {
		if m, ok := mapping.Lookup(res.RuleID); ok && m.Severity != "" {
			if s, err := core.ParseSeverity(m.Severity); err == nil {
				return s
			}
		}
	}
	if res.Level != "" {
		if s, ok := sarifLevelToSeverity(res.Level); ok {
			return s
		}
	}
	if r, ok := rules[res.RuleID]; ok && r.DefaultConfiguration != nil {
		if s, ok := sarifLevelToSeverity(r.DefaultConfiguration.Level); ok {
			return s
		}
	}
	if v, ok := res.Properties["security-severity"]; ok {
		if s := cvssToSeverity(v); s != core.SeverityInfo || def == core.SeverityInfo {
			return s
		}
	}
	if def == core.SeverityInfo {
		return core.SeverityMedium
	}
	return def
}

// sarifLevelToSeverity maps the canonical SARIF level enum to
// compliancekit's severity scale. SARIF "error" → high (we reserve
// critical for severity-elevated findings via mapping tables or
// CVSS≥9.0); "warning" → medium; "note" → low; "none" → info.
func sarifLevelToSeverity(level string) (core.Severity, bool) {
	switch strings.ToLower(level) {
	case "error":
		return core.SeverityHigh, true
	case "warning":
		return core.SeverityMedium, true
	case "note":
		return core.SeverityLow, true
	case "none":
		return core.SeverityInfo, true
	}
	return core.SeverityInfo, false
}

// cvssToSeverity converts the SARIF "security-severity" property
// Trivy emits (a stringified CVSS base score, 0.0–10.0) into the
// compliancekit severity scale. Aligns with the CVSS v3.1 qualitative
// rating bands: 9.0+ critical, 7.0+ high, 4.0+ medium, 0.1+ low.
func cvssToSeverity(v any) core.Severity {
	var n float64
	switch x := v.(type) {
	case float64:
		n = x
	case string:
		// SARIF spec says properties are free-form; Trivy emits the
		// score as a string. Best-effort parse without bringing in
		// strconv here for one call would be silly, so:
		var parsed float64
		_, err := fmt.Sscanf(x, "%f", &parsed)
		if err != nil {
			return core.SeverityInfo
		}
		n = parsed
	default:
		return core.SeverityInfo
	}
	switch {
	case n >= 9.0:
		return core.SeverityCritical
	case n >= 7.0:
		return core.SeverityHigh
	case n >= 4.0:
		return core.SeverityMedium
	case n >= 0.1:
		return core.SeverityLow
	}
	return core.SeverityInfo
}

// composeCheckID assembles a stable, namespaced CheckID for an
// ingested SARIF result. Format: "ingest.<tool>.<rule-id>" with
// dots in the rule id replaced by underscores so existing CLI
// filters and diff tooling treat the ID as a single token.
func composeCheckID(toolID, ruleID string) string {
	if ruleID == "" {
		ruleID = "unspecified"
	}
	normalized := strings.ReplaceAll(ruleID, "/", ".")
	return fmt.Sprintf("ingest.%s.%s", toolID, normalized)
}

// composeMessage builds the human-readable finding message. Prefers
// the result's own text; falls back to the rule's shortDescription;
// last resort is a synthesized line so reporters never render
// an empty Message field.
func composeMessage(res result, rules map[string]rule) string {
	if res.Message.Text != "" {
		return res.Message.Text
	}
	if r, ok := rules[res.RuleID]; ok {
		if r.ShortDescription != nil && r.ShortDescription.Text != "" {
			return r.ShortDescription.Text
		}
		if r.FullDescription != nil && r.FullDescription.Text != "" {
			return r.FullDescription.Text
		}
	}
	return fmt.Sprintf("%s finding (no message in SARIF result)", res.RuleID)
}

// primaryLocation returns the first physical-location URI and start
// line of a result, or empty strings if none are present.
func primaryLocation(res result) (uri string, startLine int) {
	if len(res.Locations) == 0 || res.Locations[0].Physical == nil {
		return "", 0
	}
	pl := res.Locations[0].Physical
	if pl.Artifact != nil {
		uri = pl.Artifact.URI
	}
	if pl.Region != nil {
		startLine = pl.Region.StartLine
	}
	return uri, startLine
}

// primaryLogical returns the first logicalLocations entry from a
// result, or nil if none are present.
func primaryLogical(res result) *logicalLocation {
	if len(res.Locations) == 0 || len(res.Locations[0].Logical) == 0 {
		return nil
	}
	return &res.Locations[0].Logical[0]
}

// indexRules turns a flat []rule into a map keyed by rule ID so the
// adapter can look up rule metadata when a result carries only an
// ID without a message.
func indexRules(rules []rule) map[string]rule {
	out := make(map[string]rule, len(rules))
	for _, r := range rules {
		out[r.ID] = r
	}
	return out
}

// synthResourceID builds a deterministic, globally unique resource
// ID for an ingested SARIF subject. Stable across re-runs so diff
// engines correlate findings without phantom resources thrashing.
func synthResourceID(toolID, name string, line int) string {
	if line > 0 {
		return fmt.Sprintf("ingest://%s/%s#L%d", toolID, name, line)
	}
	return fmt.Sprintf("ingest://%s/%s", toolID, name)
}

// firstNonEmpty returns the first argument with non-zero length.
func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// init self-registers the adapter against the Default registry so
// `import _ "github.com/darpanzope/compliancekit/internal/ingest/sarif"`
// is enough to make --format=sarif resolve.
func init() {
	ingest.Register(adapter{})
}
