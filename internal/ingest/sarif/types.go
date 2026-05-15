// Package sarif implements the SARIF 2.1.0 ingest adapter for
// compliancekit. SARIF (Static Analysis Results Interchange Format)
// is the OASIS-standardized JSON envelope produced by Trivy, Checkov,
// KICS, Terrascan, GitHub CodeQL, Semgrep, and most modern security
// scanners. v0.13+ ingest pipeline turns each SARIF result into a
// compliancekit Finding, attributing it to framework controls via a
// per-tool mapping table.
//
// The package self-registers an "sarif" adapter with internal/ingest's
// Default registry at init() time. Importing it as a side-effect
// (blank import) is the standard way to make `compliancekit ingest
// --format=sarif` light up.
package sarif

// document is the top-level SARIF 2.1.0 envelope. We decode only the
// fields the adapter consumes; unknown JSON fields are silently
// preserved by json.Unmarshal, which keeps the parser tolerant of
// schema-version drift across tool releases.
type document struct {
	Schema  string `json:"$schema,omitempty"`
	Version string `json:"version,omitempty"`
	Runs    []run  `json:"runs"`
}

// run is one tool invocation. A single SARIF file may contain multiple
// runs (e.g. when stitched from several tool outputs), so the adapter
// iterates Runs and treats each independently for tool-name detection
// and rule lookup.
type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

// tool identifies the producing scanner. We only consult
// tool.driver.name and tool.driver.version; tool.driver.rules[] gives
// us richer rule-metadata fallbacks when a result has only a ruleId.
type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	SemanticVersion string `json:"semanticVersion,omitempty"`
	InformationURI  string `json:"informationUri,omitempty"`
	Rules           []rule `json:"rules,omitempty"`
}

// rule is one scanner rule definition. SARIF stores it once in
// driver.rules[] and references it by index OR id from individual
// results. The adapter prefers result.RuleID when set; the rules[]
// table provides fall-back metadata for richer message text.
type rule struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name,omitempty"`
	ShortDescription     *multiformatString `json:"shortDescription,omitempty"`
	FullDescription      *multiformatString `json:"fullDescription,omitempty"`
	Help                 *multiformatString `json:"help,omitempty"`
	HelpURI              string             `json:"helpUri,omitempty"`
	DefaultConfiguration *configuration     `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any     `json:"properties,omitempty"`
}

type configuration struct {
	Level string `json:"level,omitempty"`
}

// multiformatString matches SARIF's multiformatMessageString shape:
// a text variant required, an optional markdown variant. The adapter
// prefers text and falls back to markdown when only that's set.
type multiformatString struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

// result is the heart of SARIF: one finding from the producing tool.
// We extract ruleId, level, message.text, locations[0], and the
// free-form properties dict — every modern tool populates these.
type result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex,omitempty"`
	Level               string            `json:"level,omitempty"`
	Message             message           `json:"message"`
	Locations           []location        `json:"locations,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type message struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

// location describes the subject of a finding. Physical points at a
// file + region (line/column); logical names a higher-level subject
// like a Terraform resource or container image. Different tools
// populate different subsets — Checkov fills both, Trivy filesystem
// fills physical only, image scans put the image into logical with
// kind="image".
type location struct {
	Physical *physicalLocation `json:"physicalLocation,omitempty"`
	Logical  []logicalLocation `json:"logicalLocations,omitempty"`
}

type physicalLocation struct {
	Artifact *artifactLocation `json:"artifactLocation,omitempty"`
	Region   *region           `json:"region,omitempty"`
}

type artifactLocation struct {
	URI       string `json:"uri,omitempty"`
	URIBaseID string `json:"uriBaseId,omitempty"`
	Index     int    `json:"index,omitempty"`
}

type region struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

type logicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}
