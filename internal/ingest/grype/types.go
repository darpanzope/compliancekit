package grype

// document is the top-level Grype v0.7x JSON shape. We decode the
// subset the adapter consumes; unknown fields are silently ignored
// so newer Grype releases stay compatible.
type document struct {
	Matches    []match    `json:"matches"`
	Source     sourceInfo `json:"source,omitempty"`
	Distro     distroInfo `json:"distro,omitempty"`
	Descriptor descriptor `json:"descriptor,omitempty"`
}

type match struct {
	Vulnerability vulnerability `json:"vulnerability"`
	Artifact      artifact      `json:"artifact"`
}

type vulnerability struct {
	ID          string      `json:"id"`
	DataSource  string      `json:"dataSource,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	Description string      `json:"description,omitempty"`
	URLs        []string    `json:"urls,omitempty"`
	CVSS        []cvssEntry `json:"cvss,omitempty"`
	Fix         fixInfo     `json:"fix,omitempty"`
	Related     []string    `json:"-"` // populated from advisories — set by adapter
}

type cvssEntry struct {
	Source         string         `json:"source,omitempty"`
	Version        string         `json:"version,omitempty"`
	Vector         string         `json:"vector,omitempty"`
	Metrics        cvssMetrics    `json:"metrics,omitempty"`
	VendorMetadata map[string]any `json:"vendorMetadata,omitempty"`
}

type cvssMetrics struct {
	BaseScore           float64 `json:"baseScore,omitempty"`
	ExploitabilityScore float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64 `json:"impactScore,omitempty"`
}

type fixInfo struct {
	Versions []string `json:"versions,omitempty"`
	State    string   `json:"state,omitempty"`
}

type artifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

type sourceInfo struct {
	Type   string     `json:"type,omitempty"`
	Target targetInfo `json:"target,omitempty"`
}

// targetInfo is the polymorphic "target" field: for image scans it's
// an object with imageID/manifestDigest; for filesystem scans it's
// a string. We decode both shapes via custom JSON.
type targetInfo struct {
	UserInput      string `json:"userInput,omitempty"`
	ImageID        string `json:"imageID,omitempty"`
	ManifestDigest string `json:"manifestDigest,omitempty"`
}

type distroInfo struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

type descriptor struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}
