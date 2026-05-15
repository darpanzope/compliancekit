// Package trivy implements a native-JSON ingest adapter for Trivy
// (aquasecurity/trivy) output. v0.14+. Trivy's JSON format carries
// richer detail than its SARIF projection — per-package CVE list,
// canonical PURLs, fixed versions, full CVSS vectors, image SHA
// digests — so this adapter exists alongside the v0.13 generic
// SARIF path for operators who want the deeper extraction.
//
// Supported inputs:
//
//   - `trivy fs --format=json` filesystem scans (lockfile-derived CVEs)
//   - `trivy image --format=json` container image scans
//   - `trivy k8s --format=json` Kubernetes cluster scans (admission
//     manifests + per-image scans aggregated)
//   - `trivy repo --format=json` git repository scans
//
// The adapter self-registers as `--format=trivy-json` with
// internal/ingest's Default registry at init() time.
package trivy

// report is the top-level Trivy v0.50 JSON shape. We decode the
// subset we project; unknown fields pass through json.Unmarshal as
// no-ops so schema drift in newer Trivy releases is tolerated.
type report struct {
	SchemaVersion int      `json:"SchemaVersion,omitempty"`
	ArtifactName  string   `json:"ArtifactName,omitempty"`
	ArtifactType  string   `json:"ArtifactType,omitempty"`
	Metadata      metadata `json:"Metadata,omitempty"`
	Results       []result `json:"Results,omitempty"`
}

// metadata for container-image scans. The interesting fields are
// ImageID (sha256 of the image config blob) and RepoDigests
// (sha256 of the manifest, the one Kubernetes / DO App Platform
// pin against). v0.14's Phase 5 graph-join uses these to correlate
// CVEs back to running cloud resources.
type metadata struct {
	OS          osInfo   `json:"OS,omitempty"`
	ImageID     string   `json:"ImageID,omitempty"`
	DiffIDs     []string `json:"DiffIDs,omitempty"`
	RepoTags    []string `json:"RepoTags,omitempty"`
	RepoDigests []string `json:"RepoDigests,omitempty"`
}

type osInfo struct {
	Family string `json:"Family,omitempty"`
	Name   string `json:"Name,omitempty"`
}

// result is one Trivy target — typically one package ecosystem
// (alpine, debian, npm, pip, …) or one IaC file. Findings group
// into Vulnerabilities (CVE-shaped), Misconfigurations (AVD-shaped),
// and Secrets (rule-id-shaped).
type result struct {
	Target            string         `json:"Target,omitempty"`
	Class             string         `json:"Class,omitempty"`
	Type              string         `json:"Type,omitempty"`
	Vulnerabilities   []vulnRecord   `json:"Vulnerabilities,omitempty"`
	Misconfigurations []misconfig    `json:"Misconfigurations,omitempty"`
	Secrets           []secretRecord `json:"Secrets,omitempty"`
}

// vulnRecord is one CVE / GHSA Trivy reported. We pull every field
// that maps cleanly into core.Vulnerability; tool-specific extras
// (CweIDs, VendorSeverity per-distro, References) are decoded into
// References / Aliases for completeness.
type vulnRecord struct {
	VulnerabilityID  string                `json:"VulnerabilityID,omitempty"`
	PkgID            string                `json:"PkgID,omitempty"`
	PkgName          string                `json:"PkgName,omitempty"`
	PkgIdentifier    pkgIdentifier         `json:"PkgIdentifier,omitempty"`
	InstalledVer     string                `json:"InstalledVersion,omitempty"`
	FixedVersion     string                `json:"FixedVersion,omitempty"`
	Status           string                `json:"Status,omitempty"`
	Layer            layerInfo             `json:"Layer,omitempty"`
	SeveritySource   string                `json:"SeveritySource,omitempty"`
	PrimaryURL       string                `json:"PrimaryURL,omitempty"`
	Title            string                `json:"Title,omitempty"`
	Description      string                `json:"Description,omitempty"`
	Severity         string                `json:"Severity,omitempty"`
	CweIDs           []string              `json:"CweIDs,omitempty"`
	CVSS             map[string]cvssDetail `json:"CVSS,omitempty"`
	References       []string              `json:"References,omitempty"`
	PublishedDate    string                `json:"PublishedDate,omitempty"`
	LastModifiedDate string                `json:"LastModifiedDate,omitempty"`
}

type pkgIdentifier struct {
	PURL string `json:"PURL,omitempty"`
}

type layerInfo struct {
	DiffID string `json:"DiffID,omitempty"`
	Digest string `json:"Digest,omitempty"`
}

// cvssDetail captures one source's CVSS scoring (nvd, redhat, ghsa,
// …). We prefer NVD when present and fall through to any source
// otherwise.
type cvssDetail struct {
	V3Score  float64 `json:"V3Score,omitempty"`
	V3Vector string  `json:"V3Vector,omitempty"`
	V2Score  float64 `json:"V2Score,omitempty"`
	V2Vector string  `json:"V2Vector,omitempty"`
}

// misconfig is one Trivy AVD (Aqua Vulnerability Database) IaC /
// container misconfiguration finding — same shape the v0.13 SARIF
// path already handles, but here we get the full description +
// remediation text Trivy ships in JSON but truncates in SARIF.
type misconfig struct {
	Type          string    `json:"Type,omitempty"`
	ID            string    `json:"ID,omitempty"`
	AVDID         string    `json:"AVDID,omitempty"`
	Title         string    `json:"Title,omitempty"`
	Description   string    `json:"Description,omitempty"`
	Message       string    `json:"Message,omitempty"`
	Namespace     string    `json:"Namespace,omitempty"`
	Query         string    `json:"Query,omitempty"`
	Resolution    string    `json:"Resolution,omitempty"`
	Severity      string    `json:"Severity,omitempty"`
	PrimaryURL    string    `json:"PrimaryURL,omitempty"`
	References    []string  `json:"References,omitempty"`
	Status        string    `json:"Status,omitempty"`
	CauseMetadata causeMeta `json:"CauseMetadata,omitempty"`
}

type causeMeta struct {
	Resource  string `json:"Resource,omitempty"`
	Provider  string `json:"Provider,omitempty"`
	Service   string `json:"Service,omitempty"`
	StartLine int    `json:"StartLine,omitempty"`
	EndLine   int    `json:"EndLine,omitempty"`
}

// secretRecord is one secret Trivy found in source. We extract the
// rule id + location + a redacted fingerprint; we NEVER write the
// raw Match value into the resulting Finding (ADR-010, Phase 8).
type secretRecord struct {
	RuleID    string `json:"RuleID,omitempty"`
	Category  string `json:"Category,omitempty"`
	Severity  string `json:"Severity,omitempty"`
	Title     string `json:"Title,omitempty"`
	StartLine int    `json:"StartLine,omitempty"`
	EndLine   int    `json:"EndLine,omitempty"`
	Match     string `json:"Match,omitempty"`
}
