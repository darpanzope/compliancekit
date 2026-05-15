// Package ocsf implements the OCSF (Open Cybersecurity Schema
// Framework) v1.x ingest adapter for compliancekit. OCSF is the
// schema AWS Security Hub, Google Cloud Security Command Center,
// and Microsoft Defender for Cloud all emit in their finding
// export pipelines. v0.13+ converts OCSF events to compliancekit
// Findings, attributing them to framework controls via per-product
// mapping tables and joining named ARNs/URIs to existing graph
// resources where the native scan already covered them.
//
// The package self-registers an "ocsf" adapter with internal/ingest's
// Default registry at init() time. Importing it as a blank import is
// the standard way to make `compliancekit ingest --format=ocsf`
// resolve.
//
// Supported OCSF classes (uid → name):
//
//	2001  Vulnerability Finding
//	2002  Compliance Finding
//	2003  Detection Finding
//	2004  Incident Finding
//
// Class shape varies modestly; the adapter targets the union of
// fields the three big SaaS producers populate today.
package ocsf

// event is one OCSF finding. We decode the union of fields the three
// big producers populate; unknown fields are ignored at decode time
// so schema-version drift across producer releases is non-fatal.
type event struct {
	ActivityID    int            `json:"activity_id,omitempty"`
	ActivityName  string         `json:"activity_name,omitempty"`
	CategoryUID   int            `json:"category_uid,omitempty"`
	CategoryName  string         `json:"category_name,omitempty"`
	ClassUID      int            `json:"class_uid,omitempty"`
	ClassName     string         `json:"class_name,omitempty"`
	Time          int64          `json:"time,omitempty"` // epoch milliseconds
	StatusID      int            `json:"status_id,omitempty"`
	Status        string         `json:"status,omitempty"`
	SeverityID    int            `json:"severity_id,omitempty"`
	Severity      string         `json:"severity,omitempty"`
	Message       string         `json:"message,omitempty"`
	Metadata      metadata       `json:"metadata,omitempty"`
	Resources     []resourceRef  `json:"resources,omitempty"`
	Finding       *findingInfo   `json:"finding_info,omitempty"`
	Compliance    *complianceObj `json:"compliance,omitempty"`
	Cloud         *cloudObj      `json:"cloud,omitempty"`
	Vulnerability []vulnObj      `json:"vulnerabilities,omitempty"`
	Unmapped      map[string]any `json:"unmapped,omitempty"`
}

type metadata struct {
	Version string  `json:"version,omitempty"`
	Product product `json:"product,omitempty"`
}

type product struct {
	Name       string   `json:"name,omitempty"`
	Vendor     string   `json:"vendor_name,omitempty"`
	Version    string   `json:"version,omitempty"`
	FeatureRef *feature `json:"feature,omitempty"`
}

type feature struct {
	UID  string `json:"uid,omitempty"`
	Name string `json:"name,omitempty"`
}

// resourceRef describes one affected resource on an event. AWS
// Security Hub puts the ARN into UID; GCP SCC puts the projects/
// path; Defender puts the Azure resource ID. The adapter treats UID
// as the canonical identifier for graph joining.
type resourceRef struct {
	UID    string         `json:"uid,omitempty"`
	Type   string         `json:"type,omitempty"`
	Name   string         `json:"name,omitempty"`
	Group  string         `json:"group,omitempty"`
	Region string         `json:"region,omitempty"`
	Owner  string         `json:"owner,omitempty"`
	Cloud  *cloudObj      `json:"cloud,omitempty"`
	Data   map[string]any `json:"data,omitempty"`
	Labels []string       `json:"labels,omitempty"`
}

type findingInfo struct {
	UID         string    `json:"uid,omitempty"`
	Title       string    `json:"title,omitempty"`
	Description string    `json:"desc,omitempty"`
	Types       []string  `json:"types,omitempty"`
	SrcURL      string    `json:"src_url,omitempty"`
	Analytic    *analytic `json:"analytic,omitempty"`
}

type analytic struct {
	UID  string `json:"uid,omitempty"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

// complianceObj is the OCSF compliance finding subobject. Standards
// names which framework (e.g. "PCI DSS v4.0"); Requirements lists
// the controls — but in the producer's own ID syntax, which usually
// needs translation. The adapter's per-product mapping table maps
// the producer's rule ID (typically the finding_info.uid or
// finding_info.types[0]) to compliancekit's framework controls.
type complianceObj struct {
	Standards    []string `json:"standards,omitempty"`
	Requirements []string `json:"requirements,omitempty"`
	Control      string   `json:"control,omitempty"`
	Status       string   `json:"status,omitempty"`
	StatusID     int      `json:"status_id,omitempty"`
}

type cloudObj struct {
	Provider string `json:"provider,omitempty"`
	Region   string `json:"region,omitempty"`
	Account  *acct  `json:"account,omitempty"`
	Project  *proj  `json:"project,omitempty"`
}

type acct struct {
	UID  string `json:"uid,omitempty"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

type proj struct {
	UID  string `json:"uid,omitempty"`
	Name string `json:"name,omitempty"`
}

type vulnObj struct {
	CVE         *cveObj `json:"cve,omitempty"`
	Severity    string  `json:"severity,omitempty"`
	Description string  `json:"desc,omitempty"`
	Title       string  `json:"title,omitempty"`
}

type cveObj struct {
	UID       string  `json:"uid,omitempty"`
	CVSSScore float64 `json:"cvss,omitempty"`
}
