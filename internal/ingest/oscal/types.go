// Package oscal implements the OSCAL (Open Security Controls
// Assessment Language) Catalog ingest adapter for compliancekit.
// v0.13+ supports loading a customer-supplied OSCAL Catalog at scan
// time, registering it as a runtime framework so the customer's
// bespoke control set (FedRAMP-aligned, internal-policy-as-OSCAL,
// or NIST 800-53 tailored to their environment) becomes scannable
// without committing a new YAML to the binary.
//
// The package self-registers an "oscal-catalog" adapter with
// internal/ingest's Default registry at init() time. Importing it
// as a blank import is the standard way to make
// `compliancekit ingest --format=oscal-catalog` resolve.
//
// Supported input shapes:
//
//   - JSON  (.json, the OSCAL "machine" format)
//   - YAML  (.yaml/.yml, lossless serialization of the same model)
//   - XML   (.xml, the original OSCAL serialization; lighter coverage)
//
// The parser is hand-rolled against the OSCAL Catalog v1.0+ model
// to keep the dependency surface zero. It targets the subset of
// fields compliancekit needs to project an OSCAL Catalog onto a
// frameworks.Framework: catalog metadata (title, version), groups
// (mapped to control families), and controls (id, title, parts).
package oscal

import "encoding/xml"

// catalogJSON is the top-level JSON shape. OSCAL JSON wraps the
// catalog in `{"catalog": {...}}`; YAML uses the same shape; XML
// uses `<catalog>` as the document element. The JSON/YAML decoder
// handles both because YAML 1.2 is a JSON superset.
type catalogJSON struct {
	Catalog catalog `json:"catalog" yaml:"catalog"`
}

// catalogXML is the top-level XML shape (no wrapping key — the
// document element IS <catalog>). We decode into a separate type
// so the XML namespace attributes don't bleed into the JSON path.
type catalogXML struct {
	XMLName  xml.Name     `xml:"catalog"`
	UUID     string       `xml:"uuid,attr"`
	Metadata metadataXML  `xml:"metadata"`
	Groups   []groupXML   `xml:"group"`
	Controls []controlXML `xml:"control"`
}

// catalog is the parsed OSCAL Catalog model. We model only the
// fields compliancekit uses; the OSCAL Catalog v1.x model has many
// more (back-matter, parameters, modify-by, …) which we ignore.
type catalog struct {
	UUID     string    `json:"uuid"     yaml:"uuid"`
	Metadata metadata  `json:"metadata" yaml:"metadata"`
	Groups   []group   `json:"groups,omitempty"   yaml:"groups,omitempty"`
	Controls []control `json:"controls,omitempty" yaml:"controls,omitempty"`
}

type metadata struct {
	Title        string `json:"title"        yaml:"title"`
	Version      string `json:"version"      yaml:"version,omitempty"`
	LastModified string `json:"last-modified,omitempty" yaml:"last-modified,omitempty"`
	OSCALVersion string `json:"oscal-version,omitempty" yaml:"oscal-version,omitempty"`
}

// group bundles controls into a family (e.g. "AC — Access Control"
// in NIST 800-53). Groups may nest, but two levels deep covers
// every published OSCAL catalog the adapter has seen in practice.
type group struct {
	ID       string    `json:"id"       yaml:"id"`
	Class    string    `json:"class,omitempty"    yaml:"class,omitempty"`
	Title    string    `json:"title,omitempty"    yaml:"title,omitempty"`
	Groups   []group   `json:"groups,omitempty"   yaml:"groups,omitempty"`
	Controls []control `json:"controls,omitempty" yaml:"controls,omitempty"`
}

// control is one OSCAL control. The Parts slice carries semi-
// structured prose (statement, guidance, objective, …); we use
// the first text-bearing "statement" part as the control name
// when no top-level title is set.
type control struct {
	ID       string    `json:"id"       yaml:"id"`
	Class    string    `json:"class,omitempty"    yaml:"class,omitempty"`
	Title    string    `json:"title,omitempty"    yaml:"title,omitempty"`
	Parts    []part    `json:"parts,omitempty"    yaml:"parts,omitempty"`
	Props    []prop    `json:"props,omitempty"    yaml:"props,omitempty"`
	Controls []control `json:"controls,omitempty" yaml:"controls,omitempty"`
}

type part struct {
	ID    string `json:"id,omitempty"   yaml:"id,omitempty"`
	Name  string `json:"name,omitempty" yaml:"name,omitempty"`
	Class string `json:"class,omitempty" yaml:"class,omitempty"`
	Prose string `json:"prose,omitempty" yaml:"prose,omitempty"`
	Parts []part `json:"parts,omitempty" yaml:"parts,omitempty"`
}

type prop struct {
	Name  string `json:"name"  yaml:"name"`
	Value string `json:"value" yaml:"value"`
	Class string `json:"class,omitempty" yaml:"class,omitempty"`
	NS    string `json:"ns,omitempty" yaml:"ns,omitempty"`
}

// XML-equivalent struct shapes. OSCAL XML uses elements rather than
// JSON keys for most fields, so the tag set differs but the data
// model is the same. We collapse the JSON/XML representations into
// a single Framework in convert.go.

type metadataXML struct {
	Title        string `xml:"title"`
	Version      string `xml:"version"`
	LastModified string `xml:"last-modified"`
	OSCALVersion string `xml:"oscal-version"`
}

type groupXML struct {
	ID       string       `xml:"id,attr"`
	Class    string       `xml:"class,attr"`
	Title    string       `xml:"title"`
	Groups   []groupXML   `xml:"group"`
	Controls []controlXML `xml:"control"`
}

type controlXML struct {
	ID       string       `xml:"id,attr"`
	Class    string       `xml:"class,attr"`
	Title    string       `xml:"title"`
	Parts    []partXML    `xml:"part"`
	Props    []propXML    `xml:"prop"`
	Controls []controlXML `xml:"control"`
}

type partXML struct {
	ID    string    `xml:"id,attr"`
	Name  string    `xml:"name,attr"`
	Class string    `xml:"class,attr"`
	Prose string    `xml:"prose"`
	Parts []partXML `xml:"part"`
}

type propXML struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
	Class string `xml:"class,attr"`
	NS    string `xml:"ns,attr"`
}
