package oscal

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/darpanzope/compliancekit/internal/frameworks"
	"github.com/darpanzope/compliancekit/internal/ingest"
)

type adapter struct{}

// Format implements ingest.Ingester.
func (adapter) Format() string { return "oscal-catalog" }

// Description implements ingest.Ingester.
func (adapter) Description() string {
	return "OSCAL Catalog v1.x — register a customer framework at scan time (JSON / YAML / XML)"
}

// Ingest reads an OSCAL Catalog from r and registers it with the
// frameworks package as a runtime framework. Unlike findings-shaped
// adapters (SARIF, OCSF), this one returns zero Findings — the
// "ingest" action here is "make this framework scannable from now
// on," and the side effect is the runtime registry update.
//
// Returns a Warning naming the registered framework so the CLI can
// surface a confirmation breadcrumb to the operator.
//
// Format auto-detection: sniff the first non-whitespace byte.
// '<' → XML; '{' → JSON; anything else → YAML. The decoder for the
// detected format runs against a buffered copy of the input.
func (adapter) Ingest(_ context.Context, r io.Reader, opts ingest.Options) (ingest.Result, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return ingest.Result{}, fmt.Errorf("read oscal: %w", err)
	}
	if len(body) == 0 {
		return ingest.Result{}, errors.New("oscal payload is empty")
	}

	cat, err := decodeAuto(body, opts.Provenance.File)
	if err != nil {
		return ingest.Result{}, err
	}
	if len(cat.Controls) == 0 && len(cat.Groups) == 0 {
		return ingest.Result{}, errors.New("oscal catalog has zero controls (zero groups, zero top-level controls)")
	}

	fw := ToFramework(cat)
	if err := frameworks.Register(fw); err != nil {
		return ingest.Result{}, fmt.Errorf("register framework: %w", err)
	}

	warning := fmt.Sprintf("registered OSCAL framework %q (%s) with %d controls",
		fw.ID, fw.Name, len(fw.Controls))

	if opts.Provenance.IngestedAt.IsZero() {
		opts.Provenance.IngestedAt = time.Now().UTC()
	}

	return ingest.Result{Warnings: []string{warning}}, nil
}

// decodeAuto tries to detect the wire format and decode accordingly.
// JSON/YAML decode into catalogJSON; XML decodes into catalogXML and
// is then converted to the JSON model so the rest of the package only
// deals with one shape.
func decodeAuto(body []byte, hint string) (catalog, error) {
	first := firstNonWhitespace(body)
	// File extension is a hint when the body is ambiguous (e.g. YAML
	// frontmatter starting with `---`).
	ext := strings.ToLower(filepath.Ext(hint))

	switch {
	case first == '<', ext == ".xml":
		return decodeXML(body)
	case first == '{', ext == ".json":
		return decodeJSON(body)
	default:
		// YAML is the catch-all for anything starting with '-' /
		// 'c'(atalog) / etc.
		return decodeYAML(body)
	}
}

func decodeJSON(body []byte) (catalog, error) {
	var doc catalogJSON
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&doc); err != nil {
		return catalog{}, fmt.Errorf("decode oscal json: %w", err)
	}
	return doc.Catalog, nil
}

func decodeYAML(body []byte) (catalog, error) {
	var doc catalogJSON
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return catalog{}, fmt.Errorf("decode oscal yaml: %w", err)
	}
	return doc.Catalog, nil
}

// decodeXML parses the OSCAL XML serialization, then re-projects
// into the JSON-shaped catalog struct so downstream code (ToFramework)
// stays format-agnostic.
func decodeXML(body []byte) (catalog, error) {
	var doc catalogXML
	dec := xml.NewDecoder(bytes.NewReader(body))
	// OSCAL XML uses the http://csrc.nist.gov/ns/oscal/1.0 namespace.
	// Default Go XML decoder matches by local name only when no
	// namespace prefix is set on the tag; the package's struct tags
	// follow the local-name pattern so this Just Works for the
	// minimal field set we extract.
	if err := dec.Decode(&doc); err != nil {
		return catalog{}, fmt.Errorf("decode oscal xml: %w", err)
	}
	return projectXMLCatalog(doc), nil
}

// projectXMLCatalog converts the XML-decoded shape into the canonical
// JSON-shaped catalog struct.
func projectXMLCatalog(x catalogXML) catalog {
	out := catalog{
		UUID: x.UUID,
		Metadata: metadata{
			Title:        x.Metadata.Title,
			Version:      x.Metadata.Version,
			LastModified: x.Metadata.LastModified,
			OSCALVersion: x.Metadata.OSCALVersion,
		},
	}
	for _, g := range x.Groups {
		out.Groups = append(out.Groups, projectXMLGroup(g))
	}
	for _, c := range x.Controls {
		out.Controls = append(out.Controls, projectXMLControl(c))
	}
	return out
}

func projectXMLGroup(g groupXML) group {
	out := group{
		ID:    g.ID,
		Class: g.Class,
		Title: g.Title,
	}
	for _, sub := range g.Groups {
		out.Groups = append(out.Groups, projectXMLGroup(sub))
	}
	for _, c := range g.Controls {
		out.Controls = append(out.Controls, projectXMLControl(c))
	}
	return out
}

func projectXMLControl(c controlXML) control {
	out := control{
		ID:    c.ID,
		Class: c.Class,
		Title: c.Title,
	}
	for _, p := range c.Parts {
		out.Parts = append(out.Parts, projectXMLPart(p))
	}
	for _, p := range c.Props {
		out.Props = append(out.Props, prop(p))
	}
	for _, sub := range c.Controls {
		out.Controls = append(out.Controls, projectXMLControl(sub))
	}
	return out
}

func projectXMLPart(p partXML) part {
	out := part{
		ID:    p.ID,
		Name:  p.Name,
		Class: p.Class,
		Prose: p.Prose,
	}
	for _, sub := range p.Parts {
		out.Parts = append(out.Parts, projectXMLPart(sub))
	}
	return out
}

// firstNonWhitespace returns the first non-whitespace byte in body,
// or 0 if there are none.
func firstNonWhitespace(body []byte) byte {
	br := bufio.NewReader(bytes.NewReader(body))
	for {
		b, err := br.ReadByte()
		if err != nil {
			return 0
		}
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			return b
		}
	}
}

func init() {
	ingest.Register(adapter{})
}
