package oscal

import (
	"strings"

	"github.com/darpanzope/compliancekit/internal/frameworks"
)

// ToFramework converts a parsed OSCAL catalog into a compliancekit
// frameworks.Framework. The conversion is structural only — every
// control in the catalog (including nested controls under groups)
// becomes a Control entry; group hierarchy collapses into the
// Control.Family field. OSCAL Profile imports are NOT followed
// (Profile is a separate model deserving its own ingest pass).
//
// Framework identity: derived from the catalog metadata title in
// kebab-case form, prefixed with "oscal." so runtime catalogs are
// visually distinct from embedded ones in `compliancekit
// frameworks list`. The catalog UUID is recorded as Source for
// auditor transparency.
func ToFramework(c catalog) *frameworks.Framework {
	fw := &frameworks.Framework{
		ID:          frameworkIDFromCatalog(c),
		Name:        firstNonEmpty(c.Metadata.Title, "OSCAL Imported Catalog"),
		Version:     c.Metadata.Version,
		Description: descriptionFromCatalog(c),
		Source:      sourceFromCatalog(c),
		Category:    frameworks.CategoryCompliance,
		Controls:    map[string]frameworks.Control{},
	}

	for _, g := range c.Groups {
		appendGroup(fw, g, "")
	}
	for _, ctrl := range c.Controls {
		appendControl(fw, ctrl, "")
	}
	return fw
}

// appendGroup walks a group's nested groups + controls into the
// flat fw.Controls map, propagating the group's class (or id) as
// the Control.Family value. OSCAL allows groups within groups; we
// concatenate the family path with `/` so a deeply nested catalog
// is still navigable.
func appendGroup(fw *frameworks.Framework, g group, parentFamily string) {
	family := parentFamily
	if g.Class != "" {
		if family != "" {
			family += "/" + g.Class
		} else {
			family = g.Class
		}
	} else if g.ID != "" {
		if family != "" {
			family += "/" + g.ID
		} else {
			family = g.ID
		}
	}

	for _, sub := range g.Groups {
		appendGroup(fw, sub, family)
	}
	for _, ctrl := range g.Controls {
		appendControl(fw, ctrl, family)
	}
}

// appendControl inserts one control into fw.Controls, plus any
// nested sub-controls (NIST 800-53 enhancements are modeled as
// nested OSCAL controls). The control's ID is preserved verbatim
// so external mappings remain stable.
func appendControl(fw *frameworks.Framework, c control, family string) {
	id := strings.TrimSpace(c.ID)
	if id == "" {
		return
	}
	ctrl := frameworks.Control{
		ID:          id,
		Name:        firstNonEmpty(c.Title, id),
		Description: descriptionFromControl(c),
		Family:      family,
		References:  referencesFromProps(c.Props),
		Tags:        tagsFromProps(c.Props),
	}
	fw.Controls[id] = ctrl

	for _, sub := range c.Controls {
		appendControl(fw, sub, family)
	}
}

// descriptionFromControl prefers a part with name="statement"
// (OSCAL convention for the normative control text), falling
// through to the first part with prose. Returns empty string if
// no part carries prose at all.
func descriptionFromControl(c control) string {
	for _, p := range c.Parts {
		if p.Name == "statement" && p.Prose != "" {
			return p.Prose
		}
	}
	for _, p := range c.Parts {
		if p.Prose != "" {
			return p.Prose
		}
	}
	// Recurse into nested parts (objective / assessment-objective
	// occasionally hold the user-friendly text in NIST catalogs).
	for _, p := range c.Parts {
		for _, sub := range p.Parts {
			if sub.Prose != "" {
				return sub.Prose
			}
		}
	}
	return ""
}

// referencesFromProps extracts every prop with name="reference"
// or class containing "reference" into the framework's
// Control.References slice.
func referencesFromProps(props []prop) []string {
	out := []string{}
	for _, p := range props {
		if p.Name == "reference" || strings.Contains(strings.ToLower(p.Class), "reference") {
			if p.Value != "" {
				out = append(out, p.Value)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// tagsFromProps maps prop name="label" values into the
// Control.Tags slice — OSCAL catalogs use a label prop for free-form
// tagging (e.g. "low-impact" / "moderate-impact" / "high-impact" in
// NIST 800-53 baselines).
func tagsFromProps(props []prop) []string {
	out := []string{}
	for _, p := range props {
		if p.Name == "label" && p.Value != "" {
			out = append(out, p.Value)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// frameworkIDFromCatalog derives a stable, human-friendly framework
// ID from the catalog metadata title. Kebab-cased, prefixed with
// "oscal." so runtime catalogs are distinguishable from the
// embedded set.
func frameworkIDFromCatalog(c catalog) string {
	title := strings.TrimSpace(c.Metadata.Title)
	if title == "" {
		// UUID is always present per OSCAL spec; the prefix-plus-
		// first-12-chars form is unambiguous and stays stable
		// across catalog edits that don't change the UUID.
		return "oscal." + truncate(strings.TrimPrefix(c.UUID, "uuid:"), 12)
	}
	return "oscal." + kebab(title)
}

func descriptionFromCatalog(c catalog) string {
	parts := []string{}
	if c.Metadata.Version != "" {
		parts = append(parts, "version "+c.Metadata.Version)
	}
	if c.Metadata.OSCALVersion != "" {
		parts = append(parts, "OSCAL "+c.Metadata.OSCALVersion)
	}
	if c.Metadata.LastModified != "" {
		parts = append(parts, "last-modified "+c.Metadata.LastModified)
	}
	return strings.Join(parts, "; ")
}

func sourceFromCatalog(c catalog) string {
	if c.UUID != "" {
		return "OSCAL Catalog UUID " + c.UUID
	}
	return "OSCAL Catalog (no UUID)"
}

func kebab(s string) string {
	var b strings.Builder
	prevDash := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := b.String()
	out = strings.Trim(out, "-")
	if out == "" {
		return "imported"
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}
