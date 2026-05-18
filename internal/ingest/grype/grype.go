// Package grype implements a native-JSON ingest adapter for Anchore
// Grype (anchore/grype) output. v0.14+. Grype is the alternate-of-
// preference for shops that don't run Trivy; the on-disk JSON shape
// is similar but distinct enough to warrant its own adapter.
//
// Self-registers as `--format=grype-json` with the Default ingest
// registry at init().
package grype

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/ingest"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

type adapter struct{}

// Format implements ingest.Ingester.
func (adapter) Format() string { return "grype-json" }

// Description implements ingest.Ingester.
func (adapter) Description() string {
	return "Grype native JSON — per-package CVE/PURL/CVSS detail, image + filesystem scans"
}

// Ingest decodes a Grype v0.x JSON document and projects every
// matches[] entry into a compliancekit Finding with a populated
// compliancekit.Vulnerability block.
func (adapter) Ingest(ctx context.Context, r io.Reader, opts ingest.Options) (ingest.Result, error) {
	var doc document
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return ingest.Result{}, fmt.Errorf("decode grype json: %w", err)
	}
	if opts.Provenance.IngestedAt.IsZero() {
		opts.Provenance.IngestedAt = time.Now().UTC()
	}

	imageSHA := primarySourceSHA(doc.Source)
	imageName := primarySourceName(doc.Source)

	out := ingest.Result{}
	for _, m := range doc.Matches {
		if err := ctx.Err(); err != nil {
			return ingest.Result{}, err
		}
		f, phantom := buildVulnFinding(m, imageName, imageSHA, opts)
		out.Findings = append(out.Findings, f)
		if phantom != nil {
			out.Resources = append(out.Resources, *phantom)
		}
	}
	if len(out.Findings) == 0 {
		out.Warnings = append(out.Warnings, "grype report had zero matches")
	}
	return out, nil
}

func buildVulnFinding(m match, imageName, imageSHA string, opts ingest.Options) (compliancekit.Finding, *compliancekit.Resource) {
	v := m.Vulnerability
	severity := severityFromGrype(v.Severity)
	cvss := preferredCVSS(v.CVSS)
	fixedVersion := ""
	if len(m.Vulnerability.Fix.Versions) > 0 {
		fixedVersion = m.Vulnerability.Fix.Versions[0]
	}

	subject, phantom := vulnSubject(m, imageName, imageSHA, opts)

	vuln := &compliancekit.Vulnerability{
		ID:           v.ID,
		Aliases:      v.Related, // related CVE/GHSA aliases
		CVSSScore:    cvss.Metrics.BaseScore,
		CVSSVector:   cvss.Vector,
		FixedVersion: fixedVersion,
		Description:  v.Description,
		PrimaryURL:   v.DataSource,
		Image:        imageName,
		Package: compliancekit.Package{
			Name:      m.Artifact.Name,
			Version:   m.Artifact.Version,
			Ecosystem: m.Artifact.Type,
			PURL:      m.Artifact.PURL,
		},
	}

	return compliancekit.Finding{
		CheckID:       "ingest.grype." + v.ID,
		Status:        compliancekit.StatusFail,
		Severity:      severity,
		Resource:      subject,
		Message:       composeMessage(m, fixedVersion),
		Tags:          []string{"vulnerability", "cve", strings.ToLower(m.Artifact.Type)},
		Vulnerability: vuln,
		Timestamp:     opts.Provenance.IngestedAt,
		Source: &compliancekit.Source{
			Type:        "ingest",
			Tool:        "grype",
			ToolVersion: opts.Provenance.ToolVersion,
			Format:      "grype-json",
			File:        opts.Provenance.File,
		},
	}, phantom
}

func vulnSubject(m match, imageName, imageSHA string, opts ingest.Options) (compliancekit.ResourceRef, *compliancekit.Resource) {
	var (
		id, kind, name string
	)
	if imageSHA != "" {
		id = "container-image://" + imageSHA
		kind = "container.image"
		name = imageName
	} else {
		id = "ingest://grype/" + m.Artifact.Name + "@" + m.Artifact.Version
		kind = "package." + strings.ToLower(m.Artifact.Type)
		name = m.Artifact.Name + "@" + m.Artifact.Version
	}
	if opts.Graph != nil {
		if existing, ok := opts.Graph.ByID(id); ok {
			return compliancekit.ResourceRef{
				ID: existing.ID, Type: existing.Type, Name: existing.Name,
				Provider: existing.Provider, Region: existing.Region,
			}, nil
		}
	}
	phantom := compliancekit.Resource{
		ID:       id,
		Type:     kind,
		Name:     name,
		Provider: "ingest",
		Attributes: map[string]any{
			"ingest_source": "grype",
			"image_sha":     imageSHA,
			"image_name":    imageName,
			"package_purl":  m.Artifact.PURL,
		},
	}
	return compliancekit.ResourceRef{
		ID: phantom.ID, Type: phantom.Type, Name: phantom.Name, Provider: phantom.Provider,
	}, &phantom
}

func composeMessage(m match, fix string) string {
	pkg := m.Artifact.Name
	if m.Artifact.Version != "" {
		pkg += "@" + m.Artifact.Version
	}
	if pkg == "" {
		return m.Vulnerability.ID
	}
	if fix != "" {
		return m.Vulnerability.ID + " — " + pkg + " (fixed in " + fix + ")"
	}
	return m.Vulnerability.ID + " — " + pkg
}

// severityFromGrype maps Grype's severity strings to compliancekit's
// scale. Grype uses Title-Case ("Critical" / "High" / ...) while
// Trivy uses upper-case; both are normalized here.
func severityFromGrype(s string) compliancekit.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return compliancekit.SeverityCritical
	case "high":
		return compliancekit.SeverityHigh
	case "medium":
		return compliancekit.SeverityMedium
	case "low":
		return compliancekit.SeverityLow
	case "negligible":
		return compliancekit.SeverityInfo
	}
	return compliancekit.SeverityInfo
}

// preferredCVSS picks the best CVSS scoring from a Grype-shape list.
// Prefer NVD when present, else any V3 entry, else V2.
func preferredCVSS(cvss []cvssEntry) cvssEntry {
	for _, c := range cvss {
		if strings.EqualFold(c.Source, "nvd") && c.Metrics.BaseScore > 0 {
			return c
		}
	}
	for _, c := range cvss {
		if strings.HasPrefix(c.Version, "3") && c.Metrics.BaseScore > 0 {
			return c
		}
	}
	for _, c := range cvss {
		if c.Metrics.BaseScore > 0 {
			return c
		}
	}
	return cvssEntry{}
}

func primarySourceSHA(s sourceInfo) string {
	if s.Target.UserInput == "" {
		return ""
	}
	// Image SHA lives in target.imageID or target.manifestDigest;
	// fall back to digest-derived target string parsing.
	if s.Target.ImageID != "" {
		return strings.TrimPrefix(s.Target.ImageID, "sha256:")
	}
	if s.Target.ManifestDigest != "" {
		return strings.TrimPrefix(s.Target.ManifestDigest, "sha256:")
	}
	return ""
}

func primarySourceName(s sourceInfo) string {
	if s.Target.UserInput != "" {
		return s.Target.UserInput
	}
	return ""
}

func init() {
	ingest.Register(adapter{})
}
