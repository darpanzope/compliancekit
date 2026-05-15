package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/ingest"
)

type adapter struct{}

// Format implements ingest.Ingester.
func (adapter) Format() string { return "trivy-json" }

// Description implements ingest.Ingester.
func (adapter) Description() string {
	return "Trivy native JSON — per-package CVE/PURL/CVSS detail, image SHA correlation"
}

// Ingest decodes a Trivy v0.50+ JSON report and projects every
// Vulnerabilities[], Misconfigurations[], and Secrets[] entry into
// compliancekit Findings. Vulnerability findings carry a populated
// core.Vulnerability block with CVE-ID, PURL, FixedVersion, CVSS
// vector, image SHA — much richer than the SARIF projection alone.
//
// Resource projection: container-image scans synthesize a phantom
// resource of type "container.image" with the image ARTIFACTNAME +
// image SHA in Attributes. Phase 5 cross-correlates this with K8s
// Deployments / DO App Platform services in the live graph.
// Filesystem scans synthesize "package.<ecosystem>" resources.
func (adapter) Ingest(ctx context.Context, r io.Reader, opts ingest.Options) (ingest.Result, error) {
	var rep report
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return ingest.Result{}, fmt.Errorf("decode trivy json: %w", err)
	}
	if len(rep.Results) == 0 {
		return ingest.Result{}, fmt.Errorf("trivy report has zero results")
	}

	if opts.Provenance.IngestedAt.IsZero() {
		opts.Provenance.IngestedAt = time.Now().UTC()
	}

	out := ingest.Result{}
	imageSHA := primaryRepoDigest(rep.Metadata)
	artifact := firstNonEmpty(rep.ArtifactName, "<unknown-artifact>")

	for _, res := range rep.Results {
		if err := ctx.Err(); err != nil {
			return ingest.Result{}, err
		}
		for _, v := range res.Vulnerabilities {
			f, phantom := buildVulnFinding(v, res, artifact, imageSHA, opts)
			out.Findings = append(out.Findings, f)
			if phantom != nil {
				out.Resources = append(out.Resources, *phantom)
			}
		}
		for _, m := range res.Misconfigurations {
			f, phantom := buildMisconfigFinding(m, res, artifact, opts)
			out.Findings = append(out.Findings, f)
			if phantom != nil {
				out.Resources = append(out.Resources, *phantom)
			}
		}
		for _, s := range res.Secrets {
			f, phantom := buildSecretFinding(s, res, artifact, opts)
			out.Findings = append(out.Findings, f)
			if phantom != nil {
				out.Resources = append(out.Resources, *phantom)
			}
		}
	}
	return out, nil
}

// buildVulnFinding constructs a Finding from one Trivy vulnerability
// record. Always populates core.Finding.Vulnerability; framework
// attribution flows through the default vuln-mgmt control set
// (defined at ingest layer in the SARIF adapter; v0.14 will pull
// that helper up to ingest itself in a future phase).
func buildVulnFinding(v vulnRecord, res result, artifact, imageSHA string, opts ingest.Options) (core.Finding, *core.Resource) {
	cvss := preferredCVSS(v.CVSS)
	severity := severityFromTrivy(v.Severity)

	subject, phantom := vulnSubject(v, res, artifact, imageSHA, opts)
	vuln := &core.Vulnerability{
		ID:               v.VulnerabilityID,
		CVSSScore:        cvss.V3Score,
		CVSSVector:       cvss.V3Vector,
		FixedVersion:     v.FixedVersion,
		Description:      firstNonEmpty(v.Description, v.Title),
		PrimaryURL:       v.PrimaryURL,
		PublishedDate:    v.PublishedDate,
		LastModifiedDate: v.LastModifiedDate,
		Image:            artifact,
		Package: core.Package{
			Name:      v.PkgName,
			Version:   v.InstalledVer,
			Ecosystem: res.Type,
			PURL:      v.PkgIdentifier.PURL,
		},
	}

	finding := core.Finding{
		CheckID:       "ingest.trivy." + v.VulnerabilityID,
		Status:        core.StatusFail,
		Severity:      severity,
		Resource:      subject,
		Message:       composeVulnMessage(v),
		Tags:          []string{"vulnerability", "cve", strings.ToLower(strings.ReplaceAll(res.Type, " ", "-"))},
		Vulnerability: vuln,
		Timestamp:     opts.Provenance.IngestedAt,
		Source: &core.Source{
			Type:        "ingest",
			Tool:        "trivy",
			ToolVersion: opts.Provenance.ToolVersion,
			Format:      "trivy-json",
			File:        opts.Provenance.File,
		},
	}
	return finding, phantom
}

// buildMisconfigFinding constructs a Finding from one Trivy AVD
// misconfig record (an IaC / Docker / K8s posture issue, distinct
// from a CVE).
func buildMisconfigFinding(m misconfig, res result, artifact string, opts ingest.Options) (core.Finding, *core.Resource) {
	ruleID := firstNonEmpty(m.AVDID, m.ID)
	severity := severityFromTrivy(m.Severity)
	subject, phantom := misconfigSubject(res, m, artifact, opts)

	finding := core.Finding{
		CheckID:   "ingest.trivy." + ruleID,
		Status:    core.StatusFail,
		Severity:  severity,
		Resource:  subject,
		Message:   firstNonEmpty(m.Message, m.Description, m.Title, ruleID),
		Tags:      []string{"misconfiguration", strings.ToLower(strings.ReplaceAll(res.Type, " ", "-"))},
		Timestamp: opts.Provenance.IngestedAt,
		Source: &core.Source{
			Type:        "ingest",
			Tool:        "trivy",
			ToolVersion: opts.Provenance.ToolVersion,
			Format:      "trivy-json",
			File:        opts.Provenance.File,
		},
	}
	return finding, phantom
}

// buildSecretFinding constructs a Finding from one Trivy secret
// record. The raw match value is REDACTED through redactSecret
// before landing in core.Secret.Fingerprint — the raw value never
// touches the Finding (ADR-010).
func buildSecretFinding(s secretRecord, res result, artifact string, opts ingest.Options) (core.Finding, *core.Resource) {
	severity := severityFromTrivy(s.Severity)
	subject, phantom := secretSubject(res, s, artifact, opts)

	finding := core.Finding{
		CheckID:  "ingest.trivy.secret." + s.RuleID,
		Status:   core.StatusFail,
		Severity: severity,
		Resource: subject,
		Message:  firstNonEmpty(s.Title, "secret detected: "+s.RuleID),
		Tags:     []string{"secret", strings.ToLower(s.Category)},
		Secret: &core.Secret{
			RuleID:      s.RuleID,
			RuleName:    s.Title,
			Fingerprint: redactSecret(s.Match),
			File:        res.Target,
			Line:        s.StartLine,
		},
		Timestamp: opts.Provenance.IngestedAt,
		Source: &core.Source{
			Type:        "ingest",
			Tool:        "trivy",
			ToolVersion: opts.Provenance.ToolVersion,
			Format:      "trivy-json",
			File:        opts.Provenance.File,
		},
	}
	return finding, phantom
}

// vulnSubject builds the ResourceRef for a vulnerability finding.
// For container-image scans the subject is the image; for filesystem
// scans it's the package. The image SHA is preserved as
// Resource.Attributes["image_sha"] so Phase 5's graph-join can
// match against K8s container imageID values.
func vulnSubject(v vulnRecord, res result, artifact, imageSHA string, opts ingest.Options) (core.ResourceRef, *core.Resource) {
	var (
		id   string
		kind string
		name string
	)
	if imageSHA != "" {
		id = "container-image://" + imageSHA
		kind = "container.image"
		name = artifact
	} else {
		id = "ingest://trivy/" + res.Target + "/" + v.PkgName + "@" + v.InstalledVer
		kind = "package." + res.Type
		name = v.PkgName + "@" + v.InstalledVer
	}
	if opts.Graph != nil {
		if existing, ok := opts.Graph.ByID(id); ok {
			return core.ResourceRef{
				ID: existing.ID, Type: existing.Type, Name: existing.Name,
				Provider: existing.Provider, Region: existing.Region,
			}, nil
		}
	}
	phantom := core.Resource{
		ID:       id,
		Type:     kind,
		Name:     name,
		Provider: "ingest",
		Attributes: map[string]any{
			"ingest_source": "trivy",
			"image_sha":     imageSHA,
			"image_name":    artifact,
			"package_purl":  v.PkgIdentifier.PURL,
		},
	}
	return core.ResourceRef{
		ID: phantom.ID, Type: phantom.Type, Name: phantom.Name, Provider: phantom.Provider,
	}, &phantom
}

func misconfigSubject(res result, m misconfig, artifact string, opts ingest.Options) (core.ResourceRef, *core.Resource) {
	id := "ingest://trivy/" + res.Target
	if m.CauseMetadata.Resource != "" {
		id += "#" + m.CauseMetadata.Resource
	}
	if opts.Graph != nil {
		if existing, ok := opts.Graph.ByID(id); ok {
			return core.ResourceRef{
				ID: existing.ID, Type: existing.Type, Name: existing.Name, Provider: existing.Provider,
			}, nil
		}
	}
	phantom := core.Resource{
		ID:       id,
		Type:     "trivy.misconfig.target",
		Name:     firstNonEmpty(m.CauseMetadata.Resource, res.Target),
		Provider: "ingest",
		Attributes: map[string]any{
			"ingest_source": "trivy",
			"trivy_type":    res.Type,
			"artifact_name": artifact,
		},
	}
	return core.ResourceRef{
		ID: phantom.ID, Type: phantom.Type, Name: phantom.Name, Provider: phantom.Provider,
	}, &phantom
}

func secretSubject(res result, s secretRecord, artifact string, opts ingest.Options) (core.ResourceRef, *core.Resource) {
	id := "ingest://trivy/secret/" + res.Target
	if s.StartLine > 0 {
		id += "#L" + itoa(s.StartLine)
	}
	if opts.Graph != nil {
		if existing, ok := opts.Graph.ByID(id); ok {
			return core.ResourceRef{
				ID: existing.ID, Type: existing.Type, Name: existing.Name, Provider: existing.Provider,
			}, nil
		}
	}
	phantom := core.Resource{
		ID:       id,
		Type:     "secret.file",
		Name:     res.Target,
		Provider: "ingest",
		Attributes: map[string]any{
			"ingest_source": "trivy",
			"artifact_name": artifact,
		},
	}
	return core.ResourceRef{
		ID: phantom.ID, Type: phantom.Type, Name: phantom.Name, Provider: phantom.Provider,
	}, &phantom
}

// preferredCVSS picks the best CVSS scoring from the map. Trivy
// ships per-source CVSS (nvd, redhat, ghsa, ...); we prefer nvd as
// the canonical authority, falling through to any source with a
// non-zero V3Score, finally to V2 if no V3 is present.
func preferredCVSS(scores map[string]cvssDetail) cvssDetail {
	if nvd, ok := scores["nvd"]; ok && nvd.V3Score > 0 {
		return nvd
	}
	// Any source with v3.
	for _, c := range scores {
		if c.V3Score > 0 {
			return c
		}
	}
	// Fall back to v2 if no v3 source exists.
	for _, c := range scores {
		if c.V2Score > 0 {
			return c
		}
	}
	return cvssDetail{}
}

// severityFromTrivy maps Trivy's severity string to compliancekit's
// scale. Trivy's enum: UNKNOWN / LOW / MEDIUM / HIGH / CRITICAL.
func severityFromTrivy(s string) core.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return core.SeverityCritical
	case "HIGH":
		return core.SeverityHigh
	case "MEDIUM":
		return core.SeverityMedium
	case "LOW":
		return core.SeverityLow
	}
	return core.SeverityInfo
}

// composeVulnMessage assembles a single-line message for a CVE
// finding suitable for the markdown / SARIF / CLI output.
func composeVulnMessage(v vulnRecord) string {
	pkg := v.PkgName
	if v.InstalledVer != "" {
		pkg += "@" + v.InstalledVer
	}
	if pkg == "" {
		return firstNonEmpty(v.Title, v.Description, v.VulnerabilityID)
	}
	fix := ""
	if v.FixedVersion != "" {
		fix = " (fixed in " + v.FixedVersion + ")"
	}
	return v.VulnerabilityID + " — " + pkg + fix
}

// primaryRepoDigest returns the first non-empty repo digest sha256
// from the image metadata, or "" for non-image scans. Trivy emits
// the digest portion after `@`; we pull just the sha256 token so
// the value matches what kubectl reports for container imageID.
func primaryRepoDigest(m metadata) string {
	if m.ImageID != "" {
		return strings.TrimPrefix(m.ImageID, "sha256:")
	}
	for _, d := range m.RepoDigests {
		if i := strings.Index(d, "@"); i > 0 && i < len(d)-1 {
			return strings.TrimPrefix(d[i+1:], "sha256:")
		}
	}
	return ""
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// itoa avoids strconv just for one integer-to-string in the
// resource-id path.
func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}

func init() {
	ingest.Register(adapter{})
}
