package ingest

import (
	"fmt"
	"strings"

	"github.com/darpanzope/compliancekit/internal/core"
)

// CorrelateImageSHA expands a finding slice with cross-references:
// when an ingested CVE finding names a container image SHA (Trivy /
// Grype image scans both emit container-image://<sha256> as the
// resource ID), and the live resource graph contains a Kubernetes
// Pod / Deployment / DaemonSet / DO App Platform service / ECS task
// referencing the same SHA, a clone of the finding is appended with
// its Resource swapped to the running instance and a "running-on"
// tag added. The original image-pinned finding is kept too so
// auditors can pivot either direction.
//
// Returns: (expanded findings, count of correlations added).
//
// Heuristics for "same SHA":
//   - Finding.Resource.ID starts with "container-image://<hex>" OR
//     Finding.Vulnerability.Image is set.
//   - Resource.Attributes["image_sha"] matches (sha256 hex prefix-
//     compared after stripping the "sha256:" prefix).
//   - Resource.Attributes["images"] contains the image name when SHA
//     is not directly recorded (DO App Platform / fluent K8s
//     manifest projections often only have the tag).
//
// The correlation runs in O(findings × resources) — fine for our
// scale (typical scans: ~100 findings × ~5000 resources). v0.15+ can
// add a SHA index on the graph if this becomes a bottleneck.
func CorrelateImageSHA(findings []core.Finding, graph *core.ResourceGraph) (out []core.Finding, added int) {
	out = findings
	if graph == nil || len(findings) == 0 {
		return out, 0
	}

	// Build a SHA → []Resource index once.
	bySHA := map[string][]core.Resource{}
	byImageName := map[string][]core.Resource{}
	for _, r := range graph.All() {
		if sha := stringAttr(r, "image_sha"); sha != "" {
			bySHA[normalizeSHA(sha)] = append(bySHA[normalizeSHA(sha)], r)
		}
		// K8s container resources sometimes record imageID with
		// docker-pullable:// prefix; extract the trailing sha.
		if id := stringAttr(r, "image_id"); id != "" {
			if sha := extractSHAFromImageID(id); sha != "" {
				bySHA[sha] = append(bySHA[sha], r)
			}
		}
		// Some cloud-collector resources only carry the image tag, no
		// SHA. Index by image name as a fallback so we still join
		// "alpine:3.18.0" → DO App Platform deploys referencing it.
		if img := stringAttr(r, "image"); img != "" {
			byImageName[img] = append(byImageName[img], r)
		}
		if img := stringAttr(r, "image_name"); img != "" {
			byImageName[img] = append(byImageName[img], r)
		}
	}

	for _, f := range findings {
		sha := extractFindingSHA(f)
		imageName := extractFindingImageName(f)

		seen := map[string]bool{f.Resource.ID: true}
		add := func(target core.Resource) {
			if seen[target.ID] {
				return
			}
			seen[target.ID] = true
			clone := f
			clone.Resource = core.ResourceRef{
				ID:       target.ID,
				Type:     target.Type,
				Name:     target.Name,
				Provider: target.Provider,
				Region:   target.Region,
			}
			clone.Tags = append(append([]string{}, f.Tags...),
				fmt.Sprintf("running-on:%s/%s", target.Type, target.Name),
				"image-sha-correlation",
			)
			out = append(out, clone)
			added++
		}

		if sha != "" {
			for _, r := range bySHA[sha] {
				add(r)
			}
		}
		if imageName != "" {
			for _, r := range byImageName[imageName] {
				add(r)
			}
		}
	}
	return out, added
}

func extractFindingSHA(f core.Finding) string {
	// Direct path: Resource.ID with container-image:// prefix.
	if strings.HasPrefix(f.Resource.ID, "container-image://") {
		return strings.TrimPrefix(f.Resource.ID, "container-image://")
	}
	// Vulnerability.Image is typically a tag, not a SHA, so we don't
	// extract a SHA from it; the byImageName fallback handles that case.
	return ""
}

func extractFindingImageName(f core.Finding) string {
	if f.Vulnerability != nil && f.Vulnerability.Image != "" {
		return f.Vulnerability.Image
	}
	return ""
}

func stringAttr(r core.Resource, key string) string {
	if r.Attributes == nil {
		return ""
	}
	if v, ok := r.Attributes[key].(string); ok {
		return v
	}
	return ""
}

// normalizeSHA strips a "sha256:" prefix if present and lowercases
// the hex so map keys match regardless of input convention.
func normalizeSHA(s string) string {
	return strings.ToLower(strings.TrimPrefix(s, "sha256:"))
}

// extractSHAFromImageID parses formats like
// "docker-pullable://repo@sha256:abc..." or
// "containerd://repo@sha256:abc..." into just the sha hex.
func extractSHAFromImageID(id string) string {
	if i := strings.LastIndex(id, "@sha256:"); i >= 0 {
		return strings.ToLower(id[i+len("@sha256:"):])
	}
	if i := strings.LastIndex(id, "sha256:"); i >= 0 {
		return strings.ToLower(id[i+len("sha256:"):])
	}
	return ""
}
