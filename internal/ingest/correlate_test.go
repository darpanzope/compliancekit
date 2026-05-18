package ingest

import (
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func TestCorrelateImageSHA_KubernetesJoin(t *testing.T) {
	graph := compliancekit.NewResourceGraph()

	// A K8s deployment running the same image SHA Trivy will report.
	graph.Add(compliancekit.Resource{
		ID:       "k8s://prod/Deployment/checkout-api",
		Type:     "k8s.deployment",
		Name:     "checkout-api",
		Provider: "kubernetes",
		Region:   "us-east-1",
		Attributes: map[string]any{
			"image_id": "docker-pullable://acme/checkout@sha256:abc123def456",
		},
	})
	// Another K8s pod referencing same SHA.
	graph.Add(compliancekit.Resource{
		ID:       "k8s://prod/Pod/checkout-api-65d8",
		Type:     "k8s.pod",
		Name:     "checkout-api-65d8",
		Provider: "kubernetes",
		Region:   "us-east-1",
		Attributes: map[string]any{
			"image_sha": "sha256:abc123def456",
		},
	})
	// A pod with a different SHA — must NOT correlate.
	graph.Add(compliancekit.Resource{
		ID:       "k8s://prod/Pod/web-ui-3a1",
		Type:     "k8s.pod",
		Name:     "web-ui-3a1",
		Provider: "kubernetes",
		Attributes: map[string]any{
			"image_sha": "sha256:deadbeefcafe",
		},
	})

	// One Trivy-emitted CVE finding pinned to the image.
	original := compliancekit.Finding{
		CheckID:  "ingest.trivy.CVE-2024-12345",
		Status:   compliancekit.StatusFail,
		Severity: compliancekit.SeverityHigh,
		Resource: compliancekit.ResourceRef{
			ID:   "container-image://abc123def456",
			Type: "container.image",
			Name: "acme/checkout:v1.4.2",
		},
		Vulnerability: &compliancekit.Vulnerability{
			ID:    "CVE-2024-12345",
			Image: "acme/checkout:v1.4.2",
		},
	}

	out, added := CorrelateImageSHA([]compliancekit.Finding{original}, graph)

	if added != 2 {
		t.Fatalf("added = %d, want 2 (Deployment + Pod)", added)
	}
	if len(out) != 3 { // original + 2 correlated
		t.Fatalf("len(out) = %d, want 3", len(out))
	}

	// First entry is the original; later entries are clones.
	if out[0].Resource.ID != "container-image://abc123def456" {
		t.Errorf("original swapped: %q", out[0].Resource.ID)
	}

	// Correlated clones must keep the same CheckID + Vulnerability
	// block but point at the K8s resource, and carry a running-on tag.
	deploymentClone := findByResourceType(out, "k8s.deployment")
	if deploymentClone == nil {
		t.Fatalf("no k8s.deployment clone")
	}
	if deploymentClone.CheckID != original.CheckID {
		t.Errorf("CheckID drifted: %q", deploymentClone.CheckID)
	}
	if deploymentClone.Vulnerability == nil || deploymentClone.Vulnerability.ID != "CVE-2024-12345" {
		t.Errorf("Vulnerability block lost in clone")
	}
	if !containsTag(deploymentClone.Tags, "image-sha-correlation") {
		t.Errorf("clone missing image-sha-correlation tag: %v", deploymentClone.Tags)
	}
	if !containsTag(deploymentClone.Tags, "running-on:k8s.deployment/checkout-api") {
		t.Errorf("clone missing running-on tag: %v", deploymentClone.Tags)
	}
}

func TestCorrelateImageSHA_ImageNameFallback(t *testing.T) {
	graph := compliancekit.NewResourceGraph()
	graph.Add(compliancekit.Resource{
		ID:       "do://apps/prod-api",
		Type:     "do.app.service",
		Name:     "prod-api",
		Provider: "digitalocean",
		Attributes: map[string]any{
			"image": "ghcr.io/acme/api:v2.0.0",
		},
	})

	f := compliancekit.Finding{
		CheckID:  "ingest.trivy.CVE-2024-1",
		Severity: compliancekit.SeverityHigh,
		Resource: compliancekit.ResourceRef{ID: "container-image://nonindexedsha"},
		Vulnerability: &compliancekit.Vulnerability{
			ID:    "CVE-2024-1",
			Image: "ghcr.io/acme/api:v2.0.0",
		},
	}
	out, added := CorrelateImageSHA([]compliancekit.Finding{f}, graph)
	if added != 1 {
		t.Fatalf("added = %d, want 1 (image-name fallback)", added)
	}
	if out[1].Resource.Type != "do.app.service" {
		t.Errorf("correlation resource type = %q", out[1].Resource.Type)
	}
}

func TestCorrelateImageSHA_NilGraph(t *testing.T) {
	out, added := CorrelateImageSHA([]compliancekit.Finding{{}}, nil)
	if added != 0 || len(out) != 1 {
		t.Errorf("nil graph should be no-op: added=%d out=%d", added, len(out))
	}
}

func findByResourceType(findings []compliancekit.Finding, kind string) *compliancekit.Finding {
	for i := range findings {
		if findings[i].Resource.Type == kind {
			return &findings[i]
		}
	}
	return nil
}

func containsTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
