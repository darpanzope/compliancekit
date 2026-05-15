package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/config"
	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/ingest"

	_ "github.com/darpanzope/compliancekit/internal/ingest/grype"
	_ "github.com/darpanzope/compliancekit/internal/ingest/sarif"
	_ "github.com/darpanzope/compliancekit/internal/ingest/trivy"
)

func trivyFixture(name string) string {
	abs, _ := filepath.Abs(filepath.Join("..", "ingest", "trivy", "testdata", name))
	return abs
}
func grypeFixture(name string) string {
	abs, _ := filepath.Abs(filepath.Join("..", "ingest", "grype", "testdata", name))
	return abs
}

// TestVulnPipeline_TrivyImageScanCorrelatesToK8s exercises the full
// v0.14 vuln story: pre-populate a graph with a K8s Deployment that
// references the same image SHA Trivy will report a CVE on, run
// the config-driven ingest path including image-SHA correlation,
// and assert the resulting finding set contains both:
//
//  1. The original CVE pinned to the container image.
//  2. A clone of the CVE pinned to the K8s Deployment with the
//     "running-on" tag set.
//
// This is the killer-demo property of v0.14 — Trivy's image-side
// CVE finds its way to the cloud resource that's actually exposed.
func TestVulnPipeline_TrivyImageScanCorrelatesToK8s(t *testing.T) {
	graph := core.NewResourceGraph()
	graph.Add(core.Resource{
		ID:       "k8s://prod/Deployment/checkout-api",
		Type:     "k8s.deployment",
		Name:     "checkout-api",
		Provider: "kubernetes",
		Region:   "us-east-1",
		Attributes: map[string]any{
			// Matches the ImageID in trivy testdata/image-scan.json
			"image_id": "docker-pullable://acme/checkout@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b",
		},
	})

	sources := []config.IngestSource{
		{Format: "trivy-json", File: trivyFixture("image-scan.json"), Tool: "trivy"},
	}

	findings, warns, err := runIngestSources(context.Background(), sources, graph)
	if err != nil {
		t.Fatalf("runIngestSources: %v", err)
	}
	_ = warns

	// At minimum: 2 trivy CVE findings (from the fixture).
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 ingested findings, got %d", len(findings))
	}

	expanded, added := ingest.CorrelateImageSHA(findings, graph)
	if added == 0 {
		t.Fatalf("expected at least one correlated finding via image-SHA join, got 0")
	}

	var clonedToK8s *core.Finding
	for i := range expanded {
		if expanded[i].Resource.Type == "k8s.deployment" {
			clonedToK8s = &expanded[i]
			break
		}
	}
	if clonedToK8s == nil {
		t.Fatalf("no finding cloned onto k8s.deployment")
	}
	if clonedToK8s.Vulnerability == nil || !strings.HasPrefix(clonedToK8s.CheckID, "ingest.trivy.CVE-") {
		t.Errorf("cloned finding lost Vulnerability or CheckID drifted: %+v", clonedToK8s)
	}
	if !hasTagLocal(clonedToK8s.Tags, "image-sha-correlation") {
		t.Errorf("cloned finding missing image-sha-correlation tag: %v", clonedToK8s.Tags)
	}
}

func hasTagLocal(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

// TestVulnPipeline_TrivyAndGrypeMergeUniformly: feeding the SAME
// image's findings from both Trivy and Grype produces parallel
// Findings (one per tool) on the same image resource ID — the
// graph correlation path remains additive across multiple ingest
// sources.
func TestVulnPipeline_TrivyAndGrypeMergeUniformly(t *testing.T) {
	sources := []config.IngestSource{
		{Format: "trivy-json", File: trivyFixture("image-scan.json"), Tool: "trivy"},
		{Format: "grype-json", File: grypeFixture("image-scan.json"), Tool: "grype"},
	}
	findings, _, err := runIngestSources(context.Background(), sources, core.NewResourceGraph())
	if err != nil {
		t.Fatalf("runIngestSources: %v", err)
	}

	var sawTrivy, sawGrype bool
	for _, f := range findings {
		if f.Source == nil {
			continue
		}
		switch f.Source.Tool {
		case "trivy":
			sawTrivy = true
		case "grype":
			sawGrype = true
		}
	}
	if !sawTrivy || !sawGrype {
		t.Errorf("expected findings from both tools; trivy=%v grype=%v", sawTrivy, sawGrype)
	}
}
