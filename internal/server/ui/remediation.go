package ui

// v1.5 Phase 4 — Remediation studio.
//
// Routes:
//
//	GET /findings/{id}/remediation                   full-screen view
//	GET /findings/{id}/remediation/{format}/raw      text/plain dump
//	GET /findings/{id}/remediation/{format}/download Content-Disposition
//
// Layered on the existing v0.15 remediate registry (ADR-011): the
// registry already produces per-format Snippets keyed by RiskClass.
// This UI surface renders them as a tabbed view with copy + download
// + a "run in CI" hint per format.
//
// Phase 4 ships the surface; v1.5.x layers Prism-style syntax
// highlighting via per-language vanilla-JS tokenizers (~5 KB each)
// once the bundle-size budget is set.

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// remediationView is the per-page payload.
type remediationView struct {
	View
	Row      findingRow
	Snippets []remediationSnippet
	Empty    bool
}

// remediationSnippet is the per-format payload the template iterates.
type remediationSnippet struct {
	Format       string
	FormatLabel  string
	Risk         string
	Idempotent   bool
	Content      string
	Notes        string
	VerifyCmd    string
	RollbackCmd  string
	DownloadName string
}

// mountRemediationRoutes registers Phase 4 endpoints.
func (u *UI) mountRemediationRoutes(r chi.Router) {
	r.Get("/findings/{id}/remediation", u.remediationView)
	r.Get("/findings/{id}/remediation/{format}/raw", u.remediationRaw)
	r.Get("/findings/{id}/remediation/{format}/download", u.remediationDownload)
}

func (u *UI) remediationView(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row, err := u.loadFindingByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	snippets := u.buildRemediationSnippets(row)
	view := remediationView{
		View:     u.viewFor(r, "Remediation · "+row.CheckID, "findings", View{}),
		Row:      row,
		Snippets: snippets,
		Empty:    len(snippets) == 0,
	}
	u.render(w, "remediation.html", view)
}

func (u *UI) remediationRaw(w http.ResponseWriter, r *http.Request) {
	body, _, err := u.pickRemediationBody(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, body)
}

func (u *UI) remediationDownload(w http.ResponseWriter, r *http.Request) {
	body, filename, err := u.pickRemediationBody(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	fmt.Fprint(w, body)
}

func (u *UI) pickRemediationBody(r *http.Request) (body, filename string, err error) {
	id := chi.URLParam(r, "id")
	format := chi.URLParam(r, "format")
	row, err := u.loadFindingByID(r.Context(), id)
	if err != nil {
		return "", "", err
	}
	for _, sn := range u.buildRemediationSnippets(row) {
		if sn.Format == format {
			return sn.Content, sn.DownloadName, nil
		}
	}
	return "", "", fmt.Errorf("format not available")
}

// buildRemediationSnippets queries the remediate registry for every
// format that has a strategy registered for this check id. The
// registry was loaded at process start (init order) via the
// strategy subpackages (internal/remediate/strategies/*).
func (u *UI) buildRemediationSnippets(row findingRow) []remediationSnippet {
	// Hand the registry a synthetic Finding so the per-format
	// strategies can interpolate resource names. Provider lives on
	// ResourceRef in the v1.0 surface, not directly on Finding.
	f := compliancekit.Finding{
		CheckID: row.CheckID,
		Resource: compliancekit.ResourceRef{
			ID:       row.ResourceID,
			Name:     row.ResourceName,
			Type:     row.ResourceType,
			Provider: row.Provider,
		},
	}
	out := []remediationSnippet{}
	for _, format := range remediate.AllFormats {
		sn, err := remediate.Default.Render(f, format)
		if err != nil {
			continue
		}
		out = append(out, remediationSnippet{
			Format:       string(format),
			FormatLabel:  formatLabel(format),
			Risk:         string(sn.Risk),
			Idempotent:   sn.Idempotent,
			Content:      sn.Content,
			Notes:        sn.Notes,
			VerifyCmd:    sn.VerifyCmd,
			RollbackCmd:  sn.RollbackCmd,
			DownloadName: filenameFor(row.CheckID, format),
		})
	}
	return out
}

// formatLabel returns the human-readable tab label for a Format.
func formatLabel(f remediate.Format) string {
	switch f {
	case remediate.FormatBash:
		return "Bash"
	case remediate.FormatTerraform:
		return "Terraform"
	case remediate.FormatKubectl:
		return "kubectl"
	case remediate.FormatHelm:
		return "Helm"
	case remediate.FormatAnsible:
		return "Ansible"
	case remediate.FormatAWSCLI:
		return "AWS CLI"
	case remediate.FormatGCloud:
		return "gcloud"
	case remediate.FormatAzureCLI:
		return "az"
	case remediate.FormatDoctl:
		return "doctl"
	case remediate.FormatHcloud:
		return "hcloud"
	}
	return string(f)
}

// filenameFor returns a sensible filename for downloads. Mostly used
// by the operator to save a per-format snippet without renaming.
func filenameFor(checkID string, f remediate.Format) string {
	ext := "sh"
	switch f {
	case remediate.FormatTerraform:
		ext = "tf"
	case remediate.FormatHelm, remediate.FormatKubectl:
		ext = "yaml"
	case remediate.FormatAnsible:
		ext = "yml"
	}
	safe := strings.ReplaceAll(checkID, "/", "-")
	return safe + "." + string(f) + "." + ext
}
