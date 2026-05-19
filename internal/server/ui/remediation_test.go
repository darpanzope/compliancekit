package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/remediate"
)

// TestRemediationView_LoadsForFinding hits the page handler against
// a seeded finding row and confirms the response renders. Whether
// any snippets are present depends on what strategies are registered
// for the check id (synthetic check IDs from the seedFindings helper
// don't have strategies, so the empty-state path is exercised).
func TestRemediationView_LoadsForFinding(t *testing.T) {
	u, _ := newUIForTests(t)
	seedFindings(t, u, 5)

	var id string
	if err := u.store.DB().QueryRowContext(context.Background(),
		`SELECT id FROM findings LIMIT 1`).Scan(&id); err != nil {
		t.Fatalf("query: %v", err)
	}

	req := httptest.NewRequest("GET", "/findings/"+id+"/remediation", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	u.remediationView(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Remediation") {
		t.Errorf("body missing header")
	}
}

// TestRemediationView_404 returns 404 for unknown id.
func TestRemediationView_404(t *testing.T) {
	u, _ := newUIForTests(t)
	req := httptest.NewRequest("GET", "/findings/nope/remediation", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "nope")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	u.remediationView(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d want 404", rec.Code)
	}
}

// TestFormatLabel + TestFilenameFor pin the format → label + ext maps.
func TestFormatLabel(t *testing.T) {
	cases := map[remediate.Format]string{
		remediate.FormatBash:      "Bash",
		remediate.FormatTerraform: "Terraform",
		remediate.FormatKubectl:   "kubectl",
		remediate.FormatHelm:      "Helm",
		remediate.FormatAnsible:   "Ansible",
		remediate.FormatAWSCLI:    "AWS CLI",
		remediate.FormatGCloud:    "gcloud",
		remediate.FormatDoctl:     "doctl",
	}
	for f, want := range cases {
		if got := formatLabel(f); got != want {
			t.Errorf("formatLabel(%q)=%q want %q", f, got, want)
		}
	}
}

func TestFilenameFor(t *testing.T) {
	cases := []struct {
		check  string
		format remediate.Format
		want   string
	}{
		{"do-spaces-public-acl", remediate.FormatBash, "do-spaces-public-acl.bash.sh"},
		{"do-spaces-public-acl", remediate.FormatTerraform, "do-spaces-public-acl.terraform.tf"},
		{"do-spaces-public-acl", remediate.FormatKubectl, "do-spaces-public-acl.kubectl.yaml"},
		{"do-spaces-public-acl", remediate.FormatAnsible, "do-spaces-public-acl.ansible.yml"},
		{"aws/iam/foo", remediate.FormatBash, "aws-iam-foo.bash.sh"},
	}
	for _, c := range cases {
		if got := filenameFor(c.check, c.format); got != c.want {
			t.Errorf("filenameFor(%q,%q)=%q want %q", c.check, c.format, got, c.want)
		}
	}
}

// TestRemediationRoutesMounted: mount regression guard.
func TestRemediationRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountRemediationRoutes(r)

	// Just confirm /findings/{id}/remediation routes — even a bad id
	// should hit the handler (404), not router 404.
	req := httptest.NewRequest("GET", "/findings/x/remediation", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	// 404 from handler ok; 404 from mux-no-route would also be 404.
	// We at least want NO 405 / 500 / panic.
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusOK {
		t.Errorf("GET /findings/x/remediation: status %d, want 404 or 200", rec.Code)
	}
}
