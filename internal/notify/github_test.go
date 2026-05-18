package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func TestGitHub_NotConfigured(t *testing.T) {
	cases := []GitHubConfig{
		{Token: "", Repo: "owner/repo", PRNumber: 1},
		{Token: "x", Repo: "", PRNumber: 1},
		{Token: "x", Repo: "owner/repo", PRNumber: 0},
	}
	for i, c := range cases {
		if NewGitHub(c).Configured() {
			t.Errorf("case %d: should not be Configured: %+v", i, c)
		}
	}
	if !NewGitHub(GitHubConfig{Token: "x", Repo: "o/r", PRNumber: 1}).Configured() {
		t.Errorf("full config should be Configured")
	}
}

func TestGitHub_SummaryCommentShape(t *testing.T) {
	var captured struct {
		path string
		auth string
		body map[string]string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.path = r.URL.Path
		captured.auth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &captured.body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id": 12345}`))
	}))
	defer srv.Close()

	sink := NewGitHub(GitHubConfig{
		Token:         "ghp_test",
		Repo:          "acme/compliancekit",
		PRNumber:      42,
		APIURL:        srv.URL,
		SeverityFloor: compliancekit.SeverityInfo,
		HTTPClient:    srv.Client(),
	})
	notifications := BuildNotifications([]compliancekit.Finding{
		sampleFinding("aws-s3-public-access-block", "critical"),
		sampleFinding("aws-iam-root-mfa", "high"),
	}, BuildOptions{})

	res, err := sink.Send(context.Background(), notifications)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.Sent != 2 {
		t.Errorf("Sent = %d (one POST, but reports per-notification count); got %d", 2, res.Sent)
	}
	if captured.path != "/repos/acme/compliancekit/issues/42/comments" {
		t.Errorf("path = %q", captured.path)
	}
	if captured.auth != "Bearer ghp_test" {
		t.Errorf("auth = %q", captured.auth)
	}
	body := captured.body["body"]
	if !strings.Contains(body, "## compliancekit") || !strings.Contains(body, "2 actionable finding(s)") {
		t.Errorf("body header missing summary: %q", body)
	}
	if !strings.Contains(body, "aws-s3-public-access-block") || !strings.Contains(body, "aws-iam-root-mfa") {
		t.Errorf("body missing one or both CheckIDs: %q", body)
	}
}

func TestGitHub_403Surfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message": "Resource not accessible by integration"}`))
	}))
	defer srv.Close()

	sink := NewGitHub(GitHubConfig{
		Token:         "ghp_test",
		Repo:          "x/y",
		PRNumber:      1,
		APIURL:        srv.URL,
		SeverityFloor: compliancekit.SeverityInfo,
		HTTPClient:    srv.Client(),
	})
	notifications := BuildNotifications([]compliancekit.Finding{sampleFinding("x", "critical")}, BuildOptions{})
	res, err := sink.Send(context.Background(), notifications)
	if err == nil {
		t.Fatalf("expected ErrAuth wrapper, got nil")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("missing ErrAuth wrap: %v", err)
	}
	if res.Errors != 1 {
		t.Errorf("Errors = %d", res.Errors)
	}
}
