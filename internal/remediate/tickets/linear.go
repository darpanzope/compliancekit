package tickets

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/darpanzope/compliancekit/internal/core"
)

// LinearConfig captures everything needed to create a Linear issue
// via the GraphQL API. Reads via the CLI from LINEAR_API_KEY +
// LINEAR_TEAM_ID env vars at v0.15.
type LinearConfig struct {
	APIKey     string // personal or workspace API key
	TeamID     string // UUID of the target team
	HTTPClient *http.Client
}

// Linear is the Provider implementation.
type Linear struct {
	cfg LinearConfig
}

// NewLinear constructs a Linear provider.
func NewLinear(cfg LinearConfig) *Linear { return &Linear{cfg: cfg} }

// Name returns the provider identifier.
func (l *Linear) Name() string { return "linear" }

// Configured reports whether enough config is present to call the API.
func (l *Linear) Configured() bool {
	return l.cfg.APIKey != "" && l.cfg.TeamID != ""
}

// Create files a single Linear issue.
func (l *Linear) Create(ctx context.Context, t Ticket) (Ref, error) {
	if !l.Configured() {
		return Ref{}, fmt.Errorf("linear: not configured")
	}

	mutation := `mutation IssueCreate($input: IssueCreateInput!) {
  issueCreate(input: $input) {
    success
    issue { id identifier url }
  }
}`
	input := map[string]any{
		"teamId":      l.cfg.TeamID,
		"title":       t.Title,
		"description": t.Description,
		"priority":    linearPriority(t.Severity),
		"labelIds":    []string{}, // labels by ID — caller can extend
	}
	payload := map[string]any{
		"query":     mutation,
		"variables": map[string]any{"input": input},
	}

	headers := map[string]string{
		"Authorization": l.cfg.APIKey, // Linear accepts the key without a scheme prefix
	}

	var resp linearGQLResp
	if err := doJSON(ctx, l.cfg.HTTPClient, "POST", "https://api.linear.app/graphql", headers, payload, &resp); err != nil {
		return Ref{}, fmt.Errorf("linear create: %w", err)
	}
	if len(resp.Errors) > 0 {
		return Ref{}, fmt.Errorf("linear graphql: %s", resp.Errors[0].Message)
	}
	if !resp.Data.IssueCreate.Success {
		return Ref{}, fmt.Errorf("linear: issueCreate returned success=false")
	}
	issue := resp.Data.IssueCreate.Issue
	if issue.Identifier == "" || issue.URL == "" {
		return Ref{}, fmt.Errorf("linear: empty issue payload")
	}
	return Ref{
		Provider: "linear",
		Key:      issue.Identifier,
		URL:      issue.URL,
	}, nil
}

// linearPriority maps compliancekit severity onto Linear's enum
// (0 = none, 1 = urgent, 2 = high, 3 = medium, 4 = low).
func linearPriority(s core.Severity) int {
	switch s {
	case core.SeverityCritical:
		return 1
	case core.SeverityHigh:
		return 2
	case core.SeverityMedium:
		return 3
	case core.SeverityLow:
		return 4
	}
	return 0
}

type linearGQLResp struct {
	Data struct {
		IssueCreate struct {
			Success bool `json:"success"`
			Issue   struct {
				ID         string `json:"id"`
				Identifier string `json:"identifier"`
				URL        string `json:"url"`
			} `json:"issue"`
		} `json:"issueCreate"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors,omitempty"`
}

// trimSpace exposes strings.TrimSpace for tests; placeholder to keep
// import stable if the file shrinks. Unused at runtime.
var _ = strings.TrimSpace
