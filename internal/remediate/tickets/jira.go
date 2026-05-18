package tickets

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// JiraConfig captures everything needed to create an issue in a Jira
// Cloud instance. Reads via the CLI from JIRA_HOST / JIRA_EMAIL /
// JIRA_TOKEN / JIRA_PROJECT env vars at v0.15.
type JiraConfig struct {
	Host       string // e.g. "acme.atlassian.net" (no scheme)
	Email      string // service-account email
	Token      string // API token from https://id.atlassian.com/manage-profile/security/api-tokens
	ProjectKey string // e.g. "SEC"
	IssueType  string // defaults to "Task"
	HTTPClient *http.Client
}

// Jira is the Provider implementation.
type Jira struct {
	cfg JiraConfig
}

// NewJira constructs a Jira provider. Returns the provider with
// IsConfigured() == false when required fields are missing; the
// caller can register it unconditionally and skip silently when
// credentials aren't available.
func NewJira(cfg JiraConfig) *Jira {
	if cfg.IssueType == "" {
		cfg.IssueType = "Task"
	}
	return &Jira{cfg: cfg}
}

// Name returns the provider identifier.
func (j *Jira) Name() string { return "jira" }

// Configured reports whether enough config is present to call the
// upstream. Missing host or token = not configured = caller skips.
func (j *Jira) Configured() bool {
	return j.cfg.Host != "" && j.cfg.Email != "" && j.cfg.Token != "" && j.cfg.ProjectKey != ""
}

// Create files a single Jira issue. Returns Ref{Provider="jira",
// Key="<PROJECT>-<N>", URL="https://<host>/browse/<KEY>"} on success.
func (j *Jira) Create(ctx context.Context, t Ticket) (Ref, error) {
	if !j.Configured() {
		return Ref{}, fmt.Errorf("jira: not configured")
	}
	url := fmt.Sprintf("https://%s/rest/api/3/issue", j.cfg.Host)
	auth := base64.StdEncoding.EncodeToString([]byte(j.cfg.Email + ":" + j.cfg.Token))
	headers := map[string]string{
		"Authorization": "Basic " + auth,
	}
	payload := jiraIssue{
		Fields: jiraFields{
			Project:     jiraKey{Key: j.cfg.ProjectKey},
			Summary:     t.Title,
			Description: adfDocFromMarkdown(t.Description),
			IssueType:   jiraName{Name: j.cfg.IssueType},
			Priority:    jiraName{Name: jiraPriority(t.Severity)},
			Labels:      t.Labels,
		},
	}
	var resp jiraCreateResp
	if err := doJSON(ctx, j.cfg.HTTPClient, "POST", url, headers, payload, &resp); err != nil {
		return Ref{}, fmt.Errorf("jira create: %w", err)
	}
	return Ref{
		Provider: "jira",
		Key:      resp.Key,
		URL:      fmt.Sprintf("https://%s/browse/%s", j.cfg.Host, resp.Key),
	}, nil
}

// jiraPriority maps compliancekit severity to Jira's stock priority
// names. Jira allows custom priorities — this only works for stock
// instances; on customized Jira a strategy-level Priority override
// would be the next step.
func jiraPriority(s compliancekit.Severity) string {
	switch s {
	case compliancekit.SeverityCritical:
		return "Highest"
	case compliancekit.SeverityHigh:
		return "High"
	case compliancekit.SeverityMedium:
		return "Medium"
	case compliancekit.SeverityLow:
		return "Low"
	}
	return "Medium"
}

// adfDocFromMarkdown wraps a plain-text description in Atlassian
// Document Format (ADF) — the body shape REST API v3 requires.
// We don't parse markdown; we wrap it as a single code block so the
// formatting survives Jira's renderer. Strategies needing rich
// formatting can populate Notes specifically with ADF later.
func adfDocFromMarkdown(s string) adfDocument {
	return adfDocument{
		Type:    "doc",
		Version: 1,
		Content: []adfNode{{
			Type:  "codeBlock",
			Attrs: map[string]string{"language": "text"},
			Content: []adfNode{{
				Type: "text",
				Text: strings.TrimSpace(s),
			}},
		}},
	}
}

type jiraIssue struct {
	Fields jiraFields `json:"fields"`
}
type jiraFields struct {
	Project     jiraKey     `json:"project"`
	Summary     string      `json:"summary"`
	Description adfDocument `json:"description"`
	IssueType   jiraName    `json:"issuetype"`
	Priority    jiraName    `json:"priority"`
	Labels      []string    `json:"labels"`
}
type jiraKey struct {
	Key string `json:"key"`
}
type jiraName struct {
	Name string `json:"name"`
}
type jiraCreateResp struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

// Atlassian Document Format (minimal subset).
type adfDocument struct {
	Type    string    `json:"type"`
	Version int       `json:"version"`
	Content []adfNode `json:"content"`
}
type adfNode struct {
	Type    string            `json:"type"`
	Attrs   map[string]string `json:"attrs,omitempty"`
	Content []adfNode         `json:"content,omitempty"`
	Text    string            `json:"text,omitempty"`
}
