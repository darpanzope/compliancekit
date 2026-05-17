package notify

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate/tickets"
)

// JiraConfig configures the Jira notification sink. Reuses the v0.15
// internal/remediate/tickets.Jira client wholesale — every Jira API
// concern (REST v3 endpoint, basic auth, ADF body, severity →
// priority mapping) is already covered there.
//
// The difference between this sink and `compliancekit remediate
// --tickets` is intent: remediate files a ticket for every manual-
// remediation finding once; notify files for any actionable finding
// crossing the per-sink threshold every time `notify` runs. Dedup
// (Phase 10) prevents the same finding firing repeatedly.
//
// Env: JIRA_NOTIFY_* envs (separate from JIRA_* used by remediate
// so an operator can route remediation-tickets and notification-
// tickets to different projects). Falls back to JIRA_* when the
// notify-prefixed ones aren't set.
type JiraConfig struct {
	Host       string
	Email      string
	Token      string
	ProjectKey string
	IssueType  string

	SeverityFloor core.Severity
	HTTPClient    *http.Client
}

// Jira implements Notifier by adapting the v0.15 tickets.Jira client.
type Jira struct {
	cfg    JiraConfig
	client *tickets.Jira
}

// NewJira constructs a Jira sink. Holds a tickets.Jira instance
// internally so the per-call Send path stays small.
func NewJira(cfg JiraConfig) *Jira {
	client := tickets.NewJira(tickets.JiraConfig{
		Host:       cfg.Host,
		Email:      cfg.Email,
		Token:      cfg.Token,
		ProjectKey: cfg.ProjectKey,
		IssueType:  cfg.IssueType,
		HTTPClient: cfg.HTTPClient,
	})
	return &Jira{cfg: cfg, client: client}
}

// Name implements Notifier.
func (j *Jira) Name() string { return "jira" }

// Configured proxies to the underlying ticket client.
func (j *Jira) Configured() bool { return j.client.Configured() }

// Threshold returns the per-sink severity floor.
func (j *Jira) Threshold() core.Severity { return j.cfg.SeverityFloor }

// Send creates one Jira issue per notification. Per-notification
// failures accumulate in Result.Errors; top-level error only when
// every send failed.
func (j *Jira) Send(ctx context.Context, notifications []Notification) (Result, error) {
	var res Result
	for _, n := range notifications {
		ref, err := j.client.Create(ctx, tickets.Ticket{
			Title:       n.Title,
			Description: n.Body,
			Labels:      append([]string{"compliancekit", "notify"}, n.Tags...),
			Severity:    n.Finding.Severity,
			CheckID:     n.Finding.CheckID,
			ResourceID:  n.Finding.Resource.ID,
		})
		if err != nil {
			res.Errors++
			res.Messages = append(res.Messages, fmt.Sprintf("jira: %s — %v", n.Finding.CheckID, err))
			continue
		}
		res.Sent++
		res.Messages = append(res.Messages, fmt.Sprintf("jira: %s — %s (%s)", n.Finding.CheckID, ref.Key, ref.URL))
	}
	if res.Sent == 0 && res.Errors > 0 {
		return res, fmt.Errorf("jira: all %d sends failed", res.Errors)
	}
	return res, nil
}

// envOr returns the first non-empty env var from the list.
func envOr(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func init() {
	cfg := JiraConfig{
		Host:       envOr("JIRA_NOTIFY_HOST", "JIRA_HOST"),
		Email:      envOr("JIRA_NOTIFY_EMAIL", "JIRA_EMAIL"),
		Token:      envOr("JIRA_NOTIFY_TOKEN", "JIRA_TOKEN"),
		ProjectKey: envOr("JIRA_NOTIFY_PROJECT", "JIRA_PROJECT"),
		IssueType:  envOr("JIRA_NOTIFY_ISSUE_TYPE", "JIRA_ISSUE_TYPE"),
	}
	if t := os.Getenv("JIRA_NOTIFY_THRESHOLD"); t != "" {
		if sev, err := core.ParseSeverity(t); err == nil {
			cfg.SeverityFloor = sev
		}
	}
	Register(NewJira(cfg))
}
