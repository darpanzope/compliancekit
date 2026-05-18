package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// TeamsConfig configures the Microsoft Teams sink. Microsoft has
// two webhook flavors:
//
//  1. Incoming Webhook connectors — the legacy MessageCard format.
//     Wide deployment; deprecated by Microsoft but still supported.
//  2. Workflows-based webhooks — Adaptive Card payload.
//
// We ship MessageCard at v0.17 because the deprecation timeline
// (October 2026) leaves room to migrate, and most enterprise
// deployments still use legacy connectors. Adaptive Card support
// is a v0.18+ enhancement.
//
// Env: TEAMS_WEBHOOK_URL, TEAMS_THRESHOLD.
type TeamsConfig struct {
	WebhookURL    string
	SeverityFloor compliancekit.Severity
	HTTPClient    *http.Client
}

// Teams implements Notifier for Microsoft Teams incoming-webhook
// connectors (MessageCard payload).
type Teams struct{ cfg TeamsConfig }

// NewTeams constructs a Teams sink.
func NewTeams(cfg TeamsConfig) *Teams { return &Teams{cfg: cfg} }

// Name implements Notifier.
func (t *Teams) Name() string { return "teams" }

// Configured returns true when WebhookURL is set.
func (t *Teams) Configured() bool { return t.cfg.WebhookURL != "" }

// Threshold returns the per-sink severity floor.
func (t *Teams) Threshold() compliancekit.Severity { return t.cfg.SeverityFloor }

// Send dispatches the notifications. Per-notification failures
// accumulate; top-level error only when every send failed.
func (t *Teams) Send(ctx context.Context, notifications []Notification) (Result, error) {
	var res Result
	for _, n := range notifications {
		if err := t.sendOne(ctx, n); err != nil {
			res.Errors++
			res.Messages = append(res.Messages, fmt.Sprintf("teams: %s — %v", n.Finding.CheckID, err))
			continue
		}
		res.Sent++
		res.Messages = append(res.Messages, fmt.Sprintf("teams: %s — sent", n.Finding.CheckID))
	}
	if res.Sent == 0 && res.Errors > 0 {
		return res, fmt.Errorf("teams: all %d sends failed", res.Errors)
	}
	return res, nil
}

// sendOne POSTs a MessageCard payload. Teams' MessageCard schema:
// https://learn.microsoft.com/en-us/outlook/actionable-messages/message-card-reference
//
// We use a single section with the title + body, and an
// OpenUri action when URL is set.
func (t *Teams) sendOne(ctx context.Context, n Notification) error {
	payload := map[string]any{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"summary":    n.Title,
		"themeColor": teamsSeverityColor(n.Finding.Severity),
		"title":      n.Title,
		"sections": []map[string]any{
			{
				"activityTitle":    fmt.Sprintf("Severity: **%s**", n.Finding.Severity),
				"activitySubtitle": fmt.Sprintf("Check: %s", n.Finding.CheckID),
				"text":             teamsConvertMarkdown(n.Body),
			},
		},
	}
	if n.URL != "" {
		payload["potentialAction"] = []map[string]any{
			{
				"@type":   "OpenUri",
				"name":    "View finding",
				"targets": []map[string]any{{"os": "default", "uri": n.URL}},
			},
		}
	}
	return t.postJSON(ctx, payload)
}

// teamsConvertMarkdown adapts CommonMark to Teams' MessageCard
// markdown subset. Teams renders most markdown natively but does
// NOT support fenced code blocks reliably across mobile; convert
// `**bold**` to `**bold**` (passthrough) but strip the leading
// ` - ` bullet to a discrete-bullet glyph since Teams' bullet
// rendering varies by client.
func teamsConvertMarkdown(body string) string {
	out := body
	// Strip leading "- " in bullets — Teams renders `\n - ` weirdly.
	// We've already structured the body; this is a robustness step.
	out = strings.ReplaceAll(out, "\n- ", "\n• ")
	return out
}

func (t *Teams) postJSON(ctx context.Context, body map[string]any) error {
	client := t.cfg.HTTPClient
	if client == nil {
		client = HTTPClient
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.cfg.WebhookURL, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w: %s", ErrAuth, string(respBody))
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted:
		return nil
	}
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
}

// teamsSeverityColor returns the hex string Teams' themeColor field
// expects (no leading '#'). Same palette as Discord, restated for
// portability since the two sinks may diverge later.
func teamsSeverityColor(s compliancekit.Severity) string {
	switch s {
	case compliancekit.SeverityCritical:
		return "D7263D"
	case compliancekit.SeverityHigh:
		return "F46036"
	case compliancekit.SeverityMedium:
		return "F7B538"
	case compliancekit.SeverityLow:
		return "2E86AB"
	}
	return "808080"
}

func init() {
	cfg := TeamsConfig{WebhookURL: os.Getenv("TEAMS_WEBHOOK_URL")}
	if t := os.Getenv("TEAMS_THRESHOLD"); t != "" {
		if sev, err := compliancekit.ParseSeverity(t); err == nil {
			cfg.SeverityFloor = sev
		}
	}
	Register(NewTeams(cfg))
}
