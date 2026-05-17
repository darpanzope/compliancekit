package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/darpanzope/compliancekit/internal/core"
)

// SlackConfig configures the Slack sink. Two delivery paths, both
// supported simultaneously: webhook (no auth header, no channel
// selection) and bot-token (PostMessage API with per-channel control).
// Env vars: SLACK_WEBHOOK_URL, SLACK_BOT_TOKEN, SLACK_CHANNEL,
// SLACK_THRESHOLD (severity string).
type SlackConfig struct {
	// WebhookURL is the canonical incoming-webhook URL. Used when
	// the operator only needs notifications to land in one channel.
	WebhookURL string

	// BotToken (xoxb-…) is the API token for chat.postMessage.
	// Used when the operator needs per-channel routing or thread
	// replies. Requires the chat:write scope.
	BotToken string

	// Channel is the destination when using BotToken. Accepts "#name"
	// or a channel ID. Ignored when WebhookURL is set.
	Channel string

	// SeverityFloor is the per-sink threshold. Notifications below
	// this severity are dropped. Defaults to SeverityInfo (everything
	// actionable passes) when zero-value.
	SeverityFloor core.Severity

	// HTTPClient overrides the package HTTPClient. Tests set this.
	HTTPClient *http.Client
}

// Slack implements Notifier.
type Slack struct {
	cfg SlackConfig
}

// NewSlack constructs a Slack sink. The returned sink reports
// Configured()=false when both WebhookURL and (BotToken+Channel)
// are empty — caller can still pass it to Default safely and the
// dispatcher will skip it.
func NewSlack(cfg SlackConfig) *Slack { return &Slack{cfg: cfg} }

// Name implements Notifier.
func (s *Slack) Name() string { return "slack" }

// Configured returns true when either delivery path has credentials.
func (s *Slack) Configured() bool {
	if s.cfg.WebhookURL != "" {
		return true
	}
	return s.cfg.BotToken != "" && s.cfg.Channel != ""
}

// Threshold returns the per-sink severity floor.
func (s *Slack) Threshold() core.Severity { return s.cfg.SeverityFloor }

// Send dispatches the notifications. Per-notification failures
// accumulate in Result.Errors + Result.Messages; the call returns
// nil error unless every send failed (transport / auth).
func (s *Slack) Send(ctx context.Context, notifications []Notification) (Result, error) {
	var res Result
	for _, n := range notifications {
		if err := s.sendOne(ctx, n); err != nil {
			res.Errors++
			res.Messages = append(res.Messages, fmt.Sprintf("slack: %s — %v", n.Finding.CheckID, err))
			continue
		}
		res.Sent++
		res.Messages = append(res.Messages, fmt.Sprintf("slack: %s — sent", n.Finding.CheckID))
	}
	if res.Sent == 0 && res.Errors > 0 {
		return res, fmt.Errorf("slack: all %d sends failed", res.Errors)
	}
	return res, nil
}

// sendOne picks the delivery path + POSTs the payload. Webhook path
// is simpler + does not require auth header; bot-token path uses
// chat.postMessage with channel routing.
func (s *Slack) sendOne(ctx context.Context, n Notification) error {
	payload := s.buildPayload(n)
	if s.cfg.WebhookURL != "" {
		return s.postJSON(ctx, s.cfg.WebhookURL, payload, nil)
	}
	headers := map[string]string{
		"Authorization": "Bearer " + s.cfg.BotToken,
	}
	payload["channel"] = s.cfg.Channel
	return s.postJSON(ctx, "https://slack.com/api/chat.postMessage", payload, headers)
}

// buildPayload renders Notification → Slack Block Kit JSON. Blocks
// chosen for legibility in mobile + desktop:
//
//   - section block with the title + severity emoji
//   - section block with the body markdown
//   - actions block with a "View finding" button when URL is set
//
// Slack's `text` field is the fallback for notifications that don't
// render blocks (push notifications, screen readers); we set it to
// the Title.
func (s *Slack) buildPayload(n Notification) map[string]any {
	blocks := []map[string]any{
		{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": fmt.Sprintf("%s *%s*", severityEmoji(n.Finding.Severity), n.Title),
			},
		},
		{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": n.Body,
			},
		},
	}
	if n.URL != "" {
		blocks = append(blocks, map[string]any{
			"type": "actions",
			"elements": []map[string]any{
				{
					"type": "button",
					"text": map[string]any{"type": "plain_text", "text": "View finding"},
					"url":  n.URL,
				},
			},
		})
	}
	return map[string]any{
		"text":   n.Title, // notification fallback
		"blocks": blocks,
	}
}

// postJSON marshals + POSTs body to url with headers + Slack-specific
// error handling. Slack returns 200 even for application errors
// (the response body's `ok` field), so we parse that.
func (s *Slack) postJSON(ctx context.Context, url string, body map[string]any, headers map[string]string) error {
	client := s.cfg.HTTPClient
	if client == nil {
		client = HTTPClient
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: %s", ErrAuth, string(respBody))
	case http.StatusOK:
		// Slack's chat.postMessage returns 200 with {"ok": false} on
		// application errors. Webhooks return 200 with body "ok"
		// on success and a plain-text error otherwise.
		return s.checkSlackResponse(respBody)
	}
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
}

// checkSlackResponse parses the two Slack response shapes and
// returns an error iff the upstream reported a failure.
func (s *Slack) checkSlackResponse(body []byte) error {
	if len(body) == 0 {
		return nil
	}
	// Webhook path: body is literally "ok" on success.
	if string(body) == "ok" {
		return nil
	}
	// API path: JSON object with `ok: true|false`.
	var parsed struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		// Webhook returns plain-text errors ("no_service", "invalid_payload");
		// surface the body verbatim.
		return fmt.Errorf("slack: %s", string(body))
	}
	if parsed.OK {
		return nil
	}
	return fmt.Errorf("slack: %s", parsed.Error)
}

// severityEmoji maps severity to a one-glyph indicator. Slack
// renders emoji via shortcodes; we keep the lookup small + universal.
func severityEmoji(s core.Severity) string {
	switch s {
	case core.SeverityCritical:
		return ":rotating_light:"
	case core.SeverityHigh:
		return ":warning:"
	case core.SeverityMedium:
		return ":small_orange_diamond:"
	case core.SeverityLow:
		return ":information_source:"
	}
	return ":speech_balloon:"
}

// init registers Slack into Default when env vars are present. Empty
// env vars produce a Configured()=false sink that the dispatcher
// skips silently — safe to always register.
func init() {
	cfg := SlackConfig{
		WebhookURL: os.Getenv("SLACK_WEBHOOK_URL"),
		BotToken:   os.Getenv("SLACK_BOT_TOKEN"),
		Channel:    os.Getenv("SLACK_CHANNEL"),
	}
	if t := os.Getenv("SLACK_THRESHOLD"); t != "" {
		if sev, err := core.ParseSeverity(t); err == nil {
			cfg.SeverityFloor = sev
		}
	}
	Register(NewSlack(cfg))
}
