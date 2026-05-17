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

// DiscordConfig configures the Discord sink. Discord uses webhook
// URLs exclusively for outbound notifications; the bot-token API
// requires a Gateway connection which is out of scope.
//
// Env: DISCORD_WEBHOOK_URL, DISCORD_THRESHOLD.
type DiscordConfig struct {
	WebhookURL    string
	SeverityFloor core.Severity
	HTTPClient    *http.Client
}

// Discord implements Notifier for Discord incoming webhooks.
type Discord struct{ cfg DiscordConfig }

// NewDiscord constructs a Discord sink.
func NewDiscord(cfg DiscordConfig) *Discord { return &Discord{cfg: cfg} }

// Name implements Notifier.
func (d *Discord) Name() string { return "discord" }

// Configured returns true when the webhook URL is set.
func (d *Discord) Configured() bool { return d.cfg.WebhookURL != "" }

// Threshold returns the per-sink severity floor.
func (d *Discord) Threshold() core.Severity { return d.cfg.SeverityFloor }

// Send dispatches the notifications via the webhook. Per-notification
// failures accumulate; top-level error only when every send failed.
func (d *Discord) Send(ctx context.Context, notifications []Notification) (Result, error) {
	var res Result
	for _, n := range notifications {
		if err := d.sendOne(ctx, n); err != nil {
			res.Errors++
			res.Messages = append(res.Messages, fmt.Sprintf("discord: %s — %v", n.Finding.CheckID, err))
			continue
		}
		res.Sent++
		res.Messages = append(res.Messages, fmt.Sprintf("discord: %s — sent", n.Finding.CheckID))
	}
	if res.Sent == 0 && res.Errors > 0 {
		return res, fmt.Errorf("discord: all %d sends failed", res.Errors)
	}
	return res, nil
}

// sendOne POSTs a single notification. Discord embed shape:
//
//   - title = Notification.Title
//   - description = Notification.Body
//   - color = severity-mapped 24-bit RGB int
//   - url = Notification.URL (link applied to title)
//   - footer = "compliancekit"
func (d *Discord) sendOne(ctx context.Context, n Notification) error {
	embed := map[string]any{
		"title":       n.Title,
		"description": n.Body,
		"color":       discordSeverityColor(n.Finding.Severity),
	}
	if n.URL != "" {
		embed["url"] = n.URL
	}
	embed["footer"] = map[string]any{"text": "compliancekit"}
	payload := map[string]any{
		"username": "compliancekit",
		"embeds":   []map[string]any{embed},
	}
	return d.postJSON(ctx, payload)
}

func (d *Discord) postJSON(ctx context.Context, body map[string]any) error {
	client := d.cfg.HTTPClient
	if client == nil {
		client = HTTPClient
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.cfg.WebhookURL, bytes.NewReader(raw))
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
	case resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK:
		return nil
	}
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
}

// discordSeverityColor maps severity onto the 24-bit RGB int Discord
// expects. Critical = red, high = orange, medium = yellow, low =
// blue, info/unknown = gray.
func discordSeverityColor(s core.Severity) int {
	switch s {
	case core.SeverityCritical:
		return 0xD7263D
	case core.SeverityHigh:
		return 0xF46036
	case core.SeverityMedium:
		return 0xF7B538
	case core.SeverityLow:
		return 0x2E86AB
	}
	return 0x808080
}

func init() {
	cfg := DiscordConfig{WebhookURL: os.Getenv("DISCORD_WEBHOOK_URL")}
	if t := os.Getenv("DISCORD_THRESHOLD"); t != "" {
		if sev, err := core.ParseSeverity(t); err == nil {
			cfg.SeverityFloor = sev
		}
	}
	Register(NewDiscord(cfg))
}
