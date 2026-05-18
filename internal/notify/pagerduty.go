package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// PagerDutyConfig configures the PagerDuty Events v2 sink. PagerDuty
// is the canonical operational escalation channel — pages humans
// at 3 AM — so this sink defaults to a high severity floor (Critical
// only) to avoid waking on-call for non-actionable medium findings.
// Operators can lower the threshold if they want broader paging.
//
// Env: PAGERDUTY_INTEGRATION_KEY, PAGERDUTY_THRESHOLD,
// PAGERDUTY_EVENTS_URL (override for testing).
type PagerDutyConfig struct {
	// IntegrationKey is the Events API v2 routing key (32 hex chars).
	// Generated per-service in the PagerDuty UI.
	IntegrationKey string

	// Source identifies the producer in the PagerDuty event (default
	// "compliancekit"). Helps on-call distinguish multiple
	// notifications from the same service.
	Source string

	// EventsURL overrides the canonical https://events.pagerduty.com
	// endpoint. Tests inject a stub here.
	EventsURL string

	SeverityFloor compliancekit.Severity

	HTTPClient *http.Client
}

// PagerDuty implements Notifier for PagerDuty Events v2.
type PagerDuty struct{ cfg PagerDutyConfig }

// NewPagerDuty constructs a PagerDuty sink with sensible operational
// defaults: Critical-only severity, "compliancekit" source.
func NewPagerDuty(cfg PagerDutyConfig) *PagerDuty {
	if cfg.Source == "" {
		cfg.Source = "compliancekit"
	}
	if cfg.EventsURL == "" {
		cfg.EventsURL = "https://events.pagerduty.com/v2/enqueue"
	}
	if cfg.SeverityFloor == compliancekit.SeverityUnknown {
		// Zero-value of compliancekit.Severity is SeverityUnknown.
		// PagerDuty pages humans — default to critical-only to
		// avoid waking on-call on noise. Operators with a different
		// risk appetite override via PAGERDUTY_THRESHOLD.
		cfg.SeverityFloor = compliancekit.SeverityCritical
	}
	return &PagerDuty{cfg: cfg}
}

// Name implements Notifier.
func (p *PagerDuty) Name() string { return "pagerduty" }

// Configured returns true when the integration key is set.
func (p *PagerDuty) Configured() bool { return p.cfg.IntegrationKey != "" }

// Threshold returns the per-sink severity floor.
func (p *PagerDuty) Threshold() compliancekit.Severity { return p.cfg.SeverityFloor }

// Send dispatches one Events v2 enqueue per notification. PagerDuty
// dedups on dedup_key — we use the notification.Fingerprint so a
// re-firing finding updates the existing incident instead of opening
// a new one. Severity → PD severity mapping:
//
//	critical → critical
//	high     → error
//	medium   → warning
//	low/info → info
func (p *PagerDuty) Send(ctx context.Context, notifications []Notification) (Result, error) {
	var res Result
	for _, n := range notifications {
		if err := p.sendOne(ctx, n); err != nil {
			res.Errors++
			res.Messages = append(res.Messages, fmt.Sprintf("pagerduty: %s — %v", n.Finding.CheckID, err))
			continue
		}
		res.Sent++
		res.Messages = append(res.Messages, fmt.Sprintf("pagerduty: %s — triggered", n.Finding.CheckID))
	}
	if res.Sent == 0 && res.Errors > 0 {
		return res, fmt.Errorf("pagerduty: all %d sends failed", res.Errors)
	}
	return res, nil
}

func (p *PagerDuty) sendOne(ctx context.Context, n Notification) error {
	payload := map[string]any{
		"routing_key":  p.cfg.IntegrationKey,
		"event_action": "trigger",
		"dedup_key":    n.Fingerprint,
		"payload": map[string]any{
			"summary":   n.Title,
			"source":    p.cfg.Source,
			"severity":  pdSeverity(n.Finding.Severity),
			"timestamp": n.Finding.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
			"component": n.Finding.Resource.Type,
			"group":     n.Finding.Resource.Provider,
			"class":     n.Finding.CheckID,
			"custom_details": map[string]any{
				"check_id":    n.Finding.CheckID,
				"resource_id": n.Finding.Resource.ID,
				"message":     n.Finding.Message,
				"body":        n.Body,
				"tags":        n.Finding.Tags,
			},
		},
	}
	if n.URL != "" {
		payload["client_url"] = n.URL
		payload["client"] = "compliancekit"
	}

	client := p.cfg.HTTPClient
	if client == nil {
		client = HTTPClient
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.EventsURL, bytes.NewReader(raw))
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
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	}
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
}

// pdSeverity maps compliancekit severity to PagerDuty's enum.
// PagerDuty has only four levels: info, warning, error, critical.
func pdSeverity(s compliancekit.Severity) string {
	switch s {
	case compliancekit.SeverityCritical:
		return "critical"
	case compliancekit.SeverityHigh:
		return "error"
	case compliancekit.SeverityMedium:
		return "warning"
	}
	return "info"
}

func init() {
	cfg := PagerDutyConfig{
		IntegrationKey: os.Getenv("PAGERDUTY_INTEGRATION_KEY"),
		EventsURL:      os.Getenv("PAGERDUTY_EVENTS_URL"),
		Source:         os.Getenv("PAGERDUTY_SOURCE"),
	}
	if t := os.Getenv("PAGERDUTY_THRESHOLD"); t != "" {
		if sev, err := compliancekit.ParseSeverity(t); err == nil {
			cfg.SeverityFloor = sev
		}
	}
	Register(NewPagerDuty(cfg))
}
