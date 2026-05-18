package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/darpanzope/compliancekit/internal/engine"
	"github.com/darpanzope/compliancekit/internal/score"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// pushPayload is the request body POST /api/v1/scans/ingest accepts.
// Mirrors the daemon's scanRow shape plus a Findings array.
type pushPayload struct {
	Source             string                  `json:"source"`
	Status             string                  `json:"status"`
	StartedAt          string                  `json:"started_at,omitempty"`
	FinishedAt         string                  `json:"finished_at,omitempty"`
	ProvidersScanned   []string                `json:"providers_scanned"`
	FrameworksScanned  []string                `json:"frameworks_scanned"`
	Score              int                     `json:"score"`
	Coverage           int                     `json:"coverage"`
	TotalFindings      int                     `json:"total_findings"`
	ActionableFindings int                     `json:"actionable_findings"`
	DurationMS         int                     `json:"duration_ms"`
	Findings           []compliancekit.Finding `json:"findings"`
}

// pushResponse is what /api/v1/scans/ingest echoes back so the CLI
// can print the new scan ID for the operator's log.
type pushResponse struct {
	ScanID string `json:"scan_id"`
}

// pushToServer POSTs a completed scan's findings to a compliancekit
// daemon. Authentication via the operator-issued bearer token; URL
// is the daemon's base (e.g. https://compliance.acme.com). On
// success returns the daemon-side scan ID for the CLI summary.
//
// The daemon endpoint is /api/v1/scans/ingest (phase 10 adds it on
// the daemon side). It's distinct from POST /api/v1/scans which
// enqueues a fresh scan job — ingest takes already-completed work.
func pushToServer(ctx context.Context, baseURL, token string, result engine.Result, providers, frameworks []string) (string, error) {
	if baseURL == "" {
		return "", fmt.Errorf("push: baseURL is required")
	}
	if token == "" {
		return "", fmt.Errorf("push: api token is required (set --api-token=ck_... or CK_API_TOKEN env)")
	}

	sc := score.Compute(result.Findings)
	totals := countByActionable(result.Findings)

	payload := pushPayload{
		Source:             "cli",
		Status:             "completed",
		FinishedAt:         time.Now().UTC().Format(time.RFC3339),
		ProvidersScanned:   providers,
		FrameworksScanned:  frameworks,
		Score:              sc.Score,
		Coverage:           sc.Coverage,
		TotalFindings:      len(result.Findings),
		ActionableFindings: totals.actionable,
		Findings:           result.Findings,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	endpoint := baseURL + "/api/v1/scans/ingest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		errBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("push: %s — %s", resp.Status, string(errBody))
	}
	var out pushResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	return out.ScanID, nil
}

// countByActionable buckets findings by whether they're actionable
// (fail/error) and returns the count. Used to populate the daemon's
// scan summary columns without re-walking the slice elsewhere.
func countByActionable(findings []compliancekit.Finding) struct{ actionable, pass int } {
	var totals struct{ actionable, pass int }
	for _, f := range findings {
		if f.Status.IsActionable() {
			totals.actionable++
		} else if f.Status == compliancekit.StatusPass {
			totals.pass++
		}
	}
	return totals
}
