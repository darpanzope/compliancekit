// Package tui is the v1.7 Bubble Tea terminal client. Two source
// modes:
//   - file:   compliancekit tui --findings=path.json  (offline)
//   - daemon: compliancekit tui --server=URL --api-token=ck_…
//     (subscribes to /api/v1/events for live updates)
//
// v1.7 phase 0 ships the subcommand + the source abstraction + the
// minimum-viable list model (proof of life — operators can launch
// the TUI against a findings.json + scroll the list). Multi-pane
// layout, vim keybindings, in-place actions, live tail, resource-
// graph navigator, diff-vs-baseline mode, help overlay all layer
// on in phases 1-9.
//
// `internal/tui/` is the new home; `pkg/compliancekit` surface
// unchanged (TUI consumes the existing types directly per ADR-014).
package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Source abstracts where the TUI gets its findings + (in phase 3+)
// live event stream. Two implementations: fileSource for offline
// findings.json + daemonSource for a running daemon.
type Source interface {
	LoadFindings(ctx context.Context) ([]compliancekit.Finding, error)
	// Phase 3 will add Subscribe(events chan<- Event); for phase 0
	// the LoadFindings path is enough to drive a static list.
}

// fileSource reads a static findings.json from disk.
type fileSource struct{ path string }

// NewFileSource constructs a file-backed Source. Returns an error
// if the path doesn't exist so the caller fails fast (the bubbletea
// program would otherwise render an empty list silently).
func NewFileSource(path string) (Source, error) {
	if path == "" {
		return nil, errors.New("tui: --findings is required for file source")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("tui: stat %s: %w", path, err)
	}
	return &fileSource{path: path}, nil
}

func (s *fileSource) LoadFindings(_ context.Context) ([]compliancekit.Finding, error) {
	// #nosec G304 — operator-supplied findings path is the documented input.
	body, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("read findings: %w", err)
	}
	// findings.json carries {"findings": [...]} per the v0.3 reporter
	// contract; tolerate a top-level array too in case an operator
	// pipes from a custom emitter.
	var wrap struct {
		Findings []compliancekit.Finding `json:"findings"`
	}
	if err := json.Unmarshal(body, &wrap); err == nil && len(wrap.Findings) > 0 {
		return wrap.Findings, nil
	}
	var bare []compliancekit.Finding
	if err := json.Unmarshal(body, &bare); err != nil {
		return nil, fmt.Errorf("parse findings: %w", err)
	}
	return bare, nil
}

// daemonSource talks to a running daemon over the v1.3 REST API +
// (phase 3+) the v1.6 SSE event bus.
type daemonSource struct {
	baseURL  string
	apiToken string
	client   *http.Client
}

// NewDaemonSource constructs a daemon-backed Source.
func NewDaemonSource(baseURL, apiToken string) (Source, error) {
	if baseURL == "" {
		return nil, errors.New("tui: --server is required for daemon source")
	}
	if apiToken == "" {
		return nil, errors.New("tui: --api-token (or CK_API_TOKEN env) is required for daemon source")
	}
	return &daemonSource{
		baseURL:  baseURL,
		apiToken: apiToken,
		client:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (s *daemonSource) LoadFindings(ctx context.Context) ([]compliancekit.Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/api/v1/findings?per_page=500", http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.apiToken)
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("daemon GET /api/v1/findings: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("daemon /api/v1/findings: HTTP %d", resp.StatusCode)
	}
	var page struct {
		Items []apiFinding `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, fmt.Errorf("decode page: %w", err)
	}
	out := make([]compliancekit.Finding, 0, len(page.Items))
	for _, it := range page.Items {
		out = append(out, it.toFinding())
	}
	return out, nil
}

// apiFinding is the trimmed shape the v1.3 + v1.5.1-enriched API
// returns. We only pull the fields the v1.7 phase 0 list renderer
// uses; phases 5+ (in-place actions) consume more.
type apiFinding struct {
	ID           string `json:"id"`
	CheckID      string `json:"check_id"`
	CheckTitle   string `json:"check_title,omitempty"`
	Severity     string `json:"severity"`
	Status       string `json:"status"`
	Provider     string `json:"provider"`
	ResourceID   string `json:"resource_id"`
	ResourceName string `json:"resource_name"`
	ResourceType string `json:"resource_type"`
	Message      string `json:"message,omitempty"`
}

func (a apiFinding) toFinding() compliancekit.Finding {
	return compliancekit.Finding{
		CheckID:  a.CheckID,
		Severity: parseSeverity(a.Severity),
		Status:   compliancekit.Status(a.Status),
		Message:  a.Message,
		Resource: compliancekit.ResourceRef{
			ID:       a.ResourceID,
			Name:     a.ResourceName,
			Type:     a.ResourceType,
			Provider: a.Provider,
		},
	}
}

func parseSeverity(s string) compliancekit.Severity {
	switch s {
	case "critical":
		return compliancekit.SeverityCritical
	case "high":
		return compliancekit.SeverityHigh
	case "medium":
		return compliancekit.SeverityMedium
	case "low":
		return compliancekit.SeverityLow
	default:
		return compliancekit.SeverityInfo
	}
}

// Run boots the Bubble Tea program against src. Blocks until the
// user quits (q / ctrl-c / esc). v1.7 phase 0 ships a minimum-
// viable model (header + scrollable list); phases 1-9 layer panes,
// vim keys, actions.
func Run(ctx context.Context, src Source) error {
	findings, err := src.LoadFindings(ctx)
	if err != nil {
		return err
	}
	m := newListModel(findings)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err = p.Run()
	return err
}
