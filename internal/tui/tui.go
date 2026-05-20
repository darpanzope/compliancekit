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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Source abstracts where the TUI gets its findings + (phase 3) the
// live event stream that drives :tail mode.
//
// fileSource implements both: LoadFindings reads disk, Subscribe is
// a no-op (offline mode has nothing live to stream).
// daemonSource implements both: LoadFindings calls /api/v1/findings,
// Subscribe opens an SSE connection against /api/v1/events + decodes
// finding.created event payloads into compliancekit.Finding values.
type Source interface {
	LoadFindings(ctx context.Context) ([]compliancekit.Finding, error)
	Subscribe(ctx context.Context, ch chan<- compliancekit.Finding) error
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

// Subscribe is a no-op on a fileSource — offline mode has no live
// updates to stream. Returning nil immediately is the documented
// contract; callers should fall back to LoadFindings + re-render
// when an operator manually re-runs the scan.
func (s *fileSource) Subscribe(_ context.Context, _ chan<- compliancekit.Finding) error {
	return nil
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

// Subscribe opens an SSE connection to the daemon's
// /api/v1/events stream + decodes finding.created payloads into
// compliancekit.Finding values pushed to ch. v1.7 phase 3.
//
// The payload shape from RealRunner.persistFindings:
//
//	{"id":N,"type":"finding.created","at":"…","entity_id":"…",
//	 "data":{"scan_id":"…","check_id":"…","severity":"…",
//	         "status":"…","provider":"…","resource":"…"}}
//
// Carries enough to hydrate a Finding for the TUI's tail panel
// without an extra round-trip to /api/v1/findings/{id}.
//
// Returns when ctx is canceled OR the server closes the stream.
// Callers should wrap in a goroutine + retry on disconnect (the
// model's tail mode handles that).
func (s *daemonSource) Subscribe(ctx context.Context, ch chan<- compliancekit.Finding) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.baseURL+"/api/v1/events", http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.apiToken)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	// SSE is open-ended; per-request timeout is not appropriate.
	client := &http.Client{Timeout: 0}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("daemon /api/v1/events: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("daemon /api/v1/events: HTTP %d", resp.StatusCode)
	}

	// SSE framing: lines starting `event:` set the event name + lines
	// starting `data:` carry the JSON payload. A blank line terminates
	// the event; comment lines start with `:` and are skipped.
	scanner := bufio.NewScanner(resp.Body)
	// 256 KB max per event line; the bus's per-event payload is < 1 KB
	// today but we leave headroom for phase-2 scan.progress.
	scanner.Buffer(make([]byte, 0, 4096), 256*1024)
	var (
		eventName string
		dataLine  string
	)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, ":"):
			continue // heartbeat / comment
		case strings.HasPrefix(line, "event:"):
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			dataLine = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		case line == "":
			if eventName == "finding.created" && dataLine != "" {
				if f, ok := parseFindingCreated(dataLine); ok {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case ch <- f:
					}
				}
			}
			eventName, dataLine = "", ""
		}
	}
	return scanner.Err()
}

// parseFindingCreated decodes one finding.created data line.
func parseFindingCreated(data string) (compliancekit.Finding, bool) {
	var env struct {
		EntityID string `json:"entity_id"`
		Data     struct {
			ScanID   string `json:"scan_id"`
			CheckID  string `json:"check_id"`
			Severity string `json:"severity"`
			Status   string `json:"status"`
			Provider string `json:"provider"`
			Resource string `json:"resource"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(data), &env); err != nil {
		return compliancekit.Finding{}, false
	}
	return compliancekit.Finding{
		CheckID:  env.Data.CheckID,
		Severity: parseSeverity(env.Data.Severity),
		Status:   compliancekit.Status(env.Data.Status),
		Resource: compliancekit.ResourceRef{
			ID:       env.Data.Resource,
			Name:     env.Data.Resource,
			Provider: env.Data.Provider,
		},
	}, true
}

// liveFindingMsg is the tea.Msg the model's tail mode receives for
// each incoming finding.created event. The cmd that produces these
// is wired in model.go via Subscribe in a goroutine + a channel
// drainer.
type liveFindingMsg compliancekit.Finding

// waitForFindingCmd blocks the bubbletea command pipe on the next
// channel receive. Re-issued by the model after each delivery so
// the program keeps draining the bus.
func waitForFindingCmd(ch <-chan compliancekit.Finding) tea.Cmd {
	return func() tea.Msg {
		f, ok := <-ch
		if !ok {
			return tailEndedMsg{}
		}
		return liveFindingMsg(f)
	}
}

// tailEndedMsg signals the channel closed (subscriber disconnect).
type tailEndedMsg struct{}

// Run boots the Bubble Tea program against src. Blocks until the
// user quits (q / ctrl-c / esc). The model owns whether to call
// :tail mode (which fires subscribeCmd against src).
func Run(ctx context.Context, src Source) error {
	findings, err := src.LoadFindings(ctx)
	if err != nil {
		return err
	}
	m := newListModel(findings)
	m.src = src
	m.ctx = ctx
	// Suppress unused warnings — ctx + time are reserved for phase-5
	// in-place-action timeouts.
	_ = time.Second
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err = p.Run()
	return err
}
