package tui

// v1.7 phase 5 — in-place actions. Four keybindings in normal mode
// when the list or detail pane is focused:
//
//   w   waive the focused finding (prompts for reason; daemon
//       POSTs /api/v1/waivers, file mode prints YAML)
//   a   acknowledge the focused finding (flash for now;
//       comment-thread persistence ships at v1.8 collaboration)
//   c   comment on the focused finding (flash for now; opens
//       $EDITOR at v1.8 collaboration)
//   r   remediate-preview — renders the bash strategy for the
//       focused check into a temporary overlay
//
// w + r are end-to-end useful at v1.7; a + c are flash-only
// because the daemon's comment + ack persistence are a v1.8
// scope item (Collaboration & workflow). Documented in CLI.md +
// the phase-7 help overlay.

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/remediate"
)

// startWaive flips into modeWaive (a sub-mode of modeCommand) +
// prompts for the reason. Enter commits via doWaive.
func (m *listModel) startWaive() {
	if len(m.filtered) == 0 || m.listCursor >= len(m.filtered) {
		m.flash = "waive: no finding selected"
		return
	}
	m.mode = modeCommand
	m.input = "waive: "
}

// doWaive is called from commitEditor when the command line starts
// with `waive: `. Daemon mode POSTs to /api/v1/waivers; file mode
// prints a YAML snippet to flash.
func (m *listModel) doWaive(reason string) {
	if len(m.filtered) == 0 || m.listCursor >= len(m.filtered) {
		m.flash = "waive: no finding selected"
		return
	}
	f := m.filtered[m.listCursor]
	resource := f.Resource.ID
	if resource == "" {
		resource = f.Resource.Name
	}
	expires := time.Now().AddDate(0, 0, 90).UTC().Format("2006-01-02")
	approver := "tui-operator" // phase 5+ may pull from /api/auth/me

	if _, isDaemon := m.src.(*daemonSource); isDaemon {
		// Daemon mode — fire a real POST. Errors surface via flash.
		if err := m.postWaiver(f.CheckID, resource, reason, approver, expires); err != nil {
			m.flash = "waive: " + err.Error()
			return
		}
		m.flash = fmt.Sprintf("waived %s on %s (90d, approver=%s)", f.CheckID, resource, approver)
		return
	}
	// File mode — print a YAML snippet so the operator can paste it
	// into their waivers.yaml.
	yaml := fmt.Sprintf("waivers:\n  - check_id: %s\n    resource_id: %s\n    reason: %q\n    approver: %s\n    expires: %s\n",
		f.CheckID, resource, reason, approver, expires)
	m.flash = "waive YAML — copy from terminal scrollback:\n" + yaml
}

// postWaiver hits POST /api/v1/waivers on the daemon. Bearer auth
// per the v1.3 contract; CSRF skipped because token-auth callers
// bypass it per the v1.5.1 middleware.
func (m *listModel) postWaiver(checkID, resourceID, reason, approver, expires string) error {
	ds, ok := m.src.(*daemonSource)
	if !ok {
		return fmt.Errorf("not a daemon source")
	}
	body := fmt.Sprintf(`{"check_id":%q,"resource_id":%q,"reason":%q,"approver":%q,"expires_at":%q}`,
		checkID, resourceID, reason, approver, expires)
	req, err := http.NewRequestWithContext(m.ctx, http.MethodPost,
		ds.baseURL+"/api/v1/waivers", bytes.NewBufferString(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+ds.apiToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ds.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// previewRemediation renders the bash strategy for the focused
// check into flash. Falls back to a clean "not registered" message
// when the check has no bash generator.
func (m *listModel) previewRemediation() {
	if len(m.filtered) == 0 || m.listCursor >= len(m.filtered) {
		m.flash = "remediate: no finding selected"
		return
	}
	f := m.filtered[m.listCursor]
	snippet, err := remediate.Default.Render(f, remediate.FormatBash)
	if err != nil {
		m.flash = "remediate: no bash strategy for " + f.CheckID
		return
	}
	body := snippet.Content
	// Cap to a few lines so the flash stays readable; phase 7 may
	// add a dedicated overlay with full scrollback.
	lines := strings.SplitN(body, "\n", 8)
	if len(lines) >= 8 {
		lines = lines[:7]
		lines = append(lines, "… (truncated)")
	}
	m.flash = "remediate (bash):\n" + strings.Join(lines, "\n")
}
