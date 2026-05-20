package tui

// v1.7 phase 7 — help overlay + severity-color theming.
//
// `?` in normal mode toggles a centered help card listing every
// keybinding the TUI ships. Esc or `?` closes. Severity tags
// across every pane now render with lipgloss adaptive colors
// matching the v1.1 CLI palette so the TUI feels like the
// scan-output operators already know.

import (
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Severity color tokens. lipgloss.AdaptiveColor switches per
// terminal background, mirroring the v1.1 CLI's
// internal/ui/palette.go choices. Kept inline (not imported from
// internal/ui) because that package is CLI-output-shaped + the
// TUI wants its own per-row width / glyph contract.
var (
	colorCritical = lipgloss.AdaptiveColor{Light: "#b91c1c", Dark: "#f87171"}
	colorHigh     = lipgloss.AdaptiveColor{Light: "#c2410c", Dark: "#fb923c"}
	colorMedium   = lipgloss.AdaptiveColor{Light: "#a16207", Dark: "#facc15"}
	colorLow      = lipgloss.AdaptiveColor{Light: "#0369a1", Dark: "#60a5fa"}
	colorInfo     = lipgloss.AdaptiveColor{Light: "#525252", Dark: "#a3a3a3"}
)

// severityStyled returns the 4-char severity tag colored by tier.
func severityStyled(s compliancekit.Severity) string {
	var color lipgloss.AdaptiveColor
	switch s {
	case compliancekit.SeverityCritical:
		color = colorCritical
	case compliancekit.SeverityHigh:
		color = colorHigh
	case compliancekit.SeverityMedium:
		color = colorMedium
	case compliancekit.SeverityLow:
		color = colorLow
	default:
		color = colorInfo
	}
	return lipgloss.NewStyle().Foreground(color).Bold(s >= compliancekit.SeverityHigh).Render(severityShort(s))
}

// renderHelp returns the centered help overlay string. width +
// height are the terminal cell extent. The overlay is plain
// text in a bordered card; lipgloss handles the border + centering.
func renderHelp(width, height int) string {
	body := `Keybindings

  Normal mode
    j / down              next finding
    k / up                previous finding
    g                     jump to top
    G                     jump to bottom
    Tab / Shift+Tab       cycle pane focus
    Enter                 activate (apply tree filter / focus detail)
    Backspace             clear provider filter
    / <text>              substring search across check/resource
    : <command>           command mode (see below)
    n / N                 next / previous match
    R                     resource-tree navigator
    w                     waive focused finding (prompts for reason)
    a                     ack focused finding (v1.8 plumbing)
    c                     comment focused finding (v1.8 plumbing)
    r                     remediate-preview (bash strategy)
    ?                     toggle this help
    q / Esc / Ctrl+C      quit

  Command mode (after ":")
    sev=critical          severity exact
    sev>=high             severity gte
    status=fail           status exact
    provider=aws          provider exact
    check=do-droplet      check_id substring
    fw=soc2               framework id
    reset                 clear filters
    tail / untail         start / stop live SSE tail
    diff <path>           overlay baseline diff (+ new, - resolved, ~ changed)
    undiff                clear diff overlay
    waive: <reason>       waive focused finding (used by w key)

  Source modes
    --findings=path.json                     offline file
    --server=URL --api-token=ck_…            live daemon`
	card := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.AdaptiveColor{Light: "#737373", Dark: "#a3a3a3"}).
		Padding(1, 2).
		Render(body)
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, card)
}

// helpKeyMatches reports whether a key event toggles the help
// overlay. Centralized so the `?` binding lives in one place
// even though handle dispatch lives in model.go.
func helpKeyMatches(key string) bool { return key == "?" }

// strings is used only by the import block at the top; keep an
// anchored reference so goimports doesn't strip it.
var _ = strings.Repeat
