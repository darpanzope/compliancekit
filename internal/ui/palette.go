package ui

import "github.com/charmbracelet/lipgloss"

// The palette is built from lipgloss.AdaptiveColor pairs so a single
// constant renders correctly under both dark and light terminals.
// Light-terminal values are chosen for ~AA contrast on a #fafafa
// background; dark-terminal values for ~AA contrast on #1e1e1e.
//
// Severity values map to the ANSI 256-color codes commonly used by
// other security tools (Trivy, kubescape) so an operator switching
// scanners sees the same visual hierarchy. The dark-mode reds /
// oranges are warmer than the lightning-bright ANSI defaults to
// keep big finding tables tolerable.
var (
	// Severity colors, brightest-first.
	colorCritical = lipgloss.AdaptiveColor{Light: "#c40233", Dark: "#ff4b6b"}
	colorHigh     = lipgloss.AdaptiveColor{Light: "#c2410c", Dark: "#ff9849"}
	colorMedium   = lipgloss.AdaptiveColor{Light: "#a16207", Dark: "#facc15"}
	colorLow      = lipgloss.AdaptiveColor{Light: "#1e40af", Dark: "#60a5fa"}
	colorInfo     = lipgloss.AdaptiveColor{Light: "#525252", Dark: "#a3a3a3"}
	colorUnknown  = lipgloss.AdaptiveColor{Light: "#737373", Dark: "#737373"}

	// Status colors.
	colorPass  = lipgloss.AdaptiveColor{Light: "#166534", Dark: "#34d399"}
	colorFail  = lipgloss.AdaptiveColor{Light: "#b91c1c", Dark: "#f87171"}
	colorSkip  = lipgloss.AdaptiveColor{Light: "#737373", Dark: "#a3a3a3"}
	colorError = lipgloss.AdaptiveColor{Light: "#7c2d12", Dark: "#fb923c"}

	// Diff-row colors (used by `compliancekit diff`).
	colorAdded    = lipgloss.AdaptiveColor{Light: "#15803d", Dark: "#4ade80"}
	colorRemoved  = lipgloss.AdaptiveColor{Light: "#9ca3af", Dark: "#6b7280"}
	colorExisting = lipgloss.AdaptiveColor{Light: "#525252", Dark: "#a3a3a3"}

	// Structural colors for tables, frames, separators.
	colorMuted  = lipgloss.AdaptiveColor{Light: "#a3a3a3", Dark: "#525252"}
	colorAccent = lipgloss.AdaptiveColor{Light: "#0369a1", Dark: "#38bdf8"}
)
