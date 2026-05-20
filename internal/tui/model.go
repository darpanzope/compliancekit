package tui

// v1.7 phase 0 model — minimum-viable findings list. Header row
// shows total + scope of the data source; the list is a scrollable
// viewport over the loaded findings. Single-pane; phase 1 adds the
// tree / list / detail split.

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

const (
	defaultListHeight = 20 // rows visible when terminal height is unknown
)

type listModel struct {
	findings []compliancekit.Finding
	cursor   int
	height   int
	width    int
}

func newListModel(findings []compliancekit.Finding) listModel {
	return listModel{
		findings: findings,
		height:   defaultListHeight,
	}
}

func (m listModel) Init() tea.Cmd { return nil }

func (m listModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "j", "down":
			if m.cursor < len(m.findings)-1 {
				m.cursor++
			}
		case "k", "up":
			if m.cursor > 0 {
				m.cursor--
			}
		case "g":
			m.cursor = 0
		case "G":
			m.cursor = len(m.findings) - 1
			if m.cursor < 0 {
				m.cursor = 0
			}
		}
	}
	return m, nil
}

func (m listModel) View() string {
	header := fmt.Sprintf("compliancekit tui — %d findings  (q to quit, j/k to scroll, g/G to top/bottom)\n\n", len(m.findings))
	if len(m.findings) == 0 {
		return header + "  (no findings to display)\n"
	}

	// Calculate visible window — rows around the cursor with a small
	// buffer. defaultListHeight - 4 leaves room for header + footer.
	maxRows := m.height - 4
	if maxRows <= 0 {
		maxRows = defaultListHeight - 4
	}
	start := m.cursor - maxRows/2
	if start < 0 {
		start = 0
	}
	end := start + maxRows
	if end > len(m.findings) {
		end = len(m.findings)
	}
	if end-start < maxRows {
		start = end - maxRows
		if start < 0 {
			start = 0
		}
	}

	out := header
	for i := start; i < end; i++ {
		f := m.findings[i]
		marker := "  "
		if i == m.cursor {
			marker = "> "
		}
		sev := padRight(f.Severity.String(), 8)
		status := padRight(string(f.Status), 6)
		resource := f.Resource.Name
		if resource == "" {
			resource = f.Resource.ID
		}
		out += fmt.Sprintf("%s%s  %s  %s  %s\n",
			marker, sev, status, padRight(f.CheckID, 40), resource)
	}
	out += fmt.Sprintf("\n  %d / %d\n", m.cursor+1, len(m.findings))
	return out
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s[:n]
	}
	pad := n - len(s)
	return s + spaces(pad)
}

func spaces(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = ' '
	}
	return string(out)
}
