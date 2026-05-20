package tui

// v1.7 phase 1 — multi-pane layout. Three vertical panes:
//
//   ┌──────────┬──────────────────────────┬──────────────────┐
//   │  TREE    │  FINDINGS                │  DETAIL          │
//   │ ──────── │ ───────────────────────  │ ───────────────  │
//   │ ▾ aws    │ > critical   fail  …     │ check_id  do-…   │
//   │   gcp    │   high       fail  …     │ severity  high   │
//   │   linux  │   medium     pass  …     │ resource  …      │
//   └──────────┴──────────────────────────┴──────────────────┘
//
// Tab cycles focus between panes; j/k scrolls within the focused
// pane. Tree selection narrows the findings list to one provider.
// Detail pane re-renders on every list-cursor move. Phase 2 layers
// vim keys + ":" command-mode + `/`-search; phase 3 layers live tail.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// pane identifies the focused pane for keybinding dispatch.
type pane int

const (
	paneTree pane = iota
	paneList
	paneDetail
)

// providerBucket is one row in the tree pane.
type providerBucket struct {
	name  string
	total int
}

// editorMode tracks whether the TUI is in normal, `/search`, or
// `:command` input mode. Affects keystroke routing.
type editorMode int

const (
	modeNormal editorMode = iota
	modeSearch
	modeCommand
)

type listModel struct {
	all       []compliancekit.Finding
	filtered  []compliancekit.Finding
	providers []providerBucket

	focused     pane
	treeCursor  int
	listCursor  int
	providerSel string // "" = all
	height      int
	width       int

	// v1.7 phase 2 — editor + filter state.
	mode   editorMode
	input  string         // /search query or :command buffer
	flash  string         // transient status message (under footer)
	filter filterCriteria // applied AND'd with provider selection

	// v1.7 phase 3 — live tail state. src + ctx are filled by Run();
	// tailing is the user-facing flag flipped by `:tail` command.
	src     Source
	ctx     context.Context //nolint:containedctx // bubbletea program scope
	tailing bool
	tailCh  chan compliancekit.Finding
}

func newListModel(findings []compliancekit.Finding) listModel {
	m := listModel{
		all:     findings,
		focused: paneList,
		height:  defaultListHeight,
	}
	m.providers = buildProviderBuckets(findings)
	m.applyFilter()
	return m
}

const defaultListHeight = 24

// buildProviderBuckets walks findings + tallies per-provider counts.
func buildProviderBuckets(findings []compliancekit.Finding) []providerBucket {
	counts := map[string]int{}
	for _, f := range findings {
		p := f.Resource.Provider
		if p == "" {
			p = providerFromType(f.Resource.Type)
		}
		if p == "" {
			p = "(unknown)"
		}
		counts[p]++
	}
	out := make([]providerBucket, 0, len(counts))
	for p, n := range counts {
		out = append(out, providerBucket{name: p, total: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func providerFromType(t string) string {
	if i := strings.Index(t, "."); i >= 0 {
		return t[:i]
	}
	return ""
}

// applyFilter re-derives m.filtered from m.all + the current
// provider selection + the :command criteria. Idempotent.
func (m *listModel) applyFilter() {
	merged := m.filter
	if m.providerSel != "" {
		// Tree-selected provider always wins over any :provider=
		// criterion (operator intent is explicit).
		merged.provider = m.providerSel
	}
	out := make([]compliancekit.Finding, 0, len(m.all))
	for _, f := range m.all {
		if merged.apply(f) {
			out = append(out, f)
		}
	}
	m.filtered = out
	if m.listCursor >= len(out) {
		m.listCursor = 0
	}
}

func (m listModel) Init() tea.Cmd { return nil }

func (m listModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		return m.handleKey(msg.String())
	case liveFindingMsg:
		// v1.7 phase 3 — append + re-filter + show flash. Drain the
		// channel again with waitForFindingCmd so the next event
		// flows in without a per-event setup cost.
		m.all = append(m.all, compliancekit.Finding(msg))
		m.providers = buildProviderBuckets(m.all)
		m.applyFilter()
		m.flash = fmt.Sprintf("tail: +%s %s", compliancekit.Finding(msg).Severity.String(), compliancekit.Finding(msg).CheckID)
		if m.tailing && m.tailCh != nil {
			return m, waitForFindingCmd(m.tailCh)
		}
	case tailEndedMsg:
		m.tailing = false
		m.tailCh = nil
		m.flash = "tail: disconnected"
	}
	return m, nil
}

func (m listModel) handleKey(key string) (tea.Model, tea.Cmd) {
	// In search / command mode, every key (except esc + enter)
	// edits the input buffer.
	if m.mode == modeSearch || m.mode == modeCommand {
		return m.handleEditKey(key)
	}
	return m.handleNormalKey(key)
}

// handleNormalKey dispatches keys in normal mode. Vim-ish:
// q quit, j/k scroll, g/G top/bottom, Tab focus, / search,
// : command, n / N step search results.
func (m listModel) handleNormalKey(key string) (tea.Model, tea.Cmd) {
	if cmd, handled := m.handleNormalChrome(key); handled {
		return m, cmd
	}
	if m.handleNormalNav(key) {
		return m, nil
	}
	m.handleNormalEditor(key)
	return m, nil
}

// handleNormalChrome handles quit / focus / esc keys; returns true
// when the key is consumed.
func (m *listModel) handleNormalChrome(key string) (tea.Cmd, bool) {
	switch key {
	case "q", "ctrl+c":
		return tea.Quit, true
	case "esc":
		m.flash = ""
		return nil, true
	case "tab":
		m.focused = (m.focused + 1) % 3
		return nil, true
	case "shift+tab":
		m.focused = (m.focused + 2) % 3
		return nil, true
	}
	return nil, false
}

// handleNormalNav handles j/k/g/G/Enter/Backspace/n/N; returns
// true when consumed.
func (m *listModel) handleNormalNav(key string) bool {
	switch key {
	case "j", "down":
		m.cursorDown()
	case "k", "up":
		m.cursorUp()
	case "g":
		m.cursorTop()
	case "G":
		m.cursorBottom()
	case "enter":
		m.activate()
	case "backspace":
		if m.focused == paneTree || m.providerSel != "" {
			m.providerSel = ""
			m.applyFilter()
		}
	case "n":
		m.stepSearch(+1)
	case "N":
		m.stepSearch(-1)
	default:
		return false
	}
	return true
}

// handleNormalEditor handles `/` and `:` — enters edit mode.
func (m *listModel) handleNormalEditor(key string) {
	switch key {
	case "/":
		m.mode = modeSearch
		m.input = ""
	case ":":
		m.mode = modeCommand
		m.input = ""
	}
}

// handleEditKey routes printable keys into m.input, Enter to
// commit, Esc to abort.
func (m listModel) handleEditKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.mode = modeNormal
		m.input = ""
		return m, nil
	case "enter":
		cmd := m.commitEditor()
		m.mode = modeNormal
		return m, cmd
	case "backspace":
		if m.input != "" {
			r := []rune(m.input)
			m.input = string(r[:len(r)-1])
		}
		return m, nil
	}
	// Bubble Tea delivers most printables as their literal character.
	if len(key) == 1 {
		m.input += key
	} else if key == "space" {
		m.input += " "
	}
	return m, nil
}

// commitEditor applies the pending /search or :command buffer to
// the filter state + refreshes m.filtered. Returns an optional
// tea.Cmd when the command had a side effect (e.g. `:tail`
// starting an SSE subscription).
func (m *listModel) commitEditor() tea.Cmd {
	var cmd tea.Cmd
	switch m.mode {
	case modeSearch:
		m.filter.search = m.input
		m.flash = "search: " + m.input
	case modeCommand:
		switch strings.TrimSpace(m.input) {
		case "tail":
			cmd = m.startTail()
		case "untail":
			m.stopTail()
		default:
			m.filter = parseCommandLine(m.input)
			m.flash = "filter: " + m.input
		}
	}
	m.input = ""
	m.applyFilter()
	m.listCursor = 0
	return cmd
}

// startTail opens an SSE subscription via the configured Source +
// arms the channel-drainer command. Idempotent — calling twice is
// a no-op.
func (m *listModel) startTail() tea.Cmd {
	if m.tailing || m.src == nil {
		return nil
	}
	m.tailing = true
	m.flash = "tail: subscribing…"
	ch := make(chan compliancekit.Finding, 64)
	m.tailCh = ch
	go func() {
		defer close(ch)
		_ = m.src.Subscribe(m.ctx, ch)
	}()
	return waitForFindingCmd(ch)
}

// stopTail tears down the SSE subscription. The drainer goroutine
// exits when the daemon closes the connection or ctx cancels;
// stopTail flags the model so newly arriving events are ignored
// (the buffered channel drains naturally).
func (m *listModel) stopTail() {
	m.tailing = false
	m.flash = "tail: stopped"
}

// stepSearch advances the cursor to the next (dir=+1) or previous
// (dir=-1) row in m.filtered. Wraps. Used by `n` / `N` in normal
// mode.
func (m *listModel) stepSearch(dir int) {
	if len(m.filtered) == 0 {
		return
	}
	m.listCursor = (m.listCursor + dir + len(m.filtered)) % len(m.filtered)
}

func (m *listModel) activate() {
	if m.focused == paneTree && len(m.providers) > 0 {
		m.providerSel = m.providers[m.treeCursor].name
		m.applyFilter()
		m.focused = paneList
		return
	}
	if m.focused == paneList {
		m.focused = paneDetail
	}
}

func (m *listModel) cursorDown() {
	switch m.focused {
	case paneTree:
		if m.treeCursor < len(m.providers)-1 {
			m.treeCursor++
		}
	case paneList:
		if m.listCursor < len(m.filtered)-1 {
			m.listCursor++
		}
	}
}

func (m *listModel) cursorUp() {
	switch m.focused {
	case paneTree:
		if m.treeCursor > 0 {
			m.treeCursor--
		}
	case paneList:
		if m.listCursor > 0 {
			m.listCursor--
		}
	}
}

func (m *listModel) cursorTop() {
	switch m.focused {
	case paneTree:
		m.treeCursor = 0
	case paneList:
		m.listCursor = 0
	}
}

func (m *listModel) cursorBottom() {
	switch m.focused {
	case paneTree:
		m.treeCursor = len(m.providers) - 1
		if m.treeCursor < 0 {
			m.treeCursor = 0
		}
	case paneList:
		m.listCursor = len(m.filtered) - 1
		if m.listCursor < 0 {
			m.listCursor = 0
		}
	}
}

func (m listModel) View() string {
	w := m.width
	if w == 0 {
		w = 120
	}
	h := m.height
	if h == 0 {
		h = defaultListHeight
	}
	// 20% tree / 50% list / 30% detail; ensure each gets ≥10 cols.
	tw := imax(10, w*20/100)
	dw := imax(10, w*30/100)
	lw := imax(10, w-tw-dw-3) // -3 for the two vertical separators
	innerH := h - 3           // -3 for header + footer + status row

	tree := m.renderTree(tw, innerH)
	list := m.renderList(lw, innerH)
	detail := m.renderDetail(dw, innerH)

	row := lipgloss.JoinHorizontal(lipgloss.Top, tree, vsep(innerH), list, vsep(innerH), detail)
	header := lipgloss.NewStyle().Bold(true).Render(fmt.Sprintf("compliancekit tui — %d findings (filter: %s)", len(m.filtered), m.filterLabel()))
	footer := m.footerLine()
	return header + "\n\n" + row + "\n" + footer + "\n"
}

// footerLine renders either the command-mode input prompt or the
// hint line, depending on m.mode. Phase 2.
func (m listModel) footerLine() string {
	switch m.mode {
	case modeSearch:
		return lipgloss.NewStyle().Bold(true).Render("/" + m.input + "_")
	case modeCommand:
		return lipgloss.NewStyle().Bold(true).Render(":" + m.input + "_")
	}
	hint := "tab cycle  j/k scroll  g/G top/bottom  enter select  backspace clear  / search  : command  q quit"
	if m.flash != "" {
		hint = m.flash + "    " + lipgloss.NewStyle().Faint(true).Render(hint)
	}
	return lipgloss.NewStyle().Faint(true).Render(hint)
}

func (m listModel) filterLabel() string {
	if m.providerSel == "" {
		return "all providers"
	}
	return "provider=" + m.providerSel
}

func vsep(h int) string {
	col := strings.Repeat("│\n", h)
	return lipgloss.NewStyle().Faint(true).Render(strings.TrimRight(col, "\n"))
}

func (m listModel) renderTree(width, height int) string {
	title := boldUnder("Providers", width)
	body := []string{title}
	maxRows := height - 1
	for i := 0; i < len(m.providers) && i < maxRows; i++ {
		p := m.providers[i]
		marker := "  "
		if m.focused == paneTree && i == m.treeCursor {
			marker = "▸ "
		}
		line := fmt.Sprintf("%s%-12s %d", marker, truncate(p.name, 12), p.total)
		body = append(body, padRight(line, width))
	}
	for len(body) < height {
		body = append(body, padRight("", width))
	}
	return strings.Join(body, "\n")
}

func (m listModel) renderList(width, height int) string {
	title := boldUnder(fmt.Sprintf("Findings (%d)", len(m.filtered)), width)
	body := []string{title}
	maxRows := height - 1
	if len(m.filtered) == 0 {
		body = append(body, padRight("  (no findings match filter)", width))
		for len(body) < height {
			body = append(body, padRight("", width))
		}
		return strings.Join(body, "\n")
	}
	// Window around cursor.
	start := m.listCursor - maxRows/2
	if start < 0 {
		start = 0
	}
	end := start + maxRows
	if end > len(m.filtered) {
		end = len(m.filtered)
	}
	if end-start < maxRows {
		start = end - maxRows
		if start < 0 {
			start = 0
		}
	}
	for i := start; i < end; i++ {
		f := m.filtered[i]
		marker := "  "
		if m.focused == paneList && i == m.listCursor {
			marker = "▸ "
		}
		line := fmt.Sprintf("%s%-8s %-6s %-30s %s",
			marker, severityShort(f.Severity), string(f.Status),
			truncate(f.CheckID, 30), truncate(displayResource(f), width-50))
		body = append(body, padRight(line, width))
	}
	for len(body) < height {
		body = append(body, padRight("", width))
	}
	return strings.Join(body, "\n")
}

func (m listModel) renderDetail(width, height int) string {
	title := boldUnder("Detail", width)
	body := []string{title}
	if len(m.filtered) == 0 || m.listCursor >= len(m.filtered) {
		body = append(body, padRight("  (select a finding)", width))
		for len(body) < height {
			body = append(body, padRight("", width))
		}
		return strings.Join(body, "\n")
	}
	f := m.filtered[m.listCursor]
	rows := []string{
		fmt.Sprintf("check     %s", f.CheckID),
		fmt.Sprintf("severity  %s", f.Severity.String()),
		fmt.Sprintf("status    %s", string(f.Status)),
		fmt.Sprintf("provider  %s", f.Resource.Provider),
		fmt.Sprintf("resource  %s", displayResource(f)),
	}
	if f.Message != "" {
		rows = append(rows, "", wrap(f.Message, width-2))
	}
	for _, r := range rows {
		body = append(body, padRight(r, width))
	}
	for len(body) < height {
		body = append(body, padRight("", width))
	}
	return strings.Join(body, "\n")
}

func boldUnder(s string, w int) string {
	return lipgloss.NewStyle().Bold(true).Render(s) + "\n" + strings.Repeat("─", w-1)
}

func displayResource(f compliancekit.Finding) string {
	if f.Resource.Name != "" {
		return f.Resource.Name
	}
	return f.Resource.ID
}

func severityShort(s compliancekit.Severity) string {
	switch s {
	case compliancekit.SeverityCritical:
		return "CRIT"
	case compliancekit.SeverityHigh:
		return "HIGH"
	case compliancekit.SeverityMedium:
		return "MED"
	case compliancekit.SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func padRight(s string, n int) string {
	visible := runeLen(s)
	if visible >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visible)
}

func runeLen(s string) int { return len([]rune(s)) }

func wrap(s string, w int) string {
	if w <= 0 {
		return s
	}
	out := []string{}
	for len(s) > w {
		out = append(out, s[:w])
		s = s[w:]
	}
	out = append(out, s)
	return strings.Join(out, "\n")
}

func imax(a, b int) int {
	if a > b {
		return a
	}
	return b
}
