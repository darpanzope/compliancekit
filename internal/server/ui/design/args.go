// Package design hosts the v1.18 design-system contract per ADR-017.
//
// Component partials live under components/*.html. Each partial is
// invoked from a daemon template via `{{ template "ck-NAME" args }}`
// where args carries one of the typed structs in this file. Passing
// a struct by name beats `map[string]any` because the partial breaks
// at compile time (well, parse time) when a field is missing — far
// cheaper than chasing a silent template render error in production.
//
// Default values:
//   - Variant/Size fields default to a sensible value (set in the
//     partial via `{{ if not . }}default{{ end }}`).
//   - Empty optional fields skip rendering the affected attribute.
//
// Adding a new component:
//  1. Define ${Name}Args here.
//  2. Add components/ck-${name}.html.
//  3. Add a /design route entry (phase 7) so it ships in the live
//     component zoo + visual-regression sweep.
package design

import "html/template"

// ButtonArgs configures `ck-button`. Renders <button> by default;
// renders <a> when Href is set.
type ButtonArgs struct {
	Variant   string // primary | secondary | destructive | ghost | link
	Size      string // sm | md | lg (default md)
	Label     string
	IconLeft  template.HTML
	IconRight template.HTML
	Tooltip   string
	Type      string // button | submit | reset (default button)
	Href      string // when set, the partial renders <a> instead of <button>
	Disabled  bool
	Loading   bool
	Attrs     template.HTMLAttr // raw attrs string (hx-*, @click, etc.)
	ID        string
	Class     string
}

// CardArgs configures `ck-card`. Body is HTML so callers can compose
// arbitrary content; for headings/footers compose separate cards.
type CardArgs struct {
	Variant string // flat | raised | floating | glass (default flat)
	Padding string // sm | md | lg (default md)
	Title   string
	Body    template.HTML
	Class   string
}

// MetricCardArgs configures `ck-metric-card`. Phase 4 fleshes the
// rendering; phase 3 ships the stub.
type MetricCardArgs struct {
	Title    string
	Value    string
	Subtitle string
	Icon     template.HTML
	Variant  string // default | primary | critical | high | medium | low | success | info
	Tooltip  string
	Trend    *MetricTrend
	Href     string
	Class    string
}

// MetricTrend is the optional trend arrow + delta beneath a metric.
type MetricTrend struct {
	Delta     string // "12%"
	Direction string // up | down | flat
	Polarity  string // good | bad | neutral — colors the arrow
}

// PillArgs renders a small label-on-bg pill. Variant maps onto the
// severity-* / status-* token families.
type PillArgs struct {
	Variant string // severity-{critical,high,medium,low,info} | status-{open,acknowledged,resolved,running,completed,failed,pending,false-positive}
	Label   string
	Class   string
}

// StatusPillArgs is a convenience for the v1.18 status taxonomy.
// Phase 11 audit-applies these across every status surface.
type StatusPillArgs struct {
	Status string // open | acknowledged | resolved | running | completed | failed | pending | false-positive
	Label  string
	Class  string
}

// InfoTooltipArgs renders the `?` icon + hover-tooltip pattern.
// Phase 5 audit-applies one to every card title surface.
type InfoTooltipArgs struct {
	Text      string
	Placement string // top | bottom | left | right (default top)
	AriaLabel string // accessible label (defaults to Text)
}

// PageHeaderArgs ships the canonical page header convention.
// Actions is a slot for the right-hand bulk-actions group.
type PageHeaderArgs struct {
	Title    string
	Subtitle string
	Eyebrow  string
	Actions  template.HTML
	Tooltip  string
}

// FilterCardArgs ships the canonical left-column filter convention.
type FilterCardArgs struct {
	Title string
	Body  template.HTML
	Class string
}

// ToastArgs configures `ck-toast`. Phase 9 fleshes the queue + the
// optimistic-UI hooks; phase 3 ships the partial stub.
type ToastArgs struct {
	Variant string // success | error | warning | info
	Title   string
	Message string
	ID      string
}

// SkeletonArgs renders a loading placeholder. Phase 8 wires the
// pulse animation + page-fetch lifecycle.
type SkeletonArgs struct {
	Variant string // text | circle | rect (default text)
	Width   string // arbitrary CSS length (e.g. "60%", "8rem")
	Height  string
	Class   string
}

// AvatarArgs renders the hash-from-name gradient avatar. Set Gradient
// (via AvatarGradient) for the deterministic per-name gradient; leave
// it empty to fall back to the default brand gradient. v1.18 phase 11.
type AvatarArgs struct {
	Initials string
	Name     string       // drives the gradient choice
	Size     string       // sm | md | lg (default md)
	Gradient template.CSS // deterministic gradient (from AvatarGradient)
	Class    string
}

// EmptyStateArgs renders an empty-state. Phase 10 supplies the
// illustration catalog (~30 hand-drawn-style SVGs).
type EmptyStateArgs struct {
	Title        string
	Description  string
	Illustration template.HTML
	Action       template.HTML
}

// IconArgs renders a sprite-symbol reference. Phase 11 expands the
// sprite from 22 → ~100 symbols.
type IconArgs struct {
	Name  string // sprite symbol id
	Size  string // 14 | 16 | 18 | 20 | 24 (default 18)
	Class string
}

// TabsArgs renders a tablist. Items.Key is the value compared to
// Current to pick the active row; Items.Href makes the tab a link.
type TabsArgs struct {
	Items   []TabItem
	Current string
	Name    string
	Class   string
}

// TabItem is one tab.
type TabItem struct {
	Key   string
	Label string
	Href  string
}

// DropdownArgs renders a button + popover menu. Trigger is the
// visible button content; Items populates the menu.
type DropdownArgs struct {
	Trigger template.HTML
	Items   []DropdownItem
	Align   string // left | right (default left)
	ID      string
	Class   string
}

// DropdownItem is one menu row.
type DropdownItem struct {
	Label    string
	Href     string
	Variant  string // default | destructive
	IconHTML template.HTML
	Attrs    template.HTMLAttr
	Divider  bool // when true, ignore label/href and render a separator
}

// InputArgs renders a labeled <input>.
type InputArgs struct {
	Type        string // text | password | email | number | search | url (default text)
	Name        string
	Value       string
	Label       string
	Placeholder string
	Required    bool
	Disabled    bool
	ID          string
	Hint        string
	Error       string
	Attrs       template.HTMLAttr
}

// CheckboxArgs renders a labeled checkbox.
type CheckboxArgs struct {
	Name    string
	Value   string
	Label   string
	Checked bool
	ID      string
	Attrs   template.HTMLAttr
}

// SelectArgs renders a labeled <select>.
type SelectArgs struct {
	Name     string
	Label    string
	Options  []SelectOption
	Selected string
	ID       string
	Required bool
	Attrs    template.HTMLAttr
}

// SelectOption is one <option>.
type SelectOption struct {
	Value string
	Label string
}

// TextareaArgs renders a labeled <textarea>.
type TextareaArgs struct {
	Name        string
	Label       string
	Value       string
	Placeholder string
	Rows        int
	ID          string
	Attrs       template.HTMLAttr
}

// ModalArgs renders an Alpine-driven modal. ID must be unique per page
// so the toggle script can find it.
type ModalArgs struct {
	ID      string
	Title   string
	Body    template.HTML
	Actions template.HTML
}

// BannerArgs renders an inline banner (page-top notice, not a toast).
type BannerArgs struct {
	Variant string // info | success | warning | error
	Title   string
	Message string
	Action  template.HTML
}

// SectionArgs wraps a content section with a heading + optional
// description + optional info tooltip. Use to scaffold long pages.
type SectionArgs struct {
	Title       string
	Description string
	Body        template.HTML
	Tooltip     string
}

// DividerArgs renders a horizontal or vertical separator.
type DividerArgs struct {
	Orientation string // horizontal | vertical (default horizontal)
	Class       string
}

// SpinnerArgs renders an inline loading spinner.
type SpinnerArgs struct {
	Size  string // sm | md | lg (default md)
	Class string
}

// ProgressArgs renders a horizontal progress bar.
type ProgressArgs struct {
	Value   int    // 0-100, clamped at render time
	Variant string // primary | success | warning | critical (default primary)
	Label   string
}
