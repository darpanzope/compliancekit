package ui

import (
	"html/template"
	"net/http"

	"github.com/darpanzope/compliancekit/internal/server/ui/design"
)

// designZooView is the canned-data payload for the /design route. The
// route renders the live component zoo — every button variant, card
// depth, status pill, MetricCard variant, palette swatch, easing curve,
// and shadow scale — with zero DB access so it doubles as a visual-
// regression target + an internal-contributor onboarding artifact.
// v1.18 phase 7 (ADR-017).
type designZooView struct {
	View
	Components    []string
	Illustrations []string
	PageTitle     design.PageHeaderArgs
	Buttons       []design.ButtonArgs
	ModalButton   design.ButtonArgs
	Metrics       []design.MetricCardArgs
	Pills         []design.PillArgs
	StatusPills   []design.StatusPillArgs
	Banners       []design.BannerArgs
	Toasts        []design.ToastArgs
	Skeletons     []design.SkeletonArgs
	Avatars       []design.AvatarArgs
	Spinners      []design.SpinnerArgs
	Progress      []design.ProgressArgs
	CardDepths    []designCardDepth
	Header        design.PageHeaderArgs
	FilterCard    design.FilterCardArgs
	EmptyState    design.EmptyStateArgs
	Tabs          design.TabsArgs
	Dropdown      design.DropdownArgs
	Input         design.InputArgs
	Select        design.SelectArgs
	Textarea      design.TextareaArgs
	Checkbox      design.CheckboxArgs
	Section       design.SectionArgs
	Divider       design.DividerArgs
	Modal         design.ModalArgs
	Tooltip       design.InfoTooltipArgs
	Palettes      []designSwatchGroup
	Easings       []designEasing
	Shadows       []designShadow
}

type designCardDepth struct {
	Variant string
	Label   string
	Note    string
}

type designSwatchGroup struct {
	Group    string
	Swatches []designSwatch
}

type designSwatch struct {
	Name string       // CSS var token name (without --)
	Var  template.CSS // the background value (hsl(var(--…)) / var(--gradient-…)) — typed CSS so html/template doesn't ZgotmplZ the var() ref
}

type designEasing struct {
	Name  string
	Style template.CSS // full `transition: …` declaration — typed CSS so the var() ref survives
}

type designShadow struct {
	Class string // shadow-* utility
}

// designZoo renders the /design component zoo. No DB access — the data
// is canned in buildDesignZoo so the route works on a fresh daemon.
func (u *UI) designZoo(w http.ResponseWriter, r *http.Request) {
	v := buildDesignZoo()
	v.View = u.viewFor(r, "Design system", "", View{})
	u.render(w, "design_zoo.html", v)
}

// buildDesignZoo assembles the canned component gallery. Split out from
// the handler so the phase-7 CI test can assert every ComponentName has
// a zoo section without spinning up a router.
func buildDesignZoo() designZooView {
	return designZooView{
		Components:    design.ComponentNames,
		Illustrations: design.IllustrationNames,
		PageTitle: design.PageHeaderArgs{
			Title:    "Design system",
			Subtitle: "Live component zoo — every variant, palette, easing, and shadow the daemon UI is built from. Canned data; no backend.",
		},
		Buttons: []design.ButtonArgs{
			{Variant: "primary", Label: "Primary"},
			{Variant: "secondary", Label: "Secondary"},
			{Variant: "destructive", Label: "Destructive"},
			{Variant: "ghost", Label: "Ghost"},
			{Variant: "link", Label: "Link"},
			{Variant: "primary", Label: "Loading", Loading: true},
			{Variant: "primary", Label: "Disabled", Disabled: true},
			{Variant: "primary", Size: "sm", Label: "Small"},
			{Variant: "primary", Size: "lg", Label: "Large"},
		},
		ModalButton: design.ButtonArgs{
			Variant: "secondary",
			Label:   "Open modal",
			Attrs:   template.HTMLAttr(`x-data="{}" @click="$dispatch('ck-modal-open','design-demo-modal')"`),
		},
		Metrics: []design.MetricCardArgs{
			{Title: "Total findings", Value: "248", Variant: "primary", Subtitle: "across 6 providers"},
			{Title: "Critical", Value: "12", Variant: "critical", Icon: severityMetricIcon("critical"),
				Trend: &design.MetricTrend{Delta: "12%", Direction: "up", Polarity: "bad"}},
			{Title: "High", Value: "34", Variant: "high", Icon: severityMetricIcon("high"),
				Trend: &design.MetricTrend{Delta: "5%", Direction: "down", Polarity: "good"}},
			{Title: "Medium", Value: "88", Variant: "medium", Icon: severityMetricIcon("medium")},
			{Title: "Low", Value: "114", Variant: "low", Icon: severityMetricIcon("low")},
			{Title: "Info", Value: "32", Variant: "info", Icon: severityMetricIcon("info")},
			{Title: "Resolved this week", Value: "57", Variant: "success",
				Trend: &design.MetricTrend{Delta: "23%", Direction: "up", Polarity: "good"}},
			{Title: "Resources scanned", Value: "1,204", Variant: "default", Subtitle: "no change"},
		},
		Pills: []design.PillArgs{
			{Variant: "severity-critical", Label: "critical"},
			{Variant: "severity-high", Label: "high"},
			{Variant: "severity-medium", Label: "medium"},
			{Variant: "severity-low", Label: "low"},
			{Variant: "severity-info", Label: "info"},
		},
		StatusPills: []design.StatusPillArgs{
			{Status: "open", Label: "open"},
			{Status: "acknowledged", Label: "acknowledged"},
			{Status: "resolved", Label: "resolved"},
			{Status: "false-positive", Label: "false positive"},
			{Status: "running", Label: "running"},
			{Status: "completed", Label: "completed"},
			{Status: "failed", Label: "failed"},
			{Status: "pending", Label: "pending"},
		},
		Banners: []design.BannerArgs{
			{Variant: "info", Title: "Heads up", Message: "A new scan is queued."},
			{Variant: "success", Title: "All clear", Message: "Last scan closed with zero critical findings."},
			{Variant: "warning", Title: "Attention", Message: "3 waivers expire this week."},
			{Variant: "error", Title: "Scan failed", Message: "Provider credentials were rejected."},
		},
		Toasts: []design.ToastArgs{
			{Variant: "success", Title: "Saved", Message: "Your settings were updated."},
			{Variant: "error", Title: "Failed", Message: "Could not reach the provider."},
		},
		Skeletons: []design.SkeletonArgs{
			{Variant: "circle"},
			{Variant: "text"},
			{Variant: "text", Width: "70%"},
		},
		Avatars: []design.AvatarArgs{
			{Initials: "DZ", Name: "Darpan Zope", Size: "sm"},
			{Initials: "AB", Name: "Ada Byron", Size: "md"},
			{Initials: "GH", Name: "Grace Hopper", Size: "lg"},
		},
		Spinners: []design.SpinnerArgs{{Size: "sm"}, {Size: "md"}, {Size: "lg"}},
		Progress: []design.ProgressArgs{
			{Value: 72, Variant: "primary"},
			{Value: 40, Variant: "warning"},
			{Value: 90, Variant: "success"},
		},
		CardDepths: []designCardDepth{
			{Variant: "flat", Label: "Flat", Note: "soft shadow — the default surface"},
			{Variant: "raised", Label: "Raised", Note: "elevated shadow — hover/active surfaces"},
			{Variant: "floating", Label: "Floating", Note: "floating shadow — popovers, modals"},
			{Variant: "glass", Label: "Glass", Note: "frosted backdrop-blur — overlays"},
		},
		Header: design.PageHeaderArgs{
			Title:    "Example page",
			Subtitle: "The canonical page header with subtitle + title tooltip.",
			Tooltip:  "What this is + why it matters.",
		},
		FilterCard: design.FilterCardArgs{
			Title: "Filters",
			Body:  template.HTML(`<label class="ck-checkbox-row"><input type="checkbox" class="ck-checkbox" checked><span class="ck-checkbox-label">Critical</span></label><label class="ck-checkbox-row"><input type="checkbox" class="ck-checkbox"><span class="ck-checkbox-label">High</span></label>`),
		},
		EmptyState: design.EmptyStateArgs{
			Illustration: design.Illustration("no-findings"),
			Title:        "No findings",
			Description:  "Run a scan to populate this view.",
			Action:       template.HTML(`<a href="/scans/new" class="ck-btn ck-btn-primary ck-btn-md">Run scan</a>`),
		},
		Tabs: design.TabsArgs{
			Current: "overview",
			Items: []design.TabItem{
				{Key: "overview", Label: "Overview", Href: "#comp-ck-tabs"},
				{Key: "findings", Label: "Findings", Href: "#comp-ck-tabs"},
				{Key: "history", Label: "History", Href: "#comp-ck-tabs"},
			},
		},
		Dropdown: design.DropdownArgs{
			Trigger: template.HTML("Actions"),
			Items: []design.DropdownItem{
				{Label: "Edit", Href: "#"},
				{Label: "Duplicate", Href: "#"},
				{Divider: true},
				{Label: "Delete", Href: "#", Variant: "destructive"},
			},
		},
		Input:    design.InputArgs{Type: "search", Name: "q", Label: "Search", Placeholder: "type to filter"},
		Select:   design.SelectArgs{Name: "size", Label: "Page size", Selected: "50", Options: []design.SelectOption{{Value: "25", Label: "25"}, {Value: "50", Label: "50"}, {Value: "100", Label: "100"}}},
		Textarea: design.TextareaArgs{Name: "notes", Label: "Notes", Placeholder: "optional context"},
		Checkbox: design.CheckboxArgs{Name: "agree", Label: "I understand"},
		Section: design.SectionArgs{
			Title:       "Notifications",
			Description: "Configure where alerts are delivered.",
			Tooltip:     "Per-event-type routing lands here.",
			Body:        template.HTML(`<p class="text-sm text-muted-foreground">Slack, email, and webhook sinks configured under Settings.</p>`),
		},
		Divider: design.DividerArgs{},
		Modal: design.ModalArgs{
			ID:    "design-demo-modal",
			Title: "Demo modal",
			Body:  template.HTML(`<p class="text-sm">This modal is driven by the ckModal Alpine factory. Press Esc or click outside to close.</p>`),
		},
		Tooltip: design.InfoTooltipArgs{Text: "This is the in-context discovery pattern audit-applied to every card title at phase 5."},
		Palettes: []designSwatchGroup{
			{Group: "Brand & surfaces", Swatches: []designSwatch{
				hslSwatch("primary"), hslSwatch("primary-glow"), hslSwatch("accent"),
				hslSwatch("background"), hslSwatch("card"), hslSwatch("muted"), hslSwatch("border"),
			}},
			{Group: "Semantics", Swatches: []designSwatch{
				hslSwatch("success"), hslSwatch("warning"), hslSwatch("destructive"),
			}},
			{Group: "Severity", Swatches: []designSwatch{
				hslSwatch("severity-critical"), hslSwatch("severity-high"), hslSwatch("severity-medium"),
				hslSwatch("severity-low"), hslSwatch("severity-info"),
			}},
			{Group: "Provider brands", Swatches: []designSwatch{
				hslSwatch("brand-aws"), hslSwatch("brand-gcp"), hslSwatch("brand-do"),
				hslSwatch("brand-hetzner"), hslSwatch("brand-kubernetes"), hslSwatch("brand-linux"),
			}},
			{Group: "Gradients", Swatches: []designSwatch{
				gradientSwatch("gradient-primary"), gradientSwatch("gradient-critical"),
				gradientSwatch("gradient-high"), gradientSwatch("gradient-medium"),
				gradientSwatch("gradient-low"), gradientSwatch("gradient-success"),
				gradientSwatch("gradient-info"),
			}},
		},
		Easings: designEasings(),
		Shadows: []designShadow{
			{Class: "shadow-soft"},
			{Class: "shadow-elevated"},
			{Class: "shadow-floating"},
			{Class: "shadow-glass"},
		},
	}
}

// hslSwatch builds a solid-color swatch from a token name. The
// background is template.CSS so html/template keeps the var() ref
// instead of replacing it with ZgotmplZ.
func hslSwatch(token string) designSwatch {
	//nolint:gosec // token is a hardcoded design-system literal, never user input
	return designSwatch{Name: token, Var: template.CSS("hsl(var(--" + token + "))")}
}

// gradientSwatch builds a gradient swatch from a gradient token name.
func gradientSwatch(token string) designSwatch {
	//nolint:gosec // token is a hardcoded design-system literal, never user input
	return designSwatch{Name: token, Var: template.CSS("var(--" + token + ")")}
}

// designEasings returns the 6 Framer-style easings the zoo previews.
// Style is a typed CSS declaration so the var() ref survives.
func designEasings() []designEasing {
	mk := func(name string) designEasing {
		//nolint:gosec // name is a hardcoded design-system literal, never user input
		return designEasing{Name: name, Style: template.CSS("transition: left 600ms var(--ease-" + name + ");")}
	}
	return []designEasing{
		mk("in-quad"), mk("out-quad"), mk("in-out-quad"),
		mk("spring"), mk("soft-in"), mk("soft-out"),
	}
}
