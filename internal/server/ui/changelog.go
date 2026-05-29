package ui

// v1.19 phase 1 — changelog modal on first login after upgrade.
//
// The catalog below is the source of truth for the "what's new" modal.
// The NEWEST entry is the one the modal surfaces; it auto-opens once per
// user until dismissed. Dismissal reuses the v1.19 phase 0
// user_tour_state table with tour_id = changelogTourID(version) — so no
// extra migration, and "reset all tours" on /onboarding also re-arms the
// changelog. Each highlight deep-links into the touched UI area so the
// operator can try the feature immediately.

// changelogHighlight is one bullet in the modal, with an optional deep
// link into the UI area the feature touches.
type changelogHighlight struct {
	Text string
	Href string // empty = no link
}

// changelogEntry is one shipped version's highlights.
type changelogEntry struct {
	Version    string
	Date       string
	Headline   string
	Highlights []changelogHighlight
}

// changelog is newest-first. changelog[0] drives the modal.
var changelog = []changelogEntry{
	{
		Version:  "v1.19.0",
		Date:     "2026-05-29",
		Headline: "Onboarding 2.0 + global search + table excellence",
		Highlights: []changelogHighlight{
			{Text: "Guided tours — press . on any page, or replay them anytime.", Href: "/onboarding"},
			{Text: "Global search — Cmd+K (or /) finds any finding, resource, scan, or setting.", Href: "/scans"},
			{Text: "Tables you can resize, reorder, pin, and save column sets on.", Href: "/findings"},
			{Text: "Inline edit + bulk actions right from the findings table.", Href: "/findings"},
		},
	},
	{
		Version:  "v1.18.0",
		Date:     "2026-05-28",
		Headline: "Design system & visual polish",
		Highlights: []changelogHighlight{
			{Text: "Every page rebuilt on the new design system — tokens, components, motion.", Href: "/design"},
			{Text: "Hero MetricCards, status pills, and gradient severity tiles on findings.", Href: "/findings"},
			{Text: "Zero-critical confetti, celebration cards, and streak badges.", Href: "/scores"},
		},
	},
}

// changelogTourID maps a version to the user_tour_state row id the
// changelog modal uses for dismissal.
func changelogTourID(version string) string { return "changelog-" + version }

// latestChangelog returns the newest entry (the one the modal shows),
// or false when the catalog is empty.
func latestChangelog() (changelogEntry, bool) {
	if len(changelog) == 0 {
		return changelogEntry{}, false
	}
	return changelog[0], true
}
