package report

// v1.14 phase 4 — executive-summary auto-gen.
//
// The "Score: 78 (+3 vs last week). Top 5 findings: ..." paragraph
// the v1.14 ExecutiveSummary widget renders. Pure templating — no
// LLM call, no phone-home, no surprise dependencies. Inputs come
// from the existing v0.6 trend store + the current-scan rollup.

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// SummaryInput is the canonical bag the auto-summary template
// renders against. Embedders populate it from whatever query path
// fits — the v1.14 widget reads from the latest scan + the v0.6
// trend snapshot 7 days ago + the rule-engine wins/regressions
// tally.
type SummaryInput struct {
	// AsOf is the timestamp the summary reflects. Renders into the
	// "as of …" footer line.
	AsOf time.Time

	// Score is the v0.6 hardening score 0..100. PriorScore is the
	// equivalent from the look-back window (7 days by default;
	// the widget passes whatever its config_json declares).
	Score      int
	PriorScore int

	// ResourceCount + FailingResourceCount drive the "covers N
	// resources" + "M with at least one failing check" lines.
	ResourceCount        int
	FailingResourceCount int

	// TopFindings is the operator-pickable "biggest open issues"
	// list. Pre-sorted by impact (severity then age); the renderer
	// just slices the top N.
	TopFindings []SummaryFinding

	// Wins is rule-engine "this resolved since the last window"
	// rows. Regressions is the inverse.
	Wins        []SummaryFinding
	Regressions []SummaryFinding

	// FrameworkCoverage maps framework_id → coverage percent in
	// 0..100. The largest delta vs the prior window gets a one-line
	// callout.
	FrameworkCoverage      map[string]int
	PriorFrameworkCoverage map[string]int
}

// SummaryFinding is the trimmed projection the summary needs;
// callers map from compliancekit.Finding before passing in.
type SummaryFinding struct {
	CheckID      string
	Severity     string
	ResourceName string
	Message      string
}

// Summary returns the rendered executive-summary markdown body. Use
// directly in the ExecutiveSummary widget or in the v1.14 phase 6
// scheduled email payload.
func Summary(in SummaryInput) string {
	var b strings.Builder
	if in.AsOf.IsZero() {
		in.AsOf = time.Now().UTC()
	}
	fmt.Fprintf(&b, "**Score: %d** %s\n\n", in.Score, scoreDelta(in.Score, in.PriorScore))

	if in.ResourceCount > 0 {
		fmt.Fprintf(&b, "Covers **%d resources** (%d failing at least one check).\n\n",
			in.ResourceCount, in.FailingResourceCount)
	}

	if len(in.TopFindings) > 0 {
		b.WriteString("**Top findings:**\n\n")
		for i, f := range topN(in.TopFindings, 5) {
			fmt.Fprintf(&b, "%d. [%s] `%s` — %s on %s\n",
				i+1, strings.ToUpper(f.Severity), f.CheckID, f.Message, f.ResourceName)
		}
		b.WriteString("\n")
	}

	if len(in.Wins) > 0 {
		fmt.Fprintf(&b, "**Wins:** %d resolved since last window — %s.\n\n",
			len(in.Wins), summarizeIDs(in.Wins, 3))
	}
	if len(in.Regressions) > 0 {
		fmt.Fprintf(&b, "**Regressions:** %d new findings — %s.\n\n",
			len(in.Regressions), summarizeIDs(in.Regressions, 3))
	}

	if msg := frameworkHeadline(in.FrameworkCoverage, in.PriorFrameworkCoverage); msg != "" {
		fmt.Fprintf(&b, "%s\n\n", msg)
	}

	fmt.Fprintf(&b, "_as of %s_\n", in.AsOf.UTC().Format("2006-01-02 15:04 UTC"))
	return b.String()
}

func scoreDelta(now, prior int) string {
	if prior == 0 {
		return "(no prior window to compare)"
	}
	d := now - prior
	switch {
	case d > 0:
		return fmt.Sprintf("(**+%d** vs last window)", d)
	case d < 0:
		return fmt.Sprintf("(**%d** vs last window)", d)
	}
	return "(unchanged vs last window)"
}

func topN(in []SummaryFinding, n int) []SummaryFinding {
	if len(in) < n {
		n = len(in)
	}
	return in[:n]
}

func summarizeIDs(in []SummaryFinding, limit int) string {
	if len(in) == 0 {
		return ""
	}
	if len(in) < limit {
		limit = len(in)
	}
	parts := make([]string, 0, limit)
	for _, f := range in[:limit] {
		parts = append(parts, fmt.Sprintf("`%s`", f.CheckID))
	}
	if len(in) > limit {
		parts = append(parts, fmt.Sprintf("+%d more", len(in)-limit))
	}
	return strings.Join(parts, ", ")
}

// frameworkHeadline finds the largest week-over-week delta + emits a
// one-line callout. Empty string when no prior data to compare.
func frameworkHeadline(now, prior map[string]int) string {
	if len(now) == 0 || len(prior) == 0 {
		return ""
	}
	type entry struct {
		id    string
		delta int
	}
	rows := make([]entry, 0, len(now))
	for id, n := range now {
		p, ok := prior[id]
		if !ok {
			continue
		}
		rows = append(rows, entry{id, n - p})
	}
	if len(rows) == 0 {
		return ""
	}
	sort.Slice(rows, func(i, j int) bool {
		return abs(rows[i].delta) > abs(rows[j].delta)
	})
	top := rows[0]
	if top.delta == 0 {
		return ""
	}
	if top.delta > 0 {
		return fmt.Sprintf("**%s coverage** improved by **%d points**.", top.id, top.delta)
	}
	return fmt.Sprintf("**%s coverage** regressed by **%d points**.", top.id, -top.delta)
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
