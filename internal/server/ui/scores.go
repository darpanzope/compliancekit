package ui

// v1.5 Phase 8 — Score-over-time chart.
//
// /scores renders the hardening-score trend across the last N
// completed scans as a vanilla SVG line chart. Hover-tooltips show
// the exact value at each scan; click a point to navigate to the
// underlying /scans/{id} report.
//
// Phase 8 ships the global score trend. Per-framework scores require
// a schema extension (scans.score is global today; frameworks_scanned
// is just the JSON-array list of which frameworks the scan covered);
// v1.5.x can break out per-framework score columns and add multi-
// line overlays without changing the page chrome.

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

// scorePoint is one data point in the trend chart.
type scorePoint struct {
	ScanID     string
	CreatedAt  string
	Score      int
	Total      int
	Actionable int
	X          int // SVG x coord (computed in Go for the template's pure-data needs)
	Y          int // SVG y coord
}

type scoresView struct {
	View
	Points     []scorePoint
	Width      int    // SVG viewBox width
	Height     int    // SVG viewBox height
	Polyline   string // computed "x,y x,y x,y" for the <polyline> element
	YGridSteps []scoreGridStep
}

type scoreGridStep struct {
	Y     int
	Label int
}

func (u *UI) mountScoresRoutes(r chi.Router) {
	r.Get("/scores", u.scoresView)
}

func (u *UI) scoresView(w http.ResponseWriter, r *http.Request) {
	const width = 1100
	const height = 320
	const padL, padR, padT, padB = 50, 20, 24, 32

	rows, err := u.store.DB().QueryContext(r.Context(),
		`SELECT id, created_at, COALESCE(score, 0), total_findings, actionable_findings
		 FROM scans WHERE status = 'completed'
		 ORDER BY created_at DESC LIMIT 60`)
	if err != nil {
		u.fail(w, "load scores: "+err.Error())
		return
	}
	defer func() { _ = rows.Close() }()
	points := []scorePoint{}
	for rows.Next() {
		var p scorePoint
		if err := rows.Scan(&p.ScanID, &p.CreatedAt, &p.Score, &p.Total, &p.Actionable); err != nil {
			continue
		}
		points = append(points, p)
	}

	// Reverse so newest is on the right (we ORDER BY DESC for the
	// LIMIT but the chart wants oldest-first).
	for i, j := 0, len(points)-1; i < j; i, j = i+1, j-1 {
		points[i], points[j] = points[j], points[i]
	}

	innerW := width - padL - padR
	innerH := height - padT - padB
	pl := ""
	for i := range points {
		if len(points) == 1 {
			points[i].X = padL + innerW/2
		} else {
			points[i].X = padL + (innerW * i / (len(points) - 1))
		}
		points[i].Y = padT + innerH - (innerH * points[i].Score / 100)
		pl += sprintXY(points[i].X, points[i].Y) + " "
	}

	// Y-axis grid: 0 / 25 / 50 / 75 / 100
	grids := []scoreGridStep{}
	for _, lbl := range []int{0, 25, 50, 75, 100} {
		grids = append(grids, scoreGridStep{
			Y:     padT + innerH - (innerH * lbl / 100),
			Label: lbl,
		})
	}

	view := scoresView{
		View:       u.viewFor(r, "Score over time", "findings", View{}),
		Points:     points,
		Width:      width,
		Height:     height,
		Polyline:   pl,
		YGridSteps: grids,
	}
	u.render(w, "scores.html", view)
}

func sprintXY(x, y int) string {
	return strconv.Itoa(x) + "," + strconv.Itoa(y)
}
