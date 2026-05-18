package ui

import (
	"context"
	"net/http"

	"github.com/darpanzope/compliancekit/internal/report"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// htmlReport is a tiny wrapper around the v1.2 HTML reporter so the
// /scans/{id} page can serve the same single-file artifact the CLI
// renders. v1.5's explorer replaces this with the SQL-backed
// filtered findings view; v1.3 stays at the static-report level.
type htmlReport struct{}

// RenderInline writes the v1.2 HTML report to w directly. We share
// the existing reporter so any improvements on that path (v1.2.x
// theme tweaks, new chart drawers, etc.) flow through automatically.
func (htmlReport) RenderInline(w http.ResponseWriter, findings []compliancekit.Finding) {
	r := compliancekitReporter()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = r.Render(context.Background(), findings, nil, w)
}

// compliancekitReporter returns the v1.2 HTML reporter. Pulled into
// its own helper so the test code in this package can swap it without
// touching the report.go renderer.
var compliancekitReporter = func() compliancekit.Reporter {
	return report.NewHTML()
}
