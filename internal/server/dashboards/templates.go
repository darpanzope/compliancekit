package dashboards

// v1.14 phase 2 — built-in dashboard templates.
//
// Templates are operator-visible starting points. Picking one in the
// UI clones the template into a fresh per-user dashboard with the
// widgets pre-populated. The cloned dashboard records its origin in
// the Template column so the catalog UI can show a "cloned from
// SOC 2 readiness" badge.

import (
	"context"
	"errors"
	"fmt"
)

// Template is one named starter layout.
type Template struct {
	ID          string
	Name        string
	Description string
	Widgets     []TemplateWidget
}

// TemplateWidget mirrors Widget but without DashboardID; the cloner
// fills that in when materializing the row.
type TemplateWidget struct {
	Kind       Kind
	Title      string
	QueryJSON  string
	ConfigJSON string
	GridX      int
	GridY      int
	GridW      int
	GridH      int
}

// BuiltinTemplates returns the v1.14 phase-2 starter set. The four
// shapes match the deliverable list in #46:
//
//	exec        Executive overview
//	aws         AWS landing zone
//	k8s         K8s-only
//	soc2        SOC 2 readiness
//
// Adding a template is operator-additive — the existing ones stay
// stable so cloned dashboards keep matching their origin badge.
func BuiltinTemplates() []Template {
	return []Template{
		{
			ID:          "exec",
			Name:        "Executive overview",
			Description: "Top-level score, severity mix, trend sparkline, and an auto-summary — the weekly stakeholder slide.",
			Widgets: []TemplateWidget{
				{Kind: KindScoreGauge, Title: "Hardening score", GridX: 0, GridY: 0, GridW: 4, GridH: 3},
				{Kind: KindSeverityDonut, Title: "Severity mix", GridX: 4, GridY: 0, GridW: 4, GridH: 3},
				{Kind: KindSparkline, Title: "30-day trend", GridX: 8, GridY: 0, GridW: 4, GridH: 3},
				{Kind: KindExecutiveSummary, Title: "Auto-summary", GridX: 0, GridY: 3, GridW: 12, GridH: 4},
				{Kind: KindFrameworkBar, Title: "Framework coverage", GridX: 0, GridY: 7, GridW: 8, GridH: 4},
				{Kind: KindFindingList, Title: "Top 10 critical", QueryJSON: `{"severity":["critical"],"limit":10}`, GridX: 8, GridY: 7, GridW: 4, GridH: 4},
			},
		},
		{
			ID:          "aws",
			Name:        "AWS landing zone",
			Description: "AWS-only filter pre-applied. IAM + S3 + EC2 + VPC at a glance.",
			Widgets: []TemplateWidget{
				{Kind: KindScoreGauge, Title: "AWS score", QueryJSON: `{"providers":["aws"]}`, GridX: 0, GridY: 0, GridW: 4, GridH: 3},
				{Kind: KindSeverityDonut, Title: "AWS severity mix", QueryJSON: `{"providers":["aws"]}`, GridX: 4, GridY: 0, GridW: 4, GridH: 3},
				{Kind: KindTreemap, Title: "Findings by service", QueryJSON: `{"providers":["aws"]}`, GridX: 8, GridY: 0, GridW: 4, GridH: 3},
				{Kind: KindHeatmap, Title: "Resource × severity", QueryJSON: `{"providers":["aws"]}`, GridX: 0, GridY: 3, GridW: 8, GridH: 5},
				{Kind: KindFindingList, Title: "Critical AWS", QueryJSON: `{"providers":["aws"],"severity":["critical"],"limit":10}`, GridX: 8, GridY: 3, GridW: 4, GridH: 5},
			},
		},
		{
			ID:          "k8s",
			Name:        "K8s-only",
			Description: "Kubernetes posture only. Workloads, RBAC, network policies, admission controllers.",
			Widgets: []TemplateWidget{
				{Kind: KindScoreGauge, Title: "K8s score", QueryJSON: `{"providers":["kubernetes"]}`, GridX: 0, GridY: 0, GridW: 4, GridH: 3},
				{Kind: KindSeverityDonut, Title: "K8s severity mix", QueryJSON: `{"providers":["kubernetes"]}`, GridX: 4, GridY: 0, GridW: 4, GridH: 3},
				{Kind: KindFrameworkRadar, Title: "NSA-CISA radar", QueryJSON: `{"providers":["kubernetes"],"frameworks":["nsa-cisa-k8s"]}`, GridX: 8, GridY: 0, GridW: 4, GridH: 5},
				{Kind: KindResourceTable, Title: "Workloads at risk", QueryJSON: `{"providers":["kubernetes"],"resource_types":["k8s.pod","k8s.deployment"]}`, GridX: 0, GridY: 3, GridW: 8, GridH: 5},
				{Kind: KindMarkdown, Title: "Runbook links", ConfigJSON: `{"body":"### Quick links\n- [Pod-security profiles](https://kubernetes.io/docs/concepts/security/pod-security-standards/)\n- [NSA-CISA hardening guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)"}`, GridX: 0, GridY: 8, GridW: 12, GridH: 3},
			},
		},
		{
			ID:          "soc2",
			Name:        "SOC 2 readiness",
			Description: "Pre-tuned for the SOC 2 controls. Clone, swap the framework filter, get an ISO/HIPAA/PCI variant.",
			Widgets: []TemplateWidget{
				{Kind: KindScoreGauge, Title: "SOC 2 score", QueryJSON: `{"frameworks":["soc2"]}`, GridX: 0, GridY: 0, GridW: 4, GridH: 3},
				{Kind: KindFrameworkBar, Title: "SOC 2 control coverage", QueryJSON: `{"frameworks":["soc2"]}`, GridX: 4, GridY: 0, GridW: 8, GridH: 3},
				{Kind: KindFrameworkRadar, Title: "Trust Service Criteria radar", QueryJSON: `{"frameworks":["soc2"]}`, GridX: 0, GridY: 3, GridW: 6, GridH: 5},
				{Kind: KindFindingList, Title: "Open SOC 2 findings", QueryJSON: `{"frameworks":["soc2"],"status":["fail"],"limit":25}`, GridX: 6, GridY: 3, GridW: 6, GridH: 5},
				{Kind: KindExecutiveSummary, Title: "Audit-pack summary", GridX: 0, GridY: 8, GridW: 12, GridH: 3},
			},
		},
	}
}

// TemplateByID returns the named template or ok=false.
func TemplateByID(id string) (Template, bool) {
	for _, t := range BuiltinTemplates() {
		if t.ID == id {
			return t, true
		}
	}
	return Template{}, false
}

// CloneTemplate materializes a Template into a per-user Dashboard.
// Each template widget becomes a real dashboard_widgets row; the
// dashboard records its origin in the Template column so the UI can
// surface a "cloned from X" badge.
func (s *Store) CloneTemplate(ctx context.Context, templateID, ownerUserID, createdBy, name string) (*Dashboard, error) {
	tmpl, ok := TemplateByID(templateID)
	if !ok {
		return nil, fmt.Errorf("dashboards: unknown template %q", templateID)
	}
	if name == "" {
		name = tmpl.Name
	}
	d, err := s.CreateDashboard(ctx, ownerUserID, createdBy, name, tmpl.Description, tmpl.ID)
	if err != nil {
		return nil, err
	}
	for i, tw := range tmpl.Widgets {
		w := &Widget{
			DashboardID: d.ID,
			Kind:        tw.Kind,
			Title:       tw.Title,
			QueryJSON:   defaulted(tw.QueryJSON, "{}"),
			ConfigJSON:  defaulted(tw.ConfigJSON, "{}"),
			GridX:       tw.GridX,
			GridY:       tw.GridY,
			GridW:       tw.GridW,
			GridH:       tw.GridH,
			OrderIdx:    i,
		}
		if _, err := s.AddWidget(ctx, w); err != nil {
			// Cleanup half-cloned dashboard so the operator isn't
			// stuck with a partial canvas.
			_ = s.DeleteDashboard(ctx, d.ID)
			return nil, fmt.Errorf("clone widget %d: %w", i, err)
		}
	}
	return s.ByID(ctx, d.ID)
}

func defaulted(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// ErrTemplateNotFound is exposed for callers that branch on it.
var ErrTemplateNotFound = errors.New("dashboards: template not found")
