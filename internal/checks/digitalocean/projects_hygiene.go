package digitalocean

import (
	"context"
	"fmt"
	"strings"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.22 phase 4 — DO Project hygiene checks split out of tail.go to
// satisfy the 600-LoC invariant.

var CheckProjectEnvironmentSet = compliancekit.Check{
	ID:           "do-project-no-environment",
	Title:        "Projects should declare their environment",
	Severity:     compliancekit.SeverityLow,
	Provider:     "digitalocean",
	Service:      "projects",
	ResourceType: docol.ProjectType,
	Description: "DO projects have an environment field (Development / " +
		"Staging / Production). Setting it correctly drives the right " +
		"defaults in the control panel and gives an unambiguous " +
		"signal in audit logs. Empty environments collapse the " +
		"distinction.",
	Remediation: "Set via the DO control panel: Projects > Settings > " +
		"Environment.",
	Frameworks: map[string][]string{
		"soc2":     {"CC1.4"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"projects"},
	Scanner: "projects.EnvironmentSet",
}

func ProjectEnvironmentSet(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, p := range g.ByType(docol.ProjectType) {
		env, _ := p.Attributes["environment"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckProjectEnvironmentSet.ID,
			Severity: CheckProjectEnvironmentSet.Severity,
			Resource: p.Ref(),
			Tags:     CheckProjectEnvironmentSet.Tags,
		}
		if strings.TrimSpace(env) == "" {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("project %q: environment unset", p.Name)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("project %q: environment=%q", p.Name, env)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckProjectDefaultDescription = compliancekit.Check{
	ID:           "do-project-default-no-description",
	Title:        "The default project should have an explicit description",
	Severity:     compliancekit.SeverityLow,
	Provider:     "digitalocean",
	Service:      "projects",
	ResourceType: docol.ProjectType,
	Description: "The default project gets every resource not assigned " +
		"elsewhere. Leaving its description empty makes the audit " +
		"trail ambiguous when a misassigned resource shows up there. " +
		"Set a description that explains the policy ('catch-all for " +
		"unsorted; review weekly').",
	Remediation: "Set a description on the default project via " +
		"the DO control panel.",
	Frameworks: map[string][]string{
		"soc2":     {"CC1.4"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"projects"},
	Scanner: "projects.DefaultDescription",
}

func ProjectDefaultDescription(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, p := range g.ByType(docol.ProjectType) {
		isDefault, _ := p.Attributes["is_default"].(bool)
		if !isDefault {
			continue
		}
		desc, _ := p.Attributes["description"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckProjectDefaultDescription.ID,
			Severity: CheckProjectDefaultDescription.Severity,
			Resource: p.Ref(),
			Tags:     CheckProjectDefaultDescription.Tags,
		}
		if strings.TrimSpace(desc) != "" {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("project %q: described", p.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("project %q: default project has no description", p.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}
func init() {
	compliancekit.Register(CheckProjectEnvironmentSet, ProjectEnvironmentSet)
	compliancekit.Register(CheckProjectDefaultDescription, ProjectDefaultDescription)
}
