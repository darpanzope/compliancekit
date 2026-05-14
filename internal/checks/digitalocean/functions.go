package digitalocean

import (
	"context"
	"fmt"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

var CheckFunctionsHasAccessKey = core.Check{
	ID:           "do-functions-no-access-keys",
	Title:        "Functions namespaces should have at least one access key",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "functions",
	ResourceType: docol.FunctionsNamespaceType,
	Description: "DO Functions namespaces ship with an implicit owner " +
		"key but explicit access keys are how applications + CI " +
		"systems authenticate. Zero access keys is either an unused " +
		"namespace (delete it) or an over-reliance on the implicit " +
		"owner key (rotate to scoped keys).",
	Remediation: "Either delete the unused namespace via the DO control " +
		"panel, or create scoped access keys per workload that " +
		"connects to it.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15"},
		"cis-v8":   {"5.4"},
	},
	Tags:    []string{"functions", "credential-hygiene"},
	Scanner: "functions.HasAccessKey",
}

func FunctionsHasAccessKey(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, ns := range g.ByType(docol.FunctionsNamespaceType) {
		n, _ := ns.Attributes["access_key_count"].(int)
		f := core.Finding{
			CheckID:  CheckFunctionsHasAccessKey.ID,
			Severity: CheckFunctionsHasAccessKey.Severity,
			Resource: ns.Ref(),
			Tags:     CheckFunctionsHasAccessKey.Tags,
		}
		if n > 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("ns %q: %d access key(s)", ns.Name, n)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("ns %q: no access keys (relying on owner key only)", ns.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckFunctionsOrphan = core.Check{
	ID:           "do-functions-namespace-empty",
	Title:        "Functions namespaces should host at least one trigger",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "functions",
	ResourceType: docol.FunctionsNamespaceType,
	Description: "A namespace with zero triggers is provisioned but " +
		"unused. Functions billing has a free tier so the cost is " +
		"low; the audit-trail confusion isn't. Either delete or " +
		"deploy something into it.",
	Remediation: "List triggers: 'doctl serverless namespaces get " +
		"<namespace>'. If empty, 'doctl serverless namespaces delete'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"functions", "hygiene"},
	Scanner: "functions.Orphan",
}

func FunctionsOrphan(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, ns := range g.ByType(docol.FunctionsNamespaceType) {
		n, _ := ns.Attributes["trigger_count"].(int)
		f := core.Finding{
			CheckID:  CheckFunctionsOrphan.ID,
			Severity: CheckFunctionsOrphan.Severity,
			Resource: ns.Ref(),
			Tags:     CheckFunctionsOrphan.Tags,
		}
		if n > 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("ns %q: %d trigger(s)", ns.Name, n)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("ns %q: empty (no triggers)", ns.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckFunctionsAllTriggersEnabled = core.Check{
	ID:           "do-functions-disabled-triggers",
	Title:        "Functions namespaces should not have disabled triggers",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "functions",
	ResourceType: docol.FunctionsNamespaceType,
	Description: "Disabled triggers indicate either a forgotten test or " +
		"a manual disable during incident response that was never " +
		"re-enabled. Either way the trigger should be cleaned up so " +
		"the active surface matches the deployed surface.",
	Remediation: "List: 'doctl serverless triggers list'. For each " +
		"disabled trigger, re-enable or delete.",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"functions", "hygiene"},
	Scanner: "functions.AllTriggersEnabled",
}

func FunctionsAllTriggersEnabled(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, ns := range g.ByType(docol.FunctionsNamespaceType) {
		total, _ := ns.Attributes["trigger_count"].(int)
		enabled, _ := ns.Attributes["enabled_trigger_count"].(int)
		f := core.Finding{
			CheckID:  CheckFunctionsAllTriggersEnabled.ID,
			Severity: CheckFunctionsAllTriggersEnabled.Severity,
			Resource: ns.Ref(),
			Tags:     CheckFunctionsAllTriggersEnabled.Tags,
		}
		if total == 0 || enabled == total {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("ns %q: %d/%d triggers enabled", ns.Name, enabled, total)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("ns %q: %d/%d triggers enabled (%d disabled)", ns.Name, enabled, total, total-enabled)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckFunctionsHasAccessKey, FunctionsHasAccessKey)
	core.Register(CheckFunctionsOrphan, FunctionsOrphan)
	core.Register(CheckFunctionsAllTriggersEnabled, FunctionsAllTriggersEnabled)
}
