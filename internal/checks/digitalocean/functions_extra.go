package digitalocean

import (
	"context"
	"fmt"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.19 phase 6 — Functions depth. godo exposes namespace + trigger
// + access-key metadata; runtime, env-vars, source code, log
// destinations, cold-start posture are not in the public API. Most
// checks here are manual-verify pointing at the dashboard + doctl
// serverless commands.

const functionsDocsURL = "https://docs.digitalocean.com/products/functions/"

func newFnFinding(check compliancekit.Check, ns compliancekit.Resource) compliancekit.Finding {
	return compliancekit.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Resource: ns.Ref(),
		Tags:     check.Tags,
	}
}

func fnManualVerify(check compliancekit.Check, ns compliancekit.Resource, control, hint string) compliancekit.Finding {
	f := newFnFinding(check, ns)
	f.Status = compliancekit.StatusError
	f.Message = fmt.Sprintf("functions namespace %q: %s — DO API does not surface this; verify via %s",
		ns.Name, control, hint)
	return f
}

// ----- 1. region pinned -----------------------------------------------

var CheckFnNamespaceRegion = compliancekit.Check{
	ID:           "do-functions-namespace-no-region",
	Title:        "Functions namespaces must declare an explicit region",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "functions",
	ResourceType: docol.FunctionsNamespaceType,
	Description: "An unset region means functions deploy wherever DO " +
		"defaults — typically NYC1 — which may not match data-residency " +
		"requirements. SOC2 CC6.1 + ISO A.5.31 expect regional " +
		"placement to be a deliberate decision recorded against the " +
		"workload.",
	Remediation: "Recreate the namespace with --region: `doctl serverless " +
		"namespaces create --label <l> --region nyc1`. Migrate existing " +
		"functions via `doctl serverless deploy`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.31"},
		"cis-v8":   {"3.5"},
	},
	Tags:    []string{"functions", "region", "residency"},
	Scanner: "functions.NamespaceRegion",
}

func FnNamespaceRegion(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, ns := range g.ByType(docol.FunctionsNamespaceType) {
		f := newFnFinding(CheckFnNamespaceRegion, ns)
		if ns.Region == "" {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("functions namespace %q: no region declared", ns.Name)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("functions namespace %q: region=%s", ns.Name, ns.Region)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 2. all triggers enabled? ----------------------------------------

var CheckFnAllTriggersEnabledRatio = compliancekit.Check{
	ID:           "do-functions-disabled-trigger-ratio",
	Title:        "Disabled-trigger ratio must be 0 (no orphan triggers)",
	Severity:     compliancekit.SeverityLow,
	Provider:     "digitalocean",
	Service:      "functions",
	ResourceType: docol.FunctionsNamespaceType,
	Description: "Disabled triggers indicate either an in-progress " +
		"migration left half-finished or a once-used schedule abandoned. " +
		"Either way they accumulate as cognitive cost on every audit. " +
		"Existing do-functions-disabled-triggers covers \"all\"; this " +
		"check counts the ratio so partial drift is visible.",
	Remediation: "List + decide: `doctl serverless trigger list <ns>`. " +
		"Either re-enable or delete with `doctl serverless trigger delete`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC8.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"functions", "triggers", "hygiene"},
	Scanner: "functions.DisabledTriggerRatio",
}

func FnAllTriggersEnabledRatio(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, ns := range g.ByType(docol.FunctionsNamespaceType) {
		total, _ := ns.Attributes["trigger_count"].(int)
		if total == 0 {
			continue
		}
		enabled, _ := ns.Attributes["enabled_trigger_count"].(int)
		disabled := total - enabled
		f := newFnFinding(CheckFnAllTriggersEnabledRatio, ns)
		if disabled == 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("functions namespace %q: %d/%d triggers enabled", ns.Name, enabled, total)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("functions namespace %q: %d/%d triggers disabled", ns.Name, disabled, total)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 3. access key minimum + rotation reminder ---------------------

var CheckFnAccessKeyMinimum = compliancekit.Check{
	ID:           "do-functions-namespace-no-access-key",
	Title:        "Functions namespaces must have at least one access key registered",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "functions",
	ResourceType: docol.FunctionsNamespaceType,
	Description: "A namespace without an access key has no way to invoke " +
		"functions outside the DO control panel. Either the namespace " +
		"is unused (consider deletion) or the operator is invoking " +
		"with their personal session token (poor audit trail). Either " +
		"way: not a production posture.",
	Remediation: "Create a scoped key: `doctl serverless functions invoke " +
		"--access-key` flow requires a registered key. Issue via " +
		"`doctl serverless namespace add-key` (or the dashboard).",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.5.16"},
		"cis-v8":   {"5.1", "5.4"},
	},
	Tags:    []string{"functions", "credentials"},
	Scanner: "functions.AccessKeyMinimum",
}

func FnAccessKeyMinimum(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, ns := range g.ByType(docol.FunctionsNamespaceType) {
		n, _ := ns.Attributes["access_key_count"].(int)
		f := newFnFinding(CheckFnAccessKeyMinimum, ns)
		if n > 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("functions namespace %q: %d access key(s)", ns.Name, n)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("functions namespace %q: no access keys registered", ns.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 4. manual: access key rotation -------------------------------

var CheckFnAccessKeyRotation = compliancekit.Check{
	ID:           "do-functions-access-key-rotation",
	Title:        "Functions access keys must be rotated on a documented cadence",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "functions",
	ResourceType: docol.FunctionsNamespaceType,
	Description: "Functions access keys are long-lived bearer credentials " +
		"that authorize invocation of every function in the namespace. " +
		"godo does not expose key creation timestamps; rotation cadence " +
		"must be tracked manually. SOC2 CC6.3 + ISO A.5.16 + CIS 5.4 " +
		"each require ≤90d rotation on long-lived credentials.",
	Remediation: "Run quarterly: `doctl serverless namespace list-keys " +
		"<ns>`, revoke any key older than 90 days, issue replacements, " +
		"rotate consumers. Document the procedure + last-rotation in " +
		"the runbook.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.3"},
		"iso27001": {"A.5.16", "A.8.5"},
		"cis-v8":   {"5.4"},
	},
	Tags:    []string{"functions", "credentials", "manual-verify"},
	Scanner: "functions.AccessKeyRotation",
}

func FnAccessKeyRotation(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, ns := range g.ByType(docol.FunctionsNamespaceType) {
		findings = append(findings,
			fnManualVerify(CheckFnAccessKeyRotation, ns,
				"access key rotation cadence",
				"`doctl serverless namespace list-keys "+ns.Name+"`"))
	}
	return findings, nil
}

// ----- 5. manual: runtime versions current --------------------------

var CheckFnRuntimeNotEOL = compliancekit.Check{
	ID:           "do-functions-runtime-eol",
	Title:        "Functions runtimes must not be EOL (Node 14/16, Python 3.8, etc.)",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "functions",
	ResourceType: docol.FunctionsNamespaceType,
	Description: "DO Functions support a fixed list of runtimes; older " +
		"versions move to EOL and stop receiving CVE patches. Per-" +
		"function runtime is NOT in the public namespace API — operators " +
		"must check via project.yml or the dashboard.",
	Remediation: "Inspect: `doctl serverless functions list <pkg>/<fn>` " +
		"shows the runtime per function. Update project.yml runtime: " +
		"\"nodejs:20\" (or python:3.11), then `doctl serverless deploy`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1"},
		"iso27001": {"A.8.8"},
		"cis-v8":   {"7.3", "7.4"},
	},
	Tags:    []string{"functions", "runtime", "patching", "manual-verify"},
	Scanner: "functions.RuntimeNotEOL",
}

func FnRuntimeNotEOL(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, ns := range g.ByType(docol.FunctionsNamespaceType) {
		findings = append(findings,
			fnManualVerify(CheckFnRuntimeNotEOL, ns,
				"runtime versions across functions",
				"`doctl serverless functions list` + project.yml inspection"))
	}
	return findings, nil
}

// ----- 6. manual: env vars encrypted --------------------------------

var CheckFnEnvVarsEncrypted = compliancekit.Check{
	ID:           "do-functions-env-vars-plain",
	Title:        "Functions env vars containing secrets must use --encrypted",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "functions",
	ResourceType: docol.FunctionsNamespaceType,
	Description: "DO Functions support encrypted-at-rest env vars via " +
		"`doctl serverless functions deploy --encrypted`. Without the " +
		"flag, env vars are stored in plaintext alongside the function " +
		"package. The DO API does not differentiate encrypted vs plain " +
		"in the namespace listing.",
	Remediation: "Re-deploy with `doctl serverless deploy --env-file " +
		".env --encrypted`. Audit existing deploys via the dashboard's " +
		"per-function env-var inspector.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.5", "A.8.24"},
		"cis-v8":   {"3.11"},
	},
	Tags:    []string{"functions", "secrets", "manual-verify"},
	Scanner: "functions.EnvVarsEncrypted",
}

func FnEnvVarsEncrypted(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, ns := range g.ByType(docol.FunctionsNamespaceType) {
		findings = append(findings,
			fnManualVerify(CheckFnEnvVarsEncrypted, ns,
				"env-var encryption posture",
				"`doctl serverless functions get` per function"))
	}
	return findings, nil
}

// ----- 7. manual: source secret scanning -----------------------------

var CheckFnSourceSecretScan = compliancekit.Check{
	ID:           "do-functions-source-secret-scan",
	Title:        "Function source must pass secret scanning before deploy",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "functions",
	ResourceType: docol.FunctionsNamespaceType,
	Description: "`doctl serverless deploy` packages local source verbatim " +
		"— no secret-scan gate. Any AWS key / DO token committed to the " +
		"function repo ships to production. SOC2 CC6.7 + CIS 16.4 each " +
		"require pre-deploy credential hygiene.",
	Remediation: "Add a pre-deploy step in CI: `gitleaks detect` or " +
		"`trufflehog filesystem .` against the function source tree. " +
		"Block deploy on any non-zero exit.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.5"},
		"cis-v8":   {"16.4"},
	},
	Tags:    []string{"functions", "secret-scan", "manual-verify"},
	Scanner: "functions.SourceSecretScan",
}

func FnSourceSecretScan(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, ns := range g.ByType(docol.FunctionsNamespaceType) {
		findings = append(findings,
			fnManualVerify(CheckFnSourceSecretScan, ns,
				"pre-deploy secret scan",
				"`gitleaks detect` or `trufflehog filesystem .` in CI"))
	}
	return findings, nil
}

// ----- 8. manual: log forwarding -------------------------------------

var CheckFnLogExport = compliancekit.Check{
	ID:           "do-functions-log-export",
	Title:        "Functions logs must be exported to a long-retention sink",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "functions",
	ResourceType: docol.FunctionsNamespaceType,
	Description: "DO Functions logs are accessible via " +
		"`doctl serverless activations logs --last` with a short " +
		"retention window. SOC2 CC7.2 + ISO A.8.15 expect ≥90d retention " +
		"of invocation logs. No native log-forwarding configuration " +
		"exists; operators ship logs from inside the function (HTTP " +
		"to Datadog / Logtail / Splunk).",
	Remediation: "Wrap each function with a try/finally that POSTs the " +
		"invocation record to a log sink. OR pull via doctl on a cron " +
		"and ship to S3/Spaces (`doctl serverless activations list -o " +
		"json | curl ...`). Document retention SLA.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.15"},
		"cis-v8":   {"8.5"},
	},
	Tags:    []string{"functions", "logging", "manual-verify"},
	Scanner: "functions.LogExport",
}

func FnLogExport(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, ns := range g.ByType(docol.FunctionsNamespaceType) {
		findings = append(findings,
			fnManualVerify(CheckFnLogExport, ns,
				"log forwarding strategy",
				"`doctl serverless activations list` + in-function sink"))
	}
	return findings, nil
}

// ----- 9. manual: cold-start mitigation -----------------------------

var CheckFnColdStartMitigation = compliancekit.Check{
	ID:           "do-functions-cold-start-mitigation",
	Title:        "Latency-sensitive functions must mitigate cold starts",
	Severity:     compliancekit.SeverityLow,
	Provider:     "digitalocean",
	Service:      "functions",
	ResourceType: docol.FunctionsNamespaceType,
	Description: "DO Functions cold-start latency can reach multi-second " +
		"on first invocation after idle. Latency-sensitive paths " +
		"(synchronous webhook handlers, customer-facing APIs) need a " +
		"scheduled keepalive trigger or a different runtime entirely. " +
		"Hygiene check; the right mitigation depends on the workload.",
	Remediation: "Add a SCHEDULED trigger at 30s-1m cadence that invokes " +
		"each cold-sensitive function: `doctl serverless trigger create " +
		"--type SCHEDULED --cron '* * * * *' <fn>`. Cost is low; impact " +
		"on p99 latency is meaningful.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"functions", "cold-start", "manual-verify"},
	Scanner: "functions.ColdStartMitigation",
}

func FnColdStartMitigation(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, ns := range g.ByType(docol.FunctionsNamespaceType) {
		findings = append(findings,
			fnManualVerify(CheckFnColdStartMitigation, ns,
				"cold-start mitigation strategy",
				"`doctl serverless trigger list "+ns.Name+"` to see scheduled keepalives"))
	}
	return findings, nil
}

// ----- 10. manual: namespace tagged with environment ---------------

var CheckFnNamespaceEnvironmentTag = compliancekit.Check{
	ID:           "do-functions-namespace-no-environment-tag",
	Title:        "Functions namespaces should carry an environment label",
	Severity:     compliancekit.SeverityLow,
	Provider:     "digitalocean",
	Service:      "functions",
	ResourceType: docol.FunctionsNamespaceType,
	Description: "Without an environment label in the namespace name " +
		"(prefix or suffix), production + non-prod namespaces are " +
		"indistinguishable to billing reports + on-call dashboards. " +
		"DO Functions namespaces don't carry separate tag fields; " +
		"convention has to live in the label.",
	Remediation: "Name new namespaces with explicit prefix: " +
		"`functions-prod`, `functions-staging`. Existing namespaces " +
		"need recreate to rename — plan a migration window.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"functions", "naming", "manual-verify"},
	Scanner: "functions.NamespaceEnvironmentTag",
}

func FnNamespaceEnvironmentTag(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, ns := range g.ByType(docol.FunctionsNamespaceType) {
		findings = append(findings,
			fnManualVerify(CheckFnNamespaceEnvironmentTag, ns,
				"environment label in namespace name",
				functionsDocsURL+"reference/projects/"))
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckFnNamespaceRegion, FnNamespaceRegion)
	compliancekit.Register(CheckFnAllTriggersEnabledRatio, FnAllTriggersEnabledRatio)
	compliancekit.Register(CheckFnAccessKeyMinimum, FnAccessKeyMinimum)
	compliancekit.Register(CheckFnAccessKeyRotation, FnAccessKeyRotation)
	compliancekit.Register(CheckFnRuntimeNotEOL, FnRuntimeNotEOL)
	compliancekit.Register(CheckFnEnvVarsEncrypted, FnEnvVarsEncrypted)
	compliancekit.Register(CheckFnSourceSecretScan, FnSourceSecretScan)
	compliancekit.Register(CheckFnLogExport, FnLogExport)
	compliancekit.Register(CheckFnColdStartMitigation, FnColdStartMitigation)
	compliancekit.Register(CheckFnNamespaceEnvironmentTag, FnNamespaceEnvironmentTag)
}
