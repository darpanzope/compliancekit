package doctl

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 6 — doctl strategies for the 10 Functions-depth checks.

func init() {
	register("doctl-do-functions-namespace-region",
		[]string{"do-functions-namespace-no-region"}, renderDoctlFnNamespaceRegion)
	register("doctl-do-functions-disabled-trigger-ratio",
		[]string{"do-functions-disabled-trigger-ratio"}, renderDoctlFnTriggerRatio)
	register("doctl-do-functions-namespace-access-key",
		[]string{"do-functions-namespace-no-access-key"}, renderDoctlFnAccessKey)
	register("doctl-do-functions-access-key-rotation",
		[]string{"do-functions-access-key-rotation"}, renderDoctlFnKeyRotation)
	register("doctl-do-functions-runtime-eol",
		[]string{"do-functions-runtime-eol"}, renderDoctlFnRuntime)
	register("doctl-do-functions-env-vars-plain",
		[]string{"do-functions-env-vars-plain"}, renderDoctlFnEnvVars)
	register("doctl-do-functions-source-secret-scan",
		[]string{"do-functions-source-secret-scan"}, renderDoctlFnSecretScan)
	register("doctl-do-functions-log-export",
		[]string{"do-functions-log-export"}, renderDoctlFnLogExport)
	register("doctl-do-functions-cold-start-mitigation",
		[]string{"do-functions-cold-start-mitigation"}, renderDoctlFnColdStart)
	register("doctl-do-functions-environment-tag",
		[]string{"do-functions-namespace-no-environment-tag"}, renderDoctlFnEnvTag)
}

func doctlFnNS(f core.Finding) string {
	if f.Resource.Name != "" {
		return f.Resource.Name
	}
	return "NAMESPACE"
}

func renderDoctlFnNamespaceRegion(f core.Finding) (remediate.Snippet, error) {
	ns := doctlFnNS(f)
	body := fmt.Sprintf("doctl serverless namespaces create --label %q --region nyc1", ns)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		VerifyCmd: "doctl serverless namespaces list --format Label,Region",
	}, nil
}

func renderDoctlFnTriggerRatio(f core.Finding) (remediate.Snippet, error) {
	ns := doctlFnNS(f)
	body := fmt.Sprintf(`# List + audit triggers in %s.
doctl serverless trigger list %s --format Name,Enabled,Type

# Disable + re-enable or delete:
# doctl serverless trigger enable  %s <trigger-name>
# doctl serverless trigger disable %s <trigger-name>
# doctl serverless trigger delete  %s <trigger-name>`, ns, ns, ns, ns, ns)
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
	}, nil
}

func renderDoctlFnAccessKey(f core.Finding) (remediate.Snippet, error) {
	ns := doctlFnNS(f)
	body := fmt.Sprintf("doctl serverless namespace add-key %s --label ci-key", ns)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		VerifyCmd: fmt.Sprintf("doctl serverless namespace list-keys %s --format Label,Created", ns),
		Notes:     "Capture key value at create time — it is shown only once.",
	}, nil
}

func renderDoctlFnKeyRotation(f core.Finding) (remediate.Snippet, error) {
	ns := doctlFnNS(f)
	body := fmt.Sprintf(`# List existing keys + last-used metadata (if available).
doctl serverless namespace list-keys %s --format Label,Created

# Revoke any key older than 90 days; issue a replacement; rotate consumers.
# doctl serverless namespace revoke-key %s <key-id>
# doctl serverless namespace add-key    %s --label rotation-Q1`, ns, ns, ns)
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
		Notes: "Quarterly cadence. Record last-rotation in the runbook.",
	}, nil
}

func renderDoctlFnRuntime(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"Functions runtime version",
		"https://docs.digitalocean.com/products/functions/reference/runtimes/",
		"Update project.yml `runtime:` to a supported version, then `doctl serverless deploy`")
}

func renderDoctlFnEnvVars(_ core.Finding) (remediate.Snippet, error) {
	body := `# Re-deploy with encrypted env file.
doctl serverless deploy --env-file .env --encrypted

# Audit existing per-function via the dashboard's env-var inspector.`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "--encrypted stores env-vars encrypted at rest; without the flag they're plaintext.",
	}, nil
}

func renderDoctlFnSecretScan(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"pre-deploy source secret scan",
		"https://github.com/gitleaks/gitleaks",
		"Add gitleaks / trufflehog gate in CI BEFORE `doctl serverless deploy`")
}

func renderDoctlFnLogExport(_ core.Finding) (remediate.Snippet, error) {
	body := `# Cron-pull activations from doctl + ship to a long-retention sink.
# Example (every 5 min, ships to a Datadog HTTP intake):

doctl serverless activations list -o json --last 5m \
  | curl -X POST -H "DD-API-KEY: $DD_API_KEY" \
      -H "Content-Type: application/json" \
      --data @- https://http-intake.logs.datadoghq.com/v1/input`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		Notes: "Run as a cron / systemd timer. Alternative: instrument the function to POST logs directly.",
	}, nil
}

func renderDoctlFnColdStart(f core.Finding) (remediate.Snippet, error) {
	ns := doctlFnNS(f)
	body := fmt.Sprintf(`# Add a scheduled keepalive trigger for the latency-sensitive function.
doctl serverless trigger create %s \
  --type SCHEDULED --cron '*/5 * * * *' \
  --function my-package/my-function`, ns)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: false, Content: body,
		Notes: "5-minute cadence balances warm-pool latency vs invocation cost. Tune per workload.",
	}, nil
}

func renderDoctlFnEnvTag(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"Functions namespace environment naming convention",
		"https://docs.digitalocean.com/products/functions/",
		"Create new namespaces with explicit prefix (functions-prod, functions-staging)")
}

// v0.19 phase 9 — legacy backfill for v0.9-vintage Functions checks.
var legacyFunctionsDoctlEntries = map[string]legacyDoctlEntry{
	"do-functions-disabled-triggers": {risk: remediate.RiskManual,
		content: "doctl serverless trigger list NS\n# Re-enable or delete each disabled trigger."},
	"do-functions-namespace-empty": {risk: remediate.RiskReview,
		content: "doctl serverless namespaces delete NS_UUID --force"},
	"do-functions-no-access-keys": {risk: remediate.RiskReview,
		content: "doctl serverless namespace add-key NS --label ci-key"},
}

func init() { registerLegacyDoctl(legacyFunctionsDoctlEntries) }
