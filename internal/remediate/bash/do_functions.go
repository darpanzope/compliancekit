package bash

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 6 — bash strategies for the 10 Functions-depth checks.

func init() {
	register("bash-do-functions-namespace-region",
		[]string{"do-functions-namespace-no-region"}, renderBashFnNamespaceRegion)
	register("bash-do-functions-disabled-trigger-ratio",
		[]string{"do-functions-disabled-trigger-ratio"}, renderBashFnTriggerRatio)
	register("bash-do-functions-namespace-access-key",
		[]string{"do-functions-namespace-no-access-key"}, renderBashFnAccessKey)
	register("bash-do-functions-access-key-rotation",
		[]string{"do-functions-access-key-rotation"}, renderBashFnKeyRotation)
	register("bash-do-functions-runtime-eol",
		[]string{"do-functions-runtime-eol"}, renderBashFnRuntime)
	register("bash-do-functions-env-vars-plain",
		[]string{"do-functions-env-vars-plain"}, renderBashFnEnvVars)
	register("bash-do-functions-source-secret-scan",
		[]string{"do-functions-source-secret-scan"}, renderBashFnSecretScan)
	register("bash-do-functions-log-export",
		[]string{"do-functions-log-export"}, renderBashFnLogExport)
	register("bash-do-functions-cold-start-mitigation",
		[]string{"do-functions-cold-start-mitigation"}, renderBashFnColdStart)
	register("bash-do-functions-environment-tag",
		[]string{"do-functions-namespace-no-environment-tag"}, renderBashFnEnvTag)
}

func bashFnNS(f core.Finding) string {
	if f.Resource.Name != "" {
		return f.Resource.Name
	}
	return "NAMESPACE"
}

func renderBashFnNamespaceRegion(f core.Finding) (remediate.Snippet, error) {
	ns := bashFnNS(f)
	body := fmt.Sprintf(`label=%q
doctl serverless namespaces create --label "$label" --region nyc1`, ns)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		VerifyCmd: "doctl serverless namespaces list --format Label,Region",
	}, nil
}

func renderBashFnTriggerRatio(f core.Finding) (remediate.Snippet, error) {
	ns := bashFnNS(f)
	body := fmt.Sprintf(`ns=%q
# Find disabled triggers + prompt to delete (interactive).
disabled="$(doctl serverless trigger list "$ns" -o json | jq -r '.[] | select(.is_enabled==false) | .name')"
for t in $disabled; do
  read -r -p "delete disabled trigger '$t'? [y/N] " ans
  case "$ans" in
    y|Y) doctl serverless trigger delete "$ns" "$t" --force ;;
  esac
done`, ns)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		Notes: "Interactive. Bypass the prompt with a yes pipe if you've audited the disabled list.",
	}, nil
}

func renderBashFnAccessKey(f core.Finding) (remediate.Snippet, error) {
	ns := bashFnNS(f)
	body := fmt.Sprintf(`ns=%q
doctl serverless namespace add-key "$ns" --label "ci-key-$(date +%%Y%%m%%d)"`, ns)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		VerifyCmd: fmt.Sprintf("doctl serverless namespace list-keys %s", ns),
	}, nil
}

func renderBashFnKeyRotation(f core.Finding) (remediate.Snippet, error) {
	ns := bashFnNS(f)
	body := fmt.Sprintf(`ns=%q
# List keys + flag any that look stale (>90d via Label-encoded date if available).
doctl serverless namespace list-keys "$ns" --format Label,Created
# Manual review + revoke + reissue as needed.`, ns)
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
	}, nil
}

func renderBashFnRuntime(_ core.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"Functions runtime versions",
		"https://docs.digitalocean.com/products/functions/reference/runtimes/",
		"Update project.yml `runtime:` to a supported version, then `doctl serverless deploy`")
}

func renderBashFnEnvVars(_ core.Finding) (remediate.Snippet, error) {
	body := `# Re-deploy current source with encrypted env vars.
doctl serverless deploy --env-file .env --encrypted`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
	}, nil
}

func renderBashFnSecretScan(_ core.Finding) (remediate.Snippet, error) {
	body := `# Pre-deploy gate. Add to CI BEFORE doctl serverless deploy.
gitleaks detect --source . --no-banner --redact || {
  echo "secret scan failed; aborting deploy" >&2
  exit 1
}
doctl serverless deploy`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: "gitleaks detect --source . --no-banner --redact",
	}, nil
}

func renderBashFnLogExport(_ core.Finding) (remediate.Snippet, error) {
	body := `# Cron-style poll: ship invocation logs to Datadog.
while sleep 300; do
  doctl serverless activations list -o json --last 5m \
    | jq -c '.[]' \
    | curl -fsSL -X POST -H "DD-API-KEY: $DD_API_KEY" \
        -H "Content-Type: application/json" \
        --data-binary @- https://http-intake.logs.datadoghq.com/v1/input
done`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		Notes: "Run under systemd / supervisord. Replace Datadog endpoint for your sink.",
	}, nil
}

func renderBashFnColdStart(f core.Finding) (remediate.Snippet, error) {
	ns := bashFnNS(f)
	body := fmt.Sprintf(`doctl serverless trigger create %s \
  --type SCHEDULED --cron '*/5 * * * *' \
  --function my-package/my-function`, ns)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: false, Content: body,
	}, nil
}

func renderBashFnEnvTag(_ core.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"Functions namespace environment-naming convention",
		"https://docs.digitalocean.com/products/functions/",
		"Create new namespaces with explicit prefix (functions-prod, functions-staging)")
}

// v0.19 phase 9 — legacy backfill for v0.9-vintage Functions checks.
var legacyFunctionsBashEntries = map[string]legacyBashEntry{
	"do-functions-disabled-triggers": {risk: remediate.RiskManual, body: "doctl serverless trigger list NS --format Name,Enabled\n# Enable / delete as needed."},
	"do-functions-namespace-empty":   {risk: remediate.RiskReview, body: "doctl serverless namespaces delete NS_UUID --force"},
	"do-functions-no-access-keys":    {risk: remediate.RiskReview, body: "doctl serverless namespace add-key NS --label ci-key"},
}

func init() { registerLegacyBash(legacyFunctionsBashEntries) }
