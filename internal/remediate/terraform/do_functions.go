package terraform

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 6 — Terraform strategies for the 10 Functions-depth
// checks. DO Functions have NO terraform-provider resource (no
// digitalocean_functions_namespace today); every strategy here either
// renders a doctl-via-local-exec stub or points the operator at the
// manual control surface.

func init() {
	register("tf-do-functions-namespace-region",
		[]string{"do-functions-namespace-no-region"}, renderTFFnNamespaceRegion)
	register("tf-do-functions-disabled-trigger-ratio",
		[]string{"do-functions-disabled-trigger-ratio"}, renderTFFnTriggerRatio)
	register("tf-do-functions-namespace-access-key",
		[]string{"do-functions-namespace-no-access-key"}, renderTFFnAccessKey)
	register("tf-do-functions-access-key-rotation",
		[]string{"do-functions-access-key-rotation"}, renderTFFnKeyRotation)
	register("tf-do-functions-runtime-eol",
		[]string{"do-functions-runtime-eol"}, renderTFFnRuntime)
	register("tf-do-functions-env-vars-plain",
		[]string{"do-functions-env-vars-plain"}, renderTFFnEnvVars)
	register("tf-do-functions-source-secret-scan",
		[]string{"do-functions-source-secret-scan"}, renderTFFnSecretScan)
	register("tf-do-functions-log-export",
		[]string{"do-functions-log-export"}, renderTFFnLogExport)
	register("tf-do-functions-cold-start-mitigation",
		[]string{"do-functions-cold-start-mitigation"}, renderTFFnColdStart)
	register("tf-do-functions-environment-tag",
		[]string{"do-functions-namespace-no-environment-tag"}, renderTFFnEnvTag)
}

// fnLocalExecStub wraps a doctl serverless command in a TF local-exec
// stub so operators driving infrastructure-as-code can at least script
// the gap until the DO provider lands a native resource.
func fnLocalExecStub(name, cmd string) string {
	return fmt.Sprintf(`# No digitalocean_functions_namespace resource exists in the DO
# terraform provider yet. Wire the doctl command via a null_resource
# + local-exec until the provider catches up (track:
# https://github.com/digitalocean/terraform-provider-digitalocean/issues).

resource "null_resource" %q {
  provisioner "local-exec" {
    command = <<-EOT
      %s
    EOT
  }
}
`, name, cmd)
}

func renderTFFnNamespaceRegion(f core.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "NAMESPACE_LABEL")
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false,
		Content: fnLocalExecStub("functions_namespace_"+tfIdent(name),
			fmt.Sprintf("doctl serverless namespaces create --label %q --region nyc1", name)),
		Notes: "Functions namespaces are not idempotent via local-exec; gate the resource behind a count flag if you've already created the namespace.",
	}, nil
}

func renderTFFnTriggerRatio(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"Functions triggers are not surfaced by the DO TF provider",
		"https://cloud.digitalocean.com/functions",
		"List + audit: `doctl serverless trigger list <ns>` and delete or re-enable")
}

func renderTFFnAccessKey(f core.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "NAMESPACE")
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false,
		Content: fnLocalExecStub("functions_access_key_"+tfIdent(name),
			fmt.Sprintf("doctl serverless namespace add-key %s --label ci-key", name)),
		Notes: "Capture the returned key value securely; rotate every ≤90d (see do-functions-access-key-rotation).",
	}, nil
}

func renderTFFnKeyRotation(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"Functions access-key rotation has no TF surface (rotation is operational)",
		"https://cloud.digitalocean.com/functions",
		"Quarterly: list keys, revoke >90d, reissue, rotate consumers, record in runbook")
}

func renderTFFnRuntime(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"Functions runtime versions live in project.yml, not the TF provider",
		"https://docs.digitalocean.com/products/functions/reference/runtimes/",
		"Update project.yml `runtime:` and re-deploy via `doctl serverless deploy`")
}

func renderTFFnEnvVars(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"Functions env-var encryption is a doctl deploy flag, not a TF resource",
		"https://docs.digitalocean.com/reference/doctl/reference/serverless/deploy/",
		"Re-deploy with `--env-file .env --encrypted`")
}

func renderTFFnSecretScan(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"Source-side secret scanning is a CI gate, not a TF resource",
		"https://github.com/gitleaks/gitleaks",
		"Add gitleaks/trufflehog gate in CI BEFORE `doctl serverless deploy`")
}

func renderTFFnLogExport(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"DO Functions log forwarding has no native config",
		"https://docs.digitalocean.com/products/functions/",
		"Ship logs from inside the function (HTTP to sink) OR pull via doctl + cron")
}

func renderTFFnColdStart(f core.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "NAMESPACE")
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: false,
		Content: fnLocalExecStub("functions_keepalive_"+tfIdent(name),
			"doctl serverless trigger create --type SCHEDULED --cron '*/5 * * * *' my-function"),
		Notes: "5-minute cadence balances warm pool against invocation cost. Adjust per workload.",
	}, nil
}

func renderTFFnEnvTag(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"Functions namespaces have no tag field; convention lives in the label",
		"https://docs.digitalocean.com/products/functions/",
		"Recreate namespaces with explicit prefix (functions-prod / functions-staging)")
}

// v0.19 phase 9 — legacy backfill for v0.9-vintage Functions checks.
var legacyFunctionsTFEntries = map[string]legacyTFEntry{
	"do-functions-disabled-triggers": {risk: remediate.RiskManual,
		content: "# Functions triggers are not surfaced by the TF provider.\n# Use doctl: `doctl serverless trigger enable <ns> <name>` or delete."},
	"do-functions-namespace-empty": {risk: remediate.RiskReview,
		content: "# Delete via doctl: `doctl serverless namespaces delete NS_UUID --force`"},
	"do-functions-no-access-keys": {risk: remediate.RiskReview,
		content: "# Add via doctl: `doctl serverless namespace add-key NS --label ci-key`"},
}

func init() { registerLegacyTF(legacyFunctionsTFEntries) }
