package bash

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 5 — bash strategies for the 10 App-Platform depth
// checks. Same shape as doctl: pull spec, edit, push back.

func init() {
	register("bash-do-app-services-healthcheck",
		[]string{"do-app-services-no-healthcheck"}, renderBashAppHealthcheck)
	register("bash-do-app-services-log-dest",
		[]string{"do-app-services-no-log-destinations"}, renderBashAppLogDest)
	register("bash-do-app-services-alerts",
		[]string{"do-app-services-no-service-alerts"}, renderBashAppServiceAlerts)
	register("bash-do-app-tier-prod-grade",
		[]string{"do-app-tier-below-production"}, renderBashAppTier)
	register("bash-do-app-database-production",
		[]string{"do-app-database-not-production-marked"}, renderBashAppDatabase)
	register("bash-do-app-deploy-on-push-protection",
		[]string{"do-app-deploy-on-push-no-branch-protection"}, renderBashAppDeployProtection)
	register("bash-do-app-domain-tls-1-3",
		[]string{"do-app-domain-tls-below-1-3"}, renderBashAppDomainTLS13)
	register("bash-do-app-build-secret-scan",
		[]string{"do-app-build-secret-scan"}, renderBashAppBuildSecretScan)
	register("bash-do-app-domain-cert-rotation",
		[]string{"do-app-domain-cert-rotation"}, renderBashAppCertRotation)
	register("bash-do-app-cdn-attachment",
		[]string{"do-app-cdn-attachment"}, renderBashAppCDN)
}

func bashAppID(f core.Finding) string {
	if f.Resource.Name != "" {
		return f.Resource.Name
	}
	return "APP_ID"
}

func appSpecPatch(id, yqExpr string) string {
	return fmt.Sprintf(`app=%q
doctl apps spec get "$app" > spec.yaml
yq eval -i %q spec.yaml
doctl apps update "$app" --spec spec.yaml`, id, yqExpr)
}

func renderBashAppHealthcheck(f core.Finding) (remediate.Snippet, error) {
	id := bashAppID(f)
	body := appSpecPatch(id, `.services[] |= (.health_check = {"http_path":"/healthz","initial_delay_seconds":5,"period_seconds":10,"timeout_seconds":5,"failure_threshold":3})`)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`doctl apps spec get %s | yq '.services[].health_check'`, id),
		Notes:     "Requires yq v4+. Implement /healthz on each service before this lands.",
	}, nil
}

func renderBashAppLogDest(f core.Finding) (remediate.Snippet, error) {
	id := bashAppID(f)
	body := appSpecPatch(id, `.services[] |= (.log_destinations = [{"name":"prod-datadog","datadog":{"api_key":"${DATADOG_API_KEY}","endpoint":"https://http-intake.logs.datadoghq.com/v1/input"}}])`)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Substitute Datadog block for the sink of your choice (papertrail / opensearch / logtail).",
	}, nil
}

func renderBashAppServiceAlerts(f core.Finding) (remediate.Snippet, error) {
	id := bashAppID(f)
	body := appSpecPatch(id, `.services[] |= (.alerts = [{"rule":"CPU_UTILIZATION","operator":"GREATER_THAN","value":80,"window":"FIVE_MINUTES"},{"rule":"DEPLOYMENT_FAILED","operator":"GREATER_THAN","value":0,"window":"FIVE_MINUTES"}])`)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
	}, nil
}

func renderBashAppTier(f core.Finding) (remediate.Snippet, error) {
	id := bashAppID(f)
	body := appSpecPatch(id, `.services[] |= (.instance_size_slug = "professional-xs" | .instance_count = 2)`)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Bumps every service. Per-service tier requires service-name filter.",
	}, nil
}

func renderBashAppDatabase(f core.Finding) (remediate.Snippet, error) {
	id := bashAppID(f)
	body := appSpecPatch(id, `.databases[] |= (.production = true)`)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Does NOT migrate data; pair with manual pg_dump/pg_restore to the managed cluster.",
	}, nil
}

func renderBashAppDeployProtection(_ core.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"deploy-branch protection",
		"https://github.com/settings",
		"GitHub Settings → Branches → require reviews + status checks on the deploy branch")
}

func renderBashAppDomainTLS13(f core.Finding) (remediate.Snippet, error) {
	id := bashAppID(f)
	body := appSpecPatch(id, `.domains[] |= (.minimum_tls_version = "1.3")`)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
	}, nil
}

func renderBashAppBuildSecretScan(_ core.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"build-time secret scan",
		"https://github.com/gitleaks/gitleaks",
		"Add gitleaks/trufflehog gate in source-repo CI BEFORE the DO build webhook fires")
}

func renderBashAppCertRotation(_ core.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"custom-domain cert provenance",
		"https://cloud.digitalocean.com/apps",
		"Drop cert_id from the domain block to use auto-renewing Let's Encrypt")
}

func renderBashAppCDN(_ core.Finding) (remediate.Snippet, error) {
	body := `# 1. Create the bucket.
aws s3api create-bucket --bucket app-static-assets --endpoint-url https://nyc3.digitaloceanspaces.com

# 2. Make it public (CDN-fronted).
aws s3api put-bucket-acl --bucket app-static-assets --acl public-read --endpoint-url https://nyc3.digitaloceanspaces.com

# 3. Enable Spaces CDN.
doctl compute cdn create --origin app-static-assets.nyc3.digitaloceanspaces.com --ttl 3600

# 4. Push static assets:
aws s3 sync ./static/ s3://app-static-assets/ --endpoint-url https://nyc3.digitaloceanspaces.com

# 5. Update app to reference CDN URLs.`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
	}, nil
}

// v0.19 phase 9 — legacy backfill for v0.9-vintage App Platform checks.
var legacyAppBashEntries = map[string]legacyBashEntry{
	"do-app-domain-weak-tls":  {risk: remediate.RiskReview, body: "app=APP_ID\ndoctl apps spec get \"$app\" > spec.yaml\nyq eval -i '.domains[] |= (.minimum_tls_version = \"1.2\")' spec.yaml\ndoctl apps update \"$app\" --spec spec.yaml"},
	"do-app-no-alerts":        {risk: remediate.RiskReview, body: "app=APP_ID\ndoctl apps spec get \"$app\" > spec.yaml\nyq eval -i '.alerts = [{\"rule\":\"DEPLOYMENT_FAILED\"},{\"rule\":\"DOMAIN_FAILED\"}]' spec.yaml\ndoctl apps update \"$app\" --spec spec.yaml"},
	"do-app-no-custom-domain": {risk: remediate.RiskReview, body: "app=APP_ID\ndoctl apps spec get \"$app\" > spec.yaml\nyq eval -i '.domains += [{\"name\":\"app.example.com\",\"type\":\"PRIMARY\"}]' spec.yaml\ndoctl apps update \"$app\" --spec spec.yaml"},
	"do-app-no-vpc":           {risk: remediate.RiskReview, body: "echo 'Apps cannot move VPC in-place; recreate with doctl apps create --spec spec.yaml (vpc set)' >&2"},
	"do-app-plain-env-vars":   {risk: remediate.RiskReview, body: "app=APP_ID\ndoctl apps spec get \"$app\" > spec.yaml\n# Flip type: SECRET on each sensitive env then:\ndoctl apps update \"$app\" --spec spec.yaml"},
}

func init() { registerLegacyBash(legacyAppBashEntries) }
