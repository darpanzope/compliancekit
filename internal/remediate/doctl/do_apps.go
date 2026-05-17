package doctl

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 5 — doctl strategies for App Platform depth. App
// remediation = edit the spec YAML + `doctl apps update <id> --spec
// spec.yaml`. Strategies render the YAML fragment to merge.

func init() {
	register("doctl-do-app-services-healthcheck",
		[]string{"do-app-services-no-healthcheck"}, renderDoctlAppHealthcheck)
	register("doctl-do-app-services-log-dest",
		[]string{"do-app-services-no-log-destinations"}, renderDoctlAppLogDest)
	register("doctl-do-app-services-alerts",
		[]string{"do-app-services-no-service-alerts"}, renderDoctlAppServiceAlerts)
	register("doctl-do-app-tier-prod-grade",
		[]string{"do-app-tier-below-production"}, renderDoctlAppTier)
	register("doctl-do-app-database-production",
		[]string{"do-app-database-not-production-marked"}, renderDoctlAppDatabase)
	register("doctl-do-app-deploy-on-push-protection",
		[]string{"do-app-deploy-on-push-no-branch-protection"}, renderDoctlAppDeployProtection)
	register("doctl-do-app-domain-tls-1-3",
		[]string{"do-app-domain-tls-below-1-3"}, renderDoctlAppDomainTLS13)
	register("doctl-do-app-build-secret-scan",
		[]string{"do-app-build-secret-scan"}, renderDoctlAppBuildSecretScan)
	register("doctl-do-app-domain-cert-rotation",
		[]string{"do-app-domain-cert-rotation"}, renderDoctlAppCertRotation)
	register("doctl-do-app-cdn-attachment",
		[]string{"do-app-cdn-attachment"}, renderDoctlAppCDN)
}

func doctlAppName(f core.Finding) string {
	if f.Resource.Name != "" {
		return f.Resource.Name
	}
	return "APP_ID"
}

func appUpdateWrapper(id, fragment string) string {
	return fmt.Sprintf(`# 1. Pull the current spec.
doctl apps spec get %s > spec.yaml

# 2. Merge the fragment (manual yaml edit OR via yq).
# Fragment:

%s
# 3. Apply.
doctl apps update %s --spec spec.yaml`, id, fragment, id)
}

func renderDoctlAppHealthcheck(f core.Finding) (remediate.Snippet, error) {
	id := doctlAppName(f)
	fragment := `# Add under each service:
services:
  - name: web
    health_check:
      http_path: /healthz
      initial_delay_seconds: 5
      period_seconds: 10
      timeout_seconds: 5
      failure_threshold: 3`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: appUpdateWrapper(id, fragment),
		VerifyCmd: fmt.Sprintf(`doctl apps spec get %s | yq '.services[].health_check'`, id),
	}, nil
}

func renderDoctlAppLogDest(f core.Finding) (remediate.Snippet, error) {
	id := doctlAppName(f)
	fragment := `services:
  - name: web
    log_destinations:
      - name: prod-datadog
        datadog:
          api_key: ${DATADOG_API_KEY}
          endpoint: https://http-intake.logs.datadoghq.com/v1/input`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: appUpdateWrapper(id, fragment),
	}, nil
}

func renderDoctlAppServiceAlerts(f core.Finding) (remediate.Snippet, error) {
	id := doctlAppName(f)
	fragment := `services:
  - name: web
    alerts:
      - rule: CPU_UTILIZATION
        operator: GREATER_THAN
        value: 80
        window: FIVE_MINUTES
      - rule: DEPLOYMENT_FAILED
        operator: GREATER_THAN
        value: 0
        window: FIVE_MINUTES`
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: false, Content: appUpdateWrapper(id, fragment),
	}, nil
}

func renderDoctlAppTier(f core.Finding) (remediate.Snippet, error) {
	id := doctlAppName(f)
	fragment := `services:
  - name: web
    instance_size_slug: professional-xs
    instance_count: 2`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: appUpdateWrapper(id, fragment),
	}, nil
}

func renderDoctlAppDatabase(f core.Finding) (remediate.Snippet, error) {
	id := doctlAppName(f)
	fragment := `databases:
  - name: app-db
    engine: PG
    production: true
    cluster_name: <managed-db-cluster-name>`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: appUpdateWrapper(id, fragment),
		Notes: "Cutover from dev to managed cluster requires manual dump + restore (dev DBs aren't backed up).",
	}, nil
}

func renderDoctlAppDeployProtection(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"deploy-branch protection",
		"https://github.com/settings",
		"GitHub Settings → Branches → require reviews + status checks on the deploy branch")
}

func renderDoctlAppDomainTLS13(f core.Finding) (remediate.Snippet, error) {
	id := doctlAppName(f)
	fragment := `domains:
  - domain: app.example.com
    type: PRIMARY
    minimum_tls_version: "1.3"`
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: false, Content: appUpdateWrapper(id, fragment),
	}, nil
}

func renderDoctlAppBuildSecretScan(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"build-time secret scan",
		"https://github.com/gitleaks/gitleaks",
		"Add gitleaks/trufflehog gate in source-repo CI BEFORE the DO build webhook fires")
}

func renderDoctlAppCertRotation(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"custom-domain cert provenance",
		"https://cloud.digitalocean.com/apps",
		"Drop cert_id from the domain block to use auto-renewing Let's Encrypt")
}

func renderDoctlAppCDN(_ core.Finding) (remediate.Snippet, error) {
	body := `# 1. Create the static-assets bucket.
aws s3api create-bucket --bucket app-static-assets --endpoint-url https://nyc3.digitaloceanspaces.com

# 2. Enable the Spaces CDN attachment.
doctl compute cdn create --origin app-static-assets.nyc3.digitaloceanspaces.com --ttl 3600`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		Notes: "Update app static asset URLs to point at the CDN endpoint.",
	}, nil
}

// v0.19 phase 9 — legacy backfill for v0.9-vintage App Platform checks.
var legacyAppDoctlEntries = map[string]legacyDoctlEntry{
	"do-app-domain-weak-tls": {risk: remediate.RiskReview,
		content: "doctl apps spec get APP_ID > spec.yaml\n# edit minimum_tls_version, then\ndoctl apps update APP_ID --spec spec.yaml"},
	"do-app-no-custom-domain": {risk: remediate.RiskReview,
		content: "doctl apps spec get APP_ID > spec.yaml\n# add domains entry, then\ndoctl apps update APP_ID --spec spec.yaml"},
	"do-app-no-vpc": {risk: remediate.RiskReview,
		content: "# Apps must be recreated to move into a VPC.\ndoctl apps create --spec spec.yaml  # with vpc set"},
	"do-app-plain-env-vars": {risk: remediate.RiskReview,
		content: "doctl apps spec get APP_ID > spec.yaml\n# flip type: SECRET on sensitive envs\ndoctl apps update APP_ID --spec spec.yaml"},
}

func init() { registerLegacyDoctl(legacyAppDoctlEntries) }
