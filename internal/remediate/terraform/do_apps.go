package terraform

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.19 phase 5 — Terraform strategies for the 10 App-Platform depth
// checks. App Platform in TF is `digitalocean_app` with a `spec`
// block; most remediation amounts to adding sub-blocks to that spec.

func init() {
	register("tf-do-app-services-healthcheck",
		[]string{"do-app-services-no-healthcheck"}, renderTFAppHealthcheck)
	register("tf-do-app-services-log-dest",
		[]string{"do-app-services-no-log-destinations"}, renderTFAppLogDest)
	register("tf-do-app-services-alerts",
		[]string{"do-app-services-no-service-alerts"}, renderTFAppServiceAlerts)
	register("tf-do-app-tier-prod-grade",
		[]string{"do-app-tier-below-production"}, renderTFAppTier)
	register("tf-do-app-database-production",
		[]string{"do-app-database-not-production-marked"}, renderTFAppDatabase)
	register("tf-do-app-deploy-on-push-protection",
		[]string{"do-app-deploy-on-push-no-branch-protection"}, renderTFAppDeployProtection)
	register("tf-do-app-domain-tls-1-3",
		[]string{"do-app-domain-tls-below-1-3"}, renderTFAppDomainTLS13)
	register("tf-do-app-build-secret-scan",
		[]string{"do-app-build-secret-scan"}, renderTFAppBuildSecretScan)
	register("tf-do-app-domain-cert-rotation",
		[]string{"do-app-domain-cert-rotation"}, renderTFAppCertRotation)
	register("tf-do-app-cdn-attachment",
		[]string{"do-app-cdn-attachment"}, renderTFAppCDN)
}

func tfAppName(f compliancekit.Finding) string {
	return tfNameOrFallback(f, "APP")
}

func renderTFAppHealthcheck(f compliancekit.Finding) (remediate.Snippet, error) {
	name := tfAppName(f)
	body := fmt.Sprintf(`# Add a HealthCheck block to every service in the app spec.

resource "digitalocean_app" %q {
  spec {
    name = %q
    service {
      name = "web"
      # ... existing fields ...
      health_check {
        http_path             = "/healthz"
        initial_delay_seconds = 5
        period_seconds        = 10
        timeout_seconds       = 5
        failure_threshold     = 3
      }
    }
  }
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Implement /healthz on each service to verify critical dependencies (db connection, downstream API).",
	}, nil
}

func renderTFAppLogDest(f compliancekit.Finding) (remediate.Snippet, error) {
	name := tfAppName(f)
	body := fmt.Sprintf(`resource "digitalocean_app" %q {
  spec {
    name = %q
    service {
      name = "web"
      log_destination {
        name = "prod-datadog"
        datadog {
          api_key  = var.DATADOG_API_KEY
          endpoint = "https://http-intake.logs.datadoghq.com/v1/input"
        }
      }
    }
  }
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Swap Datadog block for Papertrail/Logtail/OpenSearch as needed. Set DATADOG_API_KEY via TF_VAR_DATADOG_API_KEY.",
	}, nil
}

func renderTFAppServiceAlerts(f compliancekit.Finding) (remediate.Snippet, error) {
	name := tfAppName(f)
	body := fmt.Sprintf(`resource "digitalocean_app" %q {
  spec {
    name = %q
    service {
      name = "web"
      alert {
        rule     = "CPU_UTILIZATION"
        value    = 80
        operator = "GREATER_THAN"
        window   = "FIVE_MINUTES"
      }
      alert {
        rule     = "DEPLOYMENT_FAILED"
        value    = 0
        operator = "GREATER_THAN"
        window   = "FIVE_MINUTES"
      }
    }
  }
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
	}, nil
}

func renderTFAppTier(f compliancekit.Finding) (remediate.Snippet, error) {
	name := tfAppName(f)
	body := fmt.Sprintf(`resource "digitalocean_app" %q {
  spec {
    name = %q
    service {
      name               = "web"
      instance_size_slug = "professional-xs"   # bump from basic-* for prod
      instance_count     = 2                    # ≥2 for HA
    }
  }
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Professional tier ~5x basic cost but adds dedicated CPU + autoscaling headroom.",
	}, nil
}

func renderTFAppDatabase(f compliancekit.Finding) (remediate.Snippet, error) {
	name := tfAppName(f)
	body := fmt.Sprintf(`resource "digitalocean_app" %q {
  spec {
    name = %q
    database {
      name         = "app-db"
      engine       = "PG"
      production   = true
      cluster_name = digitalocean_database_cluster.app_db.name
    }
  }
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Cut over from dev DB to managed cluster requires manual dump+restore — dev DBs aren't backed up.",
	}, nil
}

func renderTFAppDeployProtection(_ compliancekit.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"branch-protection state lives on GitHub / GitLab, not the DO App spec",
		"https://github.com/settings",
		"On the source repo: require ≥1 review + status checks on the deploy branch")
}

func renderTFAppDomainTLS13(f compliancekit.Finding) (remediate.Snippet, error) {
	name := tfAppName(f)
	body := fmt.Sprintf(`resource "digitalocean_app" %q {
  spec {
    name = %q
    domain {
      name                = "app.example.com"
      type                = "PRIMARY"
      minimum_tls_version = "1.3"
    }
  }
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
	}, nil
}

func renderTFAppBuildSecretScan(_ compliancekit.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"secret scanning is a source-repo CI control; not surfaced by the DO App spec",
		"https://github.com/gitleaks/gitleaks",
		"Add a gitleaks/trufflehog gate in the source-repo CI BEFORE the DO deploy webhook fires")
}

func renderTFAppCertRotation(_ compliancekit.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"DO App spec doesn't expose cert provenance at runtime",
		"https://cloud.digitalocean.com/apps",
		"Declare custom domains WITHOUT cert_id to use auto-renewing Let's Encrypt")
}

func renderTFAppCDN(_ compliancekit.Finding) (remediate.Snippet, error) {
	body := `# Static assets via a Spaces bucket with CDN enabled.

resource "digitalocean_spaces_bucket" "static_assets" {
  name   = "app-static-assets"
  region = "nyc3"
  acl    = "public-read"
}

resource "digitalocean_cdn" "static_assets" {
  origin = digitalocean_spaces_bucket.static_assets.bucket_domain_name
  ttl    = 3600
}
`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Public-read on the bucket is required for CDN serving; pair with do-spaces-bucket-policy-required to lock down everything except GetObject.",
		Refs:  []string{"https://docs.digitalocean.com/products/spaces/how-to/enable-cdn/"},
	}, nil
}

// v0.19 phase 9 — legacy backfill for v0.9-vintage App Platform checks.
var legacyAppTFEntries = map[string]legacyTFEntry{
	"do-app-domain-weak-tls": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_app\" \"main\" {\n  spec {\n    domain {\n      name                = \"app.example.com\"\n      minimum_tls_version = \"1.2\"\n    }\n  }\n}\n"},
	"do-app-no-alerts": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_app\" \"main\" {\n  spec {\n    alert { rule = \"DEPLOYMENT_FAILED\" }\n    alert { rule = \"DOMAIN_FAILED\" }\n  }\n}\n"},
	"do-app-no-custom-domain": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_app\" \"main\" {\n  spec {\n    domain { name = \"app.example.com\"; type = \"PRIMARY\" }\n  }\n}\n"},
	"do-app-plain-env-vars": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_app\" \"main\" {\n  spec {\n    env {\n      key   = \"API_KEY\"\n      value = var.api_key\n      type  = \"SECRET\"\n    }\n  }\n}\n"},
}

func init() { registerLegacyTF(legacyAppTFEntries) }
