package digitalocean

import (
	"context"
	"fmt"
	"time"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

const spacesKeyMaxAgeDays = 365

// --- Spaces bucket checks ---

var CheckSpacesNotPublic = core.Check{
	ID:           "do-spaces-bucket-public-acl",
	Title:        "Spaces buckets must not grant public ACLs",
	Severity:     core.SeverityCritical,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesBucketType,
	Description: "A bucket ACL that grants AllUsers or " +
		"AuthenticatedUsers exposes every object to the public Internet. " +
		"Spaces buckets default to private but a copied-from-AWS ACL " +
		"snippet or a CDN-setup misstep can flip them open. The single " +
		"highest-impact misconfiguration on object storage.",
	Remediation: "Remove the public ACL: 's3cmd setacl s3://<bucket> " +
		"--acl-private' (s3cmd-compatible) or use the DO control panel " +
		"Settings > Permissions. Audit every object that was public " +
		"during the exposure window.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.3", "A.5.10"},
		"cis-v8":   {"3.3", "3.11"},
	},
	Tags:    []string{"spaces", "data-exposure", "public-access"},
	Scanner: "spaces.NotPublic",
}

func SpacesNotPublic(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(docol.SpacesBucketType) {
		pub, _ := b.Attributes["acl_has_public_grant"].(bool)
		f := core.Finding{
			CheckID:  CheckSpacesNotPublic.ID,
			Severity: CheckSpacesNotPublic.Severity,
			Resource: b.Ref(),
			Tags:     CheckSpacesNotPublic.Tags,
		}
		if pub {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: public ACL grant present", b.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: no public ACL", b.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckSpacesVersioning = core.Check{
	ID:           "do-spaces-bucket-no-versioning",
	Title:        "Spaces buckets should have versioning enabled",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesBucketType,
	Description: "Object versioning preserves previous versions on " +
		"overwrite or delete -- the only recovery path for accidental " +
		"deletes or ransomware-style encrypt-in-place attacks against " +
		"Spaces. Pair with a lifecycle policy that expires old non- " +
		"current versions to bound storage cost.",
	Remediation: "Enable via s3-compatible API: 's3cmd " +
		"--access_key=$SPACES_KEY --secret_key=$SPACES_SECRET " +
		"--host=<region>.digitaloceanspaces.com setversioning " +
		"s3://<bucket> Enabled' (or the equivalent aws-cli " +
		"put-bucket-versioning).",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2", "CC7.4"},
		"iso27001": {"A.8.13", "A.8.14"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"spaces", "backup", "recovery"},
	Scanner: "spaces.Versioning",
}

func SpacesVersioning(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(docol.SpacesBucketType) {
		on, _ := b.Attributes["versioning_enabled"].(bool)
		f := core.Finding{
			CheckID:  CheckSpacesVersioning.ID,
			Severity: CheckSpacesVersioning.Severity,
			Resource: b.Ref(),
			Tags:     CheckSpacesVersioning.Tags,
		}
		if on {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: versioning enabled", b.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: versioning disabled", b.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckSpacesEncryption = core.Check{
	ID:           "do-spaces-bucket-no-encryption",
	Title:        "Spaces buckets should have default encryption configured",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesBucketType,
	Description: "DO Spaces encrypts every object at rest using AES-256 " +
		"with platform-managed keys regardless of bucket configuration, " +
		"but the per-bucket default-encryption setting forces clients " +
		"to acknowledge encryption on every PUT. A bucket without the " +
		"default-encryption header set will accept unencrypted PUT " +
		"requests that downgrade to platform-default, which is " +
		"compliance-detectable.",
	Remediation: "Apply default encryption via s3-compatible API: " +
		"'aws s3api put-bucket-encryption --bucket <name> " +
		"--server-side-encryption-configuration ...' against the " +
		"Spaces endpoint.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.11"},
	},
	Tags:    []string{"spaces", "encryption-at-rest"},
	Scanner: "spaces.Encryption",
}

func SpacesEncryption(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(docol.SpacesBucketType) {
		on, _ := b.Attributes["encryption_configured"].(bool)
		f := core.Finding{
			CheckID:  CheckSpacesEncryption.ID,
			Severity: CheckSpacesEncryption.Severity,
			Resource: b.Ref(),
			Tags:     CheckSpacesEncryption.Tags,
		}
		if on {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: default encryption configured", b.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: no default encryption header", b.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckSpacesLifecycle = core.Check{
	ID:           "do-spaces-bucket-no-lifecycle",
	Title:        "Spaces buckets should have lifecycle rules configured",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesBucketType,
	Description: "Without lifecycle rules, every object lives forever -- " +
		"including incomplete multipart uploads, old non-current " +
		"versions, and superseded build artifacts. Most production " +
		"buckets benefit from a lifecycle policy that expires " +
		"transient data and tier-shifts cold objects.",
	Remediation: "Define a lifecycle XML and apply via s3-compatible API. " +
		"Minimum baseline: expire incomplete multipart uploads after " +
		"1 day, expire non-current versions after 90 days. Tune to " +
		"the workload.",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"3.5"},
	},
	Tags:    []string{"spaces", "hygiene", "cost"},
	Scanner: "spaces.Lifecycle",
}

func SpacesLifecycle(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(docol.SpacesBucketType) {
		on, _ := b.Attributes["lifecycle_configured"].(bool)
		f := core.Finding{
			CheckID:  CheckSpacesLifecycle.ID,
			Severity: CheckSpacesLifecycle.Severity,
			Resource: b.Ref(),
			Tags:     CheckSpacesLifecycle.Tags,
		}
		if on {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: lifecycle configured", b.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: no lifecycle rules", b.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckSpacesCORSWildcard = core.Check{
	ID:           "do-spaces-bucket-cors-wildcard",
	Title:        "Spaces buckets must not use wildcard CORS origins",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesBucketType,
	Description: "A CORS rule with AllowedOrigin '*' lets any browser " +
		"page on the public Internet fetch + (if PUT/DELETE methods " +
		"are also allowed) modify objects via XHR. Common shape of " +
		"accidental public-bucket exposure even when the underlying " +
		"ACL is correct.",
	Remediation: "List your application origins explicitly: " +
		"'https://app.example.com', 'https://staging.example.com'. " +
		"Apply via 'aws s3api put-bucket-cors' against the Spaces " +
		"endpoint. If the workload truly needs '*', restrict methods " +
		"to GET only.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"3.3"},
	},
	Tags:    []string{"spaces", "cors", "exposure"},
	Scanner: "spaces.CORSWildcard",
}

func SpacesCORSWildcard(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(docol.SpacesBucketType) {
		wildcard, _ := b.Attributes["cors_wildcard_origin"].(bool)
		f := core.Finding{
			CheckID:  CheckSpacesCORSWildcard.ID,
			Severity: CheckSpacesCORSWildcard.Severity,
			Resource: b.Ref(),
			Tags:     CheckSpacesCORSWildcard.Tags,
		}
		if wildcard {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: CORS allows '*' origin", b.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: no wildcard CORS", b.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckSpacesLogging = core.Check{
	ID:           "do-spaces-bucket-no-logging",
	Title:        "Spaces buckets should have access logging configured",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesBucketType,
	Description: "Spaces server-access logs are the forensic trail when a " +
		"bucket is the source of a security incident. Without them, " +
		"'who accessed this object at this timestamp' is unanswerable. " +
		"Apply to data-plane buckets; control-plane logs cover the " +
		"DO API surface separately.",
	Remediation: "Enable logging into a dedicated log-aggregation bucket " +
		"via the s3 PUT bucket logging API. The destination bucket " +
		"must be different from the source bucket (loop prevention).",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.15"},
		"cis-v8":   {"8.5", "8.10"},
	},
	Tags:    []string{"spaces", "audit-logging"},
	Scanner: "spaces.Logging",
}

func SpacesLogging(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(docol.SpacesBucketType) {
		on, _ := b.Attributes["logging_enabled"].(bool)
		f := core.Finding{
			CheckID:  CheckSpacesLogging.ID,
			Severity: CheckSpacesLogging.Severity,
			Resource: b.Ref(),
			Tags:     CheckSpacesLogging.Tags,
		}
		if on {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: access logging enabled", b.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: access logging disabled", b.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// --- Spaces key checks ---

var CheckSpacesKeyNotFullAccess = core.Check{
	ID:           "do-spaces-key-fullaccess",
	Title:        "Spaces keys should be scoped, not fullaccess",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesKeyType,
	Description: "DO Spaces keys can be scoped to specific buckets + " +
		"permissions (read / readwrite / fullaccess). A fullaccess key " +
		"or a key with zero grants (which legacy keys default to) can " +
		"reach every bucket in the account. Lost or leaked, the " +
		"blast radius is everything.",
	Remediation: "Rotate to a scoped key: 'doctl spaces keys create " +
		"<name> --grants bucket=<bucket>,permission=readwrite'. Update " +
		"the application credential. Revoke the old fullaccess key.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"3.3", "6.7"},
	},
	Tags:    []string{"spaces", "key-scope", "least-privilege"},
	Scanner: "spaces.KeyNotFullAccess",
}

func SpacesKeyNotFullAccess(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, k := range g.ByType(docol.SpacesKeyType) {
		full, _ := k.Attributes["is_full_access"].(bool)
		f := core.Finding{
			CheckID:  CheckSpacesKeyNotFullAccess.ID,
			Severity: CheckSpacesKeyNotFullAccess.Severity,
			Resource: k.Ref(),
			Tags:     CheckSpacesKeyNotFullAccess.Tags,
		}
		if full {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("spaces key %q: full-access or unscoped", k.Name)
		} else {
			grants, _ := k.Attributes["grant_count"].(int)
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("spaces key %q: scoped (%d grant(s))", k.Name, grants)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckSpacesKeyAge = core.Check{
	ID:           "do-spaces-key-too-old",
	Title:        "Spaces keys should be rotated at least once a year",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesKeyType,
	Description: "Long-lived credentials accumulate exposure risk: more " +
		"log entries containing the key, more code paths that have " +
		"loaded it, more former employees who once had it. Rotate " +
		"Spaces keys at least annually. SOC 2 CC6.1 + ISO 27001 A.5.16 " +
		"both prescribe periodic credential rotation.",
	Remediation: "Create a new key with the same grants: 'doctl spaces " +
		"keys create <new-name> --grants ...'. Update the application " +
		"credential. Delete the old key once traffic has migrated.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.5.16", "A.5.17"},
		"cis-v8":   {"5.3", "6.1"},
	},
	Tags:    []string{"spaces", "credential-rotation"},
	Scanner: "spaces.KeyAge",
}

func SpacesKeyAge(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	now := time.Now().UTC()
	threshold := now.Add(-spacesKeyMaxAgeDays * 24 * time.Hour)
	for _, k := range g.ByType(docol.SpacesKeyType) {
		created, _ := k.Attributes["created_at"].(string)
		f := core.Finding{
			CheckID:  CheckSpacesKeyAge.ID,
			Severity: CheckSpacesKeyAge.Severity,
			Resource: k.Ref(),
			Tags:     CheckSpacesKeyAge.Tags,
		}
		t, err := time.Parse(time.RFC3339, created)
		switch {
		case err != nil:
			f.Status = core.StatusSkip
			f.Message = fmt.Sprintf("spaces key %q: unparsable created_at=%q", k.Name, created)
		case t.Before(threshold):
			days := int(now.Sub(t).Hours() / 24)
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("spaces key %q: %d days old (> %d)", k.Name, days, spacesKeyMaxAgeDays)
		default:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("spaces key %q: created %s", k.Name, created)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckSpacesNotPublic, SpacesNotPublic)
	core.Register(CheckSpacesVersioning, SpacesVersioning)
	core.Register(CheckSpacesEncryption, SpacesEncryption)
	core.Register(CheckSpacesLifecycle, SpacesLifecycle)
	core.Register(CheckSpacesCORSWildcard, SpacesCORSWildcard)
	core.Register(CheckSpacesLogging, SpacesLogging)
	core.Register(CheckSpacesKeyNotFullAccess, SpacesKeyNotFullAccess)
	core.Register(CheckSpacesKeyAge, SpacesKeyAge)
}
