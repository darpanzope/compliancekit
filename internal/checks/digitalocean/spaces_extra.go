package digitalocean

import (
	"context"
	"fmt"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.19 phase 2 — Spaces depth: lifecycle rule completeness, logging
// target separation, bucket policy presence, plus manual-verify
// findings for the S3 features DO Spaces does not implement
// (object-lock, cross-region replication, MFA-delete, transfer
// acceleration).
//
// REAL-DATA (6) read attributes the v0.19 phase 2 collector extension
// surfaces on every Spaces bucket: lifecycle_rule_count,
// lifecycle_has_expiration, lifecycle_has_mpu_abort,
// logging_target_bucket, policy_configured.
//
// MANUAL-VERIFY (4) cover features the DO Spaces S3 surface returns
// 501 / NotImplemented for. The checks emit StatusError with the DO
// docs link so the auditor can record an off-platform compensating
// control (or note the deliberate acceptance of the limitation).

const spacesDocsURL = "https://docs.digitalocean.com/products/spaces/"

// ----- shared helpers ---------------------------------------------------

func newSpacesFinding(check core.Check, bucket core.Resource) core.Finding {
	return core.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Resource: bucket.Ref(),
		Tags:     check.Tags,
	}
}

func spacesManualVerify(check core.Check, bucket core.Resource, gap, docsURL string) core.Finding {
	f := newSpacesFinding(check, bucket)
	f.Status = core.StatusError
	f.Message = fmt.Sprintf("bucket %q: %s — DigitalOcean Spaces does not implement this S3 feature; verify compensating control then waive per ADR-013 (docs: %s)",
		bucket.Name, gap, docsURL)
	return f
}

// ----- 1. lifecycle rules cover expiration ------------------------------

var CheckSpacesLifecycleNoExpiration = core.Check{
	ID:           "do-spaces-bucket-lifecycle-no-expiration",
	Title:        "Lifecycle configuration must include an expiration rule",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesBucketType,
	Description: "A bucket with lifecycle enabled but zero expiration rules " +
		"is paying full Spaces storage for objects nobody is pruning. " +
		"The single most common lifecycle misconfiguration: the rule " +
		"only sets a transition or MPU abort, not an actual TTL on " +
		"objects. SOC2 CC9.1 + CIS 3.5 expect documented retention; " +
		"this finding asserts the lifecycle config implements one.",
	Remediation: "Add an Expiration block: in the dashboard's bucket " +
		"settings or via the S3 API. Example AWS-CLI shape: " +
		"'aws s3api put-bucket-lifecycle-configuration --bucket NAME " +
		"--lifecycle-configuration file://lifecycle.json --endpoint-url " +
		"https://REGION.digitaloceanspaces.com'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.5.13", "A.5.34"},
		"cis-v8":   {"3.5"},
	},
	Tags:    []string{"spaces", "lifecycle", "cost", "retention"},
	Scanner: "spaces.LifecycleNoExpiration",
}

func SpacesLifecycleNoExpiration(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(docol.SpacesBucketType) {
		configured, _ := b.Attributes["lifecycle_configured"].(bool)
		if !configured {
			continue // separate check do-spaces-bucket-no-lifecycle covers absence
		}
		hasExp, _ := b.Attributes["lifecycle_has_expiration"].(bool)
		f := newSpacesFinding(CheckSpacesLifecycleNoExpiration, b)
		if hasExp {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: lifecycle has expiration rule", b.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: lifecycle configured but no expiration rule", b.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 2. lifecycle covers MPU abort ------------------------------------

var CheckSpacesLifecycleNoMPUAbort = core.Check{
	ID:           "do-spaces-bucket-lifecycle-no-mpu-cleanup",
	Title:        "Lifecycle configuration must abort incomplete multipart uploads",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesBucketType,
	Description: "Multipart uploads that never call CompleteMultipartUpload " +
		"leave orphaned parts billed at full Spaces storage rate, " +
		"sometimes invisibly for years. A lifecycle rule with " +
		"AbortIncompleteMultipartUpload (DaysAfterInitiation = 7 is " +
		"the conventional value) reaps these on a schedule. The cost " +
		"impact is often material; the audit impact is that orphaned " +
		"parts are not enumerated by GetObject so they're invisible " +
		"to standard inventory scans.",
	Remediation: "Add an AbortIncompleteMultipartUpload rule to the " +
		"existing lifecycle config: 'DaysAfterInitiation: 7' is the " +
		"conventional default. The S3 API accepts this alongside " +
		"existing Expiration rules in one PutBucketLifecycleConfiguration " +
		"call.",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1", "A1.2"},
		"iso27001": {"A.5.13"},
		"cis-v8":   {"3.5"},
	},
	Tags:    []string{"spaces", "lifecycle", "cost", "multipart"},
	Scanner: "spaces.LifecycleNoMPUAbort",
}

func SpacesLifecycleNoMPUAbort(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(docol.SpacesBucketType) {
		configured, _ := b.Attributes["lifecycle_configured"].(bool)
		if !configured {
			continue
		}
		hasMPU, _ := b.Attributes["lifecycle_has_mpu_abort"].(bool)
		f := newSpacesFinding(CheckSpacesLifecycleNoMPUAbort, b)
		if hasMPU {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: lifecycle has MPU abort rule", b.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: lifecycle configured but no MPU abort rule", b.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 3. logging target must not be the source bucket ------------------

var CheckSpacesLoggingSelfTarget = core.Check{
	ID:           "do-spaces-bucket-logging-self-target",
	Title:        "Server-access log target must be a different bucket",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesBucketType,
	Description: "Targeting server-access logs at the bucket they describe " +
		"creates a feedback loop: every access-log write is itself a " +
		"new access logged in the same bucket, ballooning the dataset " +
		"and making any retention policy meaningless. SOC2 CC7.3 and " +
		"ISO A.8.15 expect log records to be tamper-segregated; " +
		"co-mingling target + source defeats that.",
	Remediation: "Designate a dedicated 'access-logs' bucket with a " +
		"restrictive lifecycle (90d expiration, no public access, " +
		"separate access key with logs:Write-only). Update the source " +
		"bucket's logging config to target the dedicated bucket.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2", "CC7.3"},
		"iso27001": {"A.8.15"},
		"cis-v8":   {"8.2", "8.5"},
	},
	Tags:    []string{"spaces", "logging", "segregation"},
	Scanner: "spaces.LoggingSelfTarget",
}

func SpacesLoggingSelfTarget(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(docol.SpacesBucketType) {
		enabled, _ := b.Attributes["logging_enabled"].(bool)
		if !enabled {
			continue // separate check do-spaces-bucket-no-logging covers absence
		}
		target, _ := b.Attributes["logging_target_bucket"].(string)
		f := newSpacesFinding(CheckSpacesLoggingSelfTarget, b)
		switch {
		case target == "":
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("bucket %q: logging_enabled=true but no target_bucket reported", b.Name)
		case target == b.Name:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: logs target the source bucket (feedback loop)", b.Name)
		default:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: logs target %q (segregated)", b.Name, target)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 4. bucket policy required for production buckets -----------------

var CheckSpacesPolicyRequired = core.Check{
	ID:           "do-spaces-bucket-policy-required",
	Title:        "Production Spaces buckets must declare an explicit bucket policy",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesBucketType,
	Description: "Spaces buckets default to no bucket policy — access is " +
		"governed solely by access keys and ACLs. SOC2 CC6.1 and ISO " +
		"A.5.15 expect documented authorization rules; the bucket " +
		"policy is the only structured surface where a Spaces bucket " +
		"can record an explicit-deny posture (e.g. Deny on Principal:* " +
		"for s3:GetObject) that survives misconfigured ACLs.",
	Remediation: "Author a policy that explicitly denies the actions you " +
		"never want — public reads, ACL changes, multipart abort. " +
		"Apply via 'aws s3api put-bucket-policy --bucket NAME --policy " +
		"file://policy.json --endpoint-url https://REGION.digitaloceanspaces.com'. " +
		"DO docs: https://docs.digitalocean.com/products/spaces/how-to/manage-access/.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15"},
		"cis-v8":   {"3.3"},
	},
	Tags:    []string{"spaces", "policy", "access-control"},
	Scanner: "spaces.PolicyRequired",
}

func SpacesPolicyRequired(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(docol.SpacesBucketType) {
		configured, _ := b.Attributes["policy_configured"].(bool)
		f := newSpacesFinding(CheckSpacesPolicyRequired, b)
		if configured {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: bucket policy configured", b.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: no bucket policy configured", b.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 5. versioning enabled implies lifecycle (cost guard) -------------

var CheckSpacesVersioningRequiresLifecycle = core.Check{
	ID:           "do-spaces-bucket-versioning-requires-lifecycle",
	Title:        "Versioned buckets must declare a lifecycle policy",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesBucketType,
	Description: "Versioning without lifecycle is a cost-leak pattern: " +
		"every overwrite + every delete creates a non-current version " +
		"that's billed at full storage rate, forever. SOC2 A1.2 + " +
		"CIS 3.5 expect retention and capacity controls together; " +
		"this finding asserts the cost dimension of the controls " +
		"pair is in place.",
	Remediation: "Add a lifecycle rule with NoncurrentVersionExpiration " +
		"(commonly 30-90 days). Apply via the S3 API or dashboard. " +
		"Pair with the do-spaces-bucket-lifecycle-no-expiration check " +
		"to ensure the rule covers current versions too.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2", "CC9.1"},
		"iso27001": {"A.5.34"},
		"cis-v8":   {"3.5"},
	},
	Tags:    []string{"spaces", "versioning", "lifecycle", "cost"},
	Scanner: "spaces.VersioningRequiresLifecycle",
}

func SpacesVersioningRequiresLifecycle(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(docol.SpacesBucketType) {
		versioning, _ := b.Attributes["versioning_enabled"].(bool)
		if !versioning {
			continue
		}
		lifecycle, _ := b.Attributes["lifecycle_configured"].(bool)
		f := newSpacesFinding(CheckSpacesVersioningRequiresLifecycle, b)
		if lifecycle {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: versioning + lifecycle both enabled", b.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: versioning enabled but no lifecycle config", b.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 6. audit-grade buckets need encryption AND logging ---------------

var CheckSpacesAuditPairing = core.Check{
	ID:           "do-spaces-bucket-audit-pairing",
	Title:        "Audit-relevant buckets must have encryption AND logging both on",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesBucketType,
	Description: "Two checks already exist for encryption + logging in " +
		"isolation; this composite check fails when EITHER is off, " +
		"matching how auditors evaluate the pair. ISO A.5.34 + " +
		"A.8.15 each require encryption + audit logs as a pair; a " +
		"bucket with one but not the other doesn't carry an audit " +
		"narrative.",
	Remediation: "Enable both: 'aws s3api put-bucket-encryption ...' + " +
		"'aws s3api put-bucket-logging ...' against the Spaces endpoint. " +
		"Logging target should be a dedicated bucket (see " +
		"do-spaces-bucket-logging-self-target).",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC7.2"},
		"iso27001": {"A.5.34", "A.8.15"},
		"cis-v8":   {"3.11", "8.2"},
	},
	Tags:    []string{"spaces", "encryption", "logging", "audit"},
	Scanner: "spaces.AuditPairing",
}

func SpacesAuditPairing(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(docol.SpacesBucketType) {
		enc, _ := b.Attributes["encryption_configured"].(bool)
		log, _ := b.Attributes["logging_enabled"].(bool)
		f := newSpacesFinding(CheckSpacesAuditPairing, b)
		if enc && log {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: encryption + logging both enabled", b.Name)
		} else {
			missing := []string{}
			if !enc {
				missing = append(missing, "encryption")
			}
			if !log {
				missing = append(missing, "logging")
			}
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: missing %v", b.Name, missing)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 7. manual-verify: object-lock unsupported ------------------------

var CheckSpacesObjectLockAppLayer = core.Check{
	ID:           "do-spaces-bucket-object-lock-via-app-layer",
	Title:        "DO Spaces does not support S3 Object Lock — verify app-layer immutability",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesBucketType,
	Description: "S3 Object Lock provides WORM (write-once-read-many) " +
		"semantics required by SEC 17a-4, FINRA, CFTC, HIPAA, and " +
		"some PCI scenarios. DO Spaces does not implement Object Lock — " +
		"any compliance regime requiring WORM must be satisfied via " +
		"application-layer immutability (content-addressed storage, " +
		"hash-locked manifests, off-platform replication to an " +
		"object-lock-capable target). This finding flags the gap so " +
		"the auditor can record the compensating control.",
	Remediation: "If WORM is a regulatory requirement: replicate audit-" +
		"relevant writes off-Spaces to an S3 Object Lock target " +
		"(AWS S3, Backblaze B2 with Object Lock, MinIO with WORM " +
		"mode) and document the application-layer hash-chain. " +
		"Otherwise, waive via waivers.yaml citing the absence of " +
		"WORM regulatory requirements.",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.5.13", "A.5.34"},
		"cis-v8":   {"3.5"},
	},
	Tags:    []string{"spaces", "object-lock", "unsupported", "manual-verify"},
	Scanner: "spaces.ObjectLockAppLayer",
}

func SpacesObjectLockAppLayer(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(docol.SpacesBucketType) {
		findings = append(findings,
			spacesManualVerify(CheckSpacesObjectLockAppLayer, b,
				"S3 Object Lock not implemented",
				spacesDocsURL+"reference/s3-compatibility/"))
	}
	return findings, nil
}

// ----- 8. manual-verify: replication unsupported ------------------------

var CheckSpacesReplicationViaExternalSync = core.Check{
	ID:           "do-spaces-bucket-replication-via-external-sync",
	Title:        "DO Spaces does not support cross-region replication — verify external sync",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesBucketType,
	Description: "S3 Cross-Region Replication (CRR) is the standard " +
		"availability + durability control for object stores: a " +
		"single-region outage doesn't lose objects, RPO ≈ minutes. " +
		"DO Spaces does not implement CRR. SOC2 A1.2 + ISO A.5.30 " +
		"each require a documented availability strategy; this " +
		"finding flags the gap so the auditor can confirm an " +
		"out-of-band sync (rclone cron, custom job) is in place.",
	Remediation: "Run a periodic 'rclone sync' between the source Spaces " +
		"region and a target (different Spaces region OR a different " +
		"provider). Capture the cron schedule + last-success timestamp " +
		"in the runbook. If a multi-region availability SLA isn't a " +
		"business requirement, waive via waivers.yaml.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2", "CC9.1"},
		"iso27001": {"A.5.30", "A.8.13"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"spaces", "replication", "unsupported", "manual-verify"},
	Scanner: "spaces.ReplicationViaExternalSync",
}

func SpacesReplicationViaExternalSync(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(docol.SpacesBucketType) {
		findings = append(findings,
			spacesManualVerify(CheckSpacesReplicationViaExternalSync, b,
				"Cross-region replication not implemented",
				spacesDocsURL+"reference/s3-compatibility/"))
	}
	return findings, nil
}

// ----- 9. manual-verify: MFA-delete unsupported -------------------------

var CheckSpacesMFADeleteViaTeamIAM = core.Check{
	ID:           "do-spaces-bucket-mfa-delete-via-team-iam",
	Title:        "DO Spaces does not support MFA-Delete — verify via team IAM controls",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesBucketType,
	Description: "S3 MFA-Delete requires an MFA token to call DeleteObject " +
		"or PutBucketVersioning. DO Spaces does not implement this. " +
		"The compensating control is team-level: require 2FA on the " +
		"team (do-account-mfa-required) AND restrict the Spaces access " +
		"key permissions so delete operations require a separate " +
		"least-privilege key whose use is logged. CIS 3.3 and SOC2 " +
		"CC6.3 each expect deletion to be a privileged operation.",
	Remediation: "Three layers: (1) ensure team 2FA is enforced; (2) issue " +
		"a separate Spaces access key for any role that needs delete; " +
		"(3) restrict that key to specific buckets via the bucket " +
		"policy. See do-spaces-key-fullaccess for the existing scope-" +
		"of-key check.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.3"},
		"iso27001": {"A.5.15", "A.5.18"},
		"cis-v8":   {"3.3", "6.5"},
	},
	Tags:    []string{"spaces", "mfa-delete", "unsupported", "manual-verify"},
	Scanner: "spaces.MFADeleteViaTeamIAM",
}

func SpacesMFADeleteViaTeamIAM(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(docol.SpacesBucketType) {
		findings = append(findings,
			spacesManualVerify(CheckSpacesMFADeleteViaTeamIAM, b,
				"MFA-Delete not implemented; control falls back to team 2FA + key scope",
				spacesDocsURL+"reference/s3-compatibility/"))
	}
	return findings, nil
}

// ----- 10. manual-verify: encryption key rotation -----------------------

var CheckSpacesEncryptionKeyRotation = core.Check{
	ID:           "do-spaces-bucket-encryption-key-rotation-documented",
	Title:        "Spaces encryption uses platform-managed keys — verify rotation cadence",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "spaces",
	ResourceType: docol.SpacesBucketType,
	Description: "DO Spaces server-side encryption is SSE-S3-equivalent: " +
		"DigitalOcean manages the keys. Customer-managed keys (SSE-C, " +
		"SSE-KMS-equivalent) are not exposed. SOC2 CC6.7 + ISO A.8.24 " +
		"each ask for documented rotation cadence on encryption keys; " +
		"since the keys are out of scope, the audit obligation falls " +
		"on DigitalOcean's published SOC 2 Type 2 report. This finding " +
		"records the gap so the auditor knows to reference DO's report " +
		"rather than expecting a customer-side rotation log.",
	Remediation: "Obtain DigitalOcean's current SOC 2 Type 2 report from " +
		"the security portal (https://www.digitalocean.com/trust). " +
		"Cite section addressing CC6.7 encryption-key management in " +
		"your audit narrative. No customer-side action.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.11"},
	},
	Tags:    []string{"spaces", "encryption", "key-rotation", "manual-verify"},
	Scanner: "spaces.EncryptionKeyRotation",
}

func SpacesEncryptionKeyRotation(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(docol.SpacesBucketType) {
		findings = append(findings,
			spacesManualVerify(CheckSpacesEncryptionKeyRotation, b,
				"platform-managed encryption keys; rotation cadence is DO's responsibility per SOC2 report",
				"https://www.digitalocean.com/trust"))
	}
	return findings, nil
}

func init() {
	core.Register(CheckSpacesLifecycleNoExpiration, SpacesLifecycleNoExpiration)
	core.Register(CheckSpacesLifecycleNoMPUAbort, SpacesLifecycleNoMPUAbort)
	core.Register(CheckSpacesLoggingSelfTarget, SpacesLoggingSelfTarget)
	core.Register(CheckSpacesPolicyRequired, SpacesPolicyRequired)
	core.Register(CheckSpacesVersioningRequiresLifecycle, SpacesVersioningRequiresLifecycle)
	core.Register(CheckSpacesAuditPairing, SpacesAuditPairing)
	core.Register(CheckSpacesObjectLockAppLayer, SpacesObjectLockAppLayer)
	core.Register(CheckSpacesReplicationViaExternalSync, SpacesReplicationViaExternalSync)
	core.Register(CheckSpacesMFADeleteViaTeamIAM, SpacesMFADeleteViaTeamIAM)
	core.Register(CheckSpacesEncryptionKeyRotation, SpacesEncryptionKeyRotation)
}
