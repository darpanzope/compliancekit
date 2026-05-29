package cli

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// v1.19 phase 4 — screenshot-grade demo seed.
//
// seedDemoRich replaces the v1.15.1 hand-coded 3-scan / ~50-finding DO
// demo with a procedurally generated fleet: ~150 resources across six
// providers, a curated per-resource-type check catalog, and 8 weekly
// scans whose finding counts shrink toward the present (an improving
// posture, so the score-over-time chart trends up and the dashboards
// look like a real account). The generator is seeded with a fixed RNG
// so every `serve --demo` boot produces the identical dataset —
// screenshot-stable + idempotent (fixed row ids + ON CONFLICT).

const (
	demoScanWeeks   = 8  // 8 weekly scans (week 0 = newest)
	demoRNGSeed     = 42 // fixed so the demo is identical every boot
	demoOldestFails = 92 // fails in the oldest scan
	demoNewestFails = 46 // fails in the newest scan (improving trend)
)

type demoResource struct {
	id, name, typ, provider string
}

// demoCheck is a check that fails on resources of ResType. Severity +
// message + framework JSON match the real catalog's shape closely
// enough for screenshots.
type demoCheck struct {
	id, severity, message, frameworks, resType string
}

// demoFleet builds the ~150-resource demo inventory across providers.
func demoFleet() []demoResource {
	var rs []demoResource
	add := func(provider, typ, prefix string, n int) {
		for i := 1; i <= n; i++ {
			name := fmt.Sprintf("%s-%02d", prefix, i)
			rs = append(rs, demoResource{
				id:       fmt.Sprintf("%s:%s:%s", provider, typ, name),
				name:     name,
				typ:      typ,
				provider: provider,
			})
		}
	}
	// DigitalOcean (~46)
	add("digitalocean", "droplet", "web", 12)
	add("digitalocean", "droplet", "worker", 8)
	add("digitalocean", "space", "bucket", 8)
	add("digitalocean", "database", "pg", 5)
	add("digitalocean", "firewall", "fw", 6)
	add("digitalocean", "load_balancer", "lb", 4)
	add("digitalocean", "vpc", "vpc", 3)
	// AWS (~40)
	add("aws", "ec2", "ec2", 15)
	add("aws", "s3", "s3", 8)
	add("aws", "iam", "role", 6)
	add("aws", "rds", "rds", 4)
	add("aws", "eks", "eks", 3)
	add("aws", "kms", "key", 4)
	// GCP (~30)
	add("gcp", "compute", "vm", 12)
	add("gcp", "storage", "gcs", 6)
	add("gcp", "iam", "sa", 5)
	add("gcp", "gke", "gke", 3)
	add("gcp", "sqladmin", "sql", 4)
	// Kubernetes (~36)
	add("kubernetes", "pod", "pod", 18)
	add("kubernetes", "deployment", "deploy", 6)
	add("kubernetes", "service", "svc", 4)
	add("kubernetes", "ingress", "ing", 3)
	add("kubernetes", "secret", "secret", 5)
	return rs
}

// demoCheckCatalog maps a resource type to the checks that can fail on
// it. Each (resource, check) pair is a candidate finding.
func demoCheckCatalog() map[string][]demoCheck {
	c := map[string][]demoCheck{
		"droplet": {
			{"do-droplet-no-firewall", "high", "Droplet has no firewall attached", `["soc2","cis-v8","iso27001"]`, "droplet"},
			{"do-droplet-old-image", "low", "Droplet image is more than 180 days old", `["cis-v8"]`, "droplet"},
			{"do-droplet-no-backups", "medium", "Droplet has automatic backups disabled", `["cis-v8","soc2"]`, "droplet"},
		},
		"space": {
			{"do-spaces-public-acl", "critical", "Spaces bucket has a public ACL", `["soc2","pci-dss-v4","iso27001"]`, "space"},
			{"do-spaces-versioning-disabled", "medium", "Spaces bucket versioning is disabled", `["soc2","cis-v8"]`, "space"},
			{"do-spaces-no-encryption", "medium", "Spaces bucket has no default encryption", `["soc2","pci-dss-v4"]`, "space"},
		},
		"database": {
			{"do-managed-db-public", "high", "Managed database accepts public connections", `["soc2","pci-dss-v4"]`, "database"},
			{"do-managed-db-no-backup-window", "medium", "Managed database has no backup window", `["soc2","cis-v8"]`, "database"},
		},
		"firewall": {
			{"do-firewall-ssh-from-any", "high", "Firewall allows SSH (22) from 0.0.0.0/0", `["soc2","cis-v8","iso27001"]`, "firewall"},
			{"do-firewall-rdp-from-any", "high", "Firewall allows RDP (3389) from 0.0.0.0/0", `["soc2","cis-v8"]`, "firewall"},
		},
		"load_balancer": {
			{"do-lb-tls-13", "medium", "Load balancer uses TLS < 1.3", `["soc2","cis-v8"]`, "load_balancer"},
		},
		"vpc": {
			{"do-vpc-default-used", "low", "Resources attached to the default VPC", `["cis-v8"]`, "vpc"},
		},
		"ec2": {
			{"aws-ec2-public-ip", "high", "EC2 instance has a public IP", `["soc2","cis-v8"]`, "ec2"},
			{"aws-ec2-imdsv2-optional", "medium", "EC2 instance allows IMDSv1", `["cis-v8","soc2"]`, "ec2"},
			{"aws-ec2-no-detailed-monitoring", "low", "EC2 instance has detailed monitoring off", `["cis-v8"]`, "ec2"},
		},
		"s3": {
			{"aws-s3-public-bucket", "critical", "S3 bucket is publicly readable", `["soc2","pci-dss-v4","iso27001"]`, "s3"},
			{"aws-s3-no-encryption", "high", "S3 bucket has no default encryption", `["soc2","pci-dss-v4"]`, "s3"},
		},
		"iam": {
			{"aws-iam-admin-policy", "high", "IAM role attaches AdministratorAccess", `["soc2","cis-v8","iso27001"]`, "iam"},
			{"aws-iam-no-mfa", "medium", "IAM user has no MFA device", `["soc2","cis-v8"]`, "iam"},
		},
		"rds": {
			{"aws-rds-public", "high", "RDS instance is publicly accessible", `["soc2","pci-dss-v4"]`, "rds"},
		},
		"eks": {
			{"aws-eks-public-endpoint", "high", "EKS API endpoint is public", `["soc2","cis-v8"]`, "eks"},
		},
		"kms": {
			{"aws-kms-no-rotation", "medium", "KMS key rotation is disabled", `["soc2","cis-v8"]`, "kms"},
		},
		"compute": {
			{"gcp-compute-public-ip", "high", "Compute instance has a public IP", `["soc2","cis-v8"]`, "compute"},
			{"gcp-compute-oslogin-off", "medium", "Compute instance has OS Login disabled", `["cis-v8"]`, "compute"},
		},
		"storage": {
			{"gcp-gcs-public", "critical", "GCS bucket is publicly accessible", `["soc2","pci-dss-v4"]`, "storage"},
		},
		"sa": {
			{"gcp-sa-owner-role", "high", "Service account holds the Owner role", `["soc2","iso27001"]`, "sa"},
		},
		"gke": {
			{"gcp-gke-legacy-abac", "high", "GKE cluster has legacy ABAC enabled", `["cis-v8","soc2"]`, "gke"},
		},
		"sqladmin": {
			{"gcp-sql-public", "high", "Cloud SQL allows public IP connections", `["soc2","pci-dss-v4"]`, "sqladmin"},
		},
		"pod": {
			{"k8s-pod-privileged", "critical", "Pod runs a privileged container", `["nsa-cisa-k8s","cis-v8"]`, "pod"},
			{"k8s-pod-run-as-root", "high", "Pod runs as root (runAsNonRoot unset)", `["nsa-cisa-k8s","soc2"]`, "pod"},
			{"k8s-pod-no-limits", "low", "Pod has no resource limits", `["cis-v8"]`, "pod"},
		},
		"deployment": {
			{"k8s-deploy-no-probes", "medium", "Deployment has no readiness/liveness probes", `["cis-v8"]`, "deployment"},
		},
		"service": {
			{"k8s-svc-loadbalancer-public", "medium", "Service of type LoadBalancer is public", `["soc2","cis-v8"]`, "service"},
		},
		"ingress": {
			{"k8s-ingress-no-tls", "high", "Ingress has no TLS configured", `["soc2","pci-dss-v4"]`, "ingress"},
		},
		"secret": {
			{"k8s-secret-unencrypted", "high", "Secret is not encrypted at rest", `["soc2","nsa-cisa-k8s"]`, "secret"},
		},
	}
	return c
}

// seedDemoRich generates the 8-week scan history + ~500 findings across
// the demo fleet. Deterministic (fixed RNG) so screenshots are stable.
func seedDemoRich(ctx context.Context, st *store.Store) {
	rng := rand.New(rand.NewSource(demoRNGSeed)) //nolint:gosec // demo data, not security-sensitive
	fleet := demoFleet()
	catalog := demoCheckCatalog()

	// Build the full candidate (resource, check) pair list once.
	type pair struct {
		r demoResource
		c demoCheck
	}
	var pairs []pair
	for _, r := range fleet {
		for _, ck := range catalog[r.typ] {
			pairs = append(pairs, pair{r, ck})
		}
	}

	scanQ := `INSERT INTO scans (id, created_at, source, status, providers_scanned,
	                              frameworks_scanned, score, coverage, total_findings,
	                              actionable_findings, duration_ms)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	          ON CONFLICT(id) DO NOTHING`
	const findingQ = `INSERT INTO findings (id, scan_id, fingerprint, check_id, severity, status, provider,
	                                         resource_id, resource_name, resource_type, message,
	                                         framework_ids, first_seen_at, last_seen_at, created_at)
	                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	                  ON CONFLICT(id) DO NOTHING`
	const resourceQ = `INSERT INTO resources (id, name, type, provider, first_seen_at, last_seen_at, last_seen_scan_id)
	                   VALUES (?, ?, ?, ?, ?, ?, ?)
	                   ON CONFLICT(id) DO UPDATE SET
	                     name = excluded.name, type = excluded.type, provider = excluded.provider,
	                     last_seen_at = excluded.last_seen_at, last_seen_scan_id = excluded.last_seen_scan_id`

	providersJSON := `["digitalocean","aws","gcp","kubernetes"]`
	frameworksJSON := `["soc2","cis-v8","iso27001","pci-dss-v4","nsa-cisa-k8s"]`
	findingSeq := 0

	for w := 0; w < demoScanWeeks; w++ {
		scanID := fmt.Sprintf("demo-scan-%d", w+1)
		ts := time.Now().Add(-time.Duration(w*7) * 24 * time.Hour).UTC().Format(time.RFC3339)
		// Linear improving trend: oldest week has the most fails.
		frac := float64(w) / float64(demoScanWeeks-1) // 0 (newest) .. 1 (oldest)
		fails := demoNewestFails + int(frac*float64(demoOldestFails-demoNewestFails))
		if fails > len(pairs) {
			fails = len(pairs)
		}
		// Every demo check is non-info, so actionable == fails. Score
		// climbs as fails shrink: ~64 (oldest) → ~90 (newest).
		score := 90 - int(frac*26)
		// Insert the scan FIRST — findings.scan_id has a FK to scans(id)
		// + SQLite enforces foreign keys, so the parent row must exist
		// before its findings.
		_, _ = st.DB().ExecContext(ctx, scanQ,
			scanID, ts, "daemon", "completed", providersJSON, frameworksJSON,
			score, 96, fails, fails, 8200+w*140)

		// Shuffle the candidate pairs + take the first `fails`.
		idx := rng.Perm(len(pairs))
		for k := 0; k < fails; k++ {
			p := pairs[idx[k]]
			findingSeq++
			findingID := fmt.Sprintf("demo-finding-%04d", findingSeq)
			fp := fmt.Sprintf("%s|%s|%s", p.c.id, p.r.id, p.c.severity)
			_, _ = st.DB().ExecContext(ctx, findingQ,
				findingID, scanID, fp, p.c.id, p.c.severity, "fail", p.r.provider,
				p.r.id, p.r.name, p.r.typ, p.c.message, p.c.frameworks, ts, ts, ts)
			_, _ = st.DB().ExecContext(ctx, resourceQ,
				p.r.id, p.r.name, p.r.typ, p.r.provider, ts, ts, scanID)
		}
	}
}
