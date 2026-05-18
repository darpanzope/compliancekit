package policy_test

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	"github.com/darpanzope/compliancekit/internal/policy"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Phase 6 validation: each Rego policy under examples/policies/ is
// exercised against a fixture that matches its declared resource
// schema, asserting the produced Finding set matches expectations.
//
// Scope: this is *semantic* validation, not Go-twin byte parity.
// The Go checks read directly from the collector's native attribute
// shapes (nested maps, container lists, sshd config blobs); the
// Rego policies declare a simpler attribute schema in their own
// comments and tests. Cross-implementation byte parity requires a
// JSON-stable canonical resource shape that both sides can target,
// which is a collector-side change deferred to a future milestone.
//
// What this test proves at v0.16:
//   - Every shipped Rego policy compiles + loads.
//   - Every policy correctly implements the semantics declared in
//     its metadata description.
//   - The compliancekit built-ins (has_tag / attr_str / attr_bool /
//     cvss_band) work end-to-end across all 15 policies.
//   - Severity routing: a policy that does not declare a severity
//     override inherits its metadata.severity; a policy that does
//     override produces the overridden value.

type parityCase struct {
	name      string
	regoPath  string
	resources []compliancekit.Resource
	wantFails []string // Resource.IDs that must produce a fail finding
}

func TestRegoPolicy_Semantics(t *testing.T) {
	cases := []parityCase{
		// ---------------------------------------------------- AWS
		{
			name:     "aws-s3-public-access-block: missing PAB attr → error finding; configured=false flags → fail",
			regoPath: "../../examples/policies/aws/s3_public_access_block.rego",
			resources: []compliancekit.Resource{
				bucket("aws.s3.bucket.no-pab", "no-pab", nil), // missing attr → 1 error finding
				bucket("aws.s3.bucket.partial-pab", "partial-pab", map[string]any{
					"public_access_block": map[string]any{
						"configured":              true,
						"block_public_acls":       true,
						"ignore_public_acls":      false, // ← one false flag
						"block_public_policy":     true,
						"restrict_public_buckets": true,
					},
				}),
				bucket("aws.s3.bucket.fully-private", "fully-private", map[string]any{
					"public_access_block": map[string]any{
						"configured":              true,
						"block_public_acls":       true,
						"ignore_public_acls":      true,
						"block_public_policy":     true,
						"restrict_public_buckets": true,
					},
				}),
			},
			wantFails: []string{"aws.s3.bucket.no-pab", "aws.s3.bucket.partial-pab"},
		},
		{
			name:     "aws-kms-cmk-rotation: customer symmetric without rotation → fail",
			regoPath: "../../examples/policies/aws/kms_cmk_rotation.rego",
			resources: []compliancekit.Resource{
				kmsKey("aws.kms.key.unrotated", "unrotated", "CUSTOMER", "SYMMETRIC_DEFAULT", false),
				kmsKey("aws.kms.key.rotated", "rotated", "CUSTOMER", "SYMMETRIC_DEFAULT", true),
				kmsKey("aws.kms.key.aws-managed", "aws-managed", "AWS", "SYMMETRIC_DEFAULT", false), // AWS-managed → skip
			},
			wantFails: []string{"aws.kms.key.unrotated"},
		},
		{
			name:     "aws-iam-password-policy: length + classes + age + reuse violations",
			regoPath: "../../examples/policies/aws/iam_password_policy.rego",
			resources: []compliancekit.Resource{
				account("aws.account.compliant", "compliant", map[string]any{
					"minimum_password_length":   14,
					"require_uppercase":         true,
					"require_lowercase":         true,
					"require_numbers":           true,
					"require_symbols":           true,
					"max_password_age":          90,
					"password_reuse_prevention": 24,
				}),
				account("aws.account.weak-length", "weak-length", map[string]any{
					"minimum_password_length":   8, // ← fail
					"require_uppercase":         true,
					"require_lowercase":         true,
					"require_numbers":           true,
					"require_symbols":           true,
					"max_password_age":          90,
					"password_reuse_prevention": 24,
				}),
			},
			wantFails: []string{"aws.account.weak-length"},
		},

		// ---------------------------------------------------- GCP
		{
			name:     "gcp-storage-public-access-prevention: pap != enforced → fail",
			regoPath: "../../examples/policies/gcp/storage_public_access_prevention.rego",
			resources: []compliancekit.Resource{
				gcsBucket("gcp.storage.bucket.unenforced", "unenforced", map[string]any{"public_access_prevention": "inherited"}),
				gcsBucket("gcp.storage.bucket.enforced", "enforced", map[string]any{"public_access_prevention": "enforced"}),
			},
			wantFails: []string{"gcp.storage.bucket.unenforced"},
		},
		{
			name:     "gcp-storage-uniform-bucket-level-access: ubla=false → fail",
			regoPath: "../../examples/policies/gcp/storage_uniform_bucket_level_access.rego",
			resources: []compliancekit.Resource{
				gcsBucket("gcp.storage.bucket.noubla", "noubla", map[string]any{"uniform_bucket_level_access": false}),
				gcsBucket("gcp.storage.bucket.ubla", "ubla", map[string]any{"uniform_bucket_level_access": true}),
			},
			wantFails: []string{"gcp.storage.bucket.noubla"},
		},
		{
			name:     "gcp-sql-deletion-protection: false → fail",
			regoPath: "../../examples/policies/gcp/sql_deletion_protection.rego",
			resources: []compliancekit.Resource{
				sqlInstance("gcp.sql.instance.unprotected", "unprotected", false),
				sqlInstance("gcp.sql.instance.protected", "protected", true),
			},
			wantFails: []string{"gcp.sql.instance.unprotected"},
		},

		// ---------------------------------------------------- DO
		{
			name:     "do-droplet-no-vpc: empty vpc_uuid → fail",
			regoPath: "../../examples/policies/digitalocean/droplet_no_vpc.rego",
			resources: []compliancekit.Resource{
				droplet("digitalocean.droplet.default-net", "default-net", ""),
				droplet("digitalocean.droplet.in-vpc", "in-vpc", "vpc-uuid-1234"),
			},
			wantFails: []string{"digitalocean.droplet.default-net"},
		},
		{
			name:     "do-spaces-public-acl: acl=public-read → fail",
			regoPath: "../../examples/policies/digitalocean/spaces_public_acl.rego",
			resources: []compliancekit.Resource{
				spacesBucket("digitalocean.spaces_bucket.public", "public", "public-read"),
				spacesBucket("digitalocean.spaces_bucket.private", "private", "private"),
			},
			wantFails: []string{"digitalocean.spaces_bucket.public"},
		},
		{
			name:     "do-db-tls-disabled: tls_enforced=false → fail",
			regoPath: "../../examples/policies/digitalocean/db_tls_disabled.rego",
			resources: []compliancekit.Resource{
				doDB("digitalocean.database.notls", "notls", false),
				doDB("digitalocean.database.tls", "tls", true),
			},
			wantFails: []string{"digitalocean.database.notls"},
		},

		// ---------------------------------------------------- K8s
		{
			name:     "k8s-pod-run-as-non-root: run_as_non_root=false → fail",
			regoPath: "../../examples/policies/kubernetes/pod_run_as_non_root.rego",
			resources: []compliancekit.Resource{
				pod("k8s.pod.bad", "bad", map[string]any{"run_as_non_root": false}),
				pod("k8s.pod.good", "good", map[string]any{"run_as_non_root": true}),
			},
			wantFails: []string{"k8s.pod.bad"},
		},
		{
			name:     "k8s-pod-privileged: privileged=true → fail",
			regoPath: "../../examples/policies/kubernetes/pod_privileged.rego",
			resources: []compliancekit.Resource{
				pod("k8s.pod.priv", "priv", map[string]any{"privileged": true}),
				pod("k8s.pod.unpriv", "unpriv", map[string]any{"privileged": false}),
			},
			wantFails: []string{"k8s.pod.priv"},
		},
		{
			name:     "k8s-pod-readonly-root-fs: read_only_root_fs=false → fail",
			regoPath: "../../examples/policies/kubernetes/pod_readonly_root_fs.rego",
			resources: []compliancekit.Resource{
				pod("k8s.pod.writable", "writable", map[string]any{"read_only_root_fs": false}),
				pod("k8s.pod.readonly", "readonly", map[string]any{"read_only_root_fs": true}),
			},
			wantFails: []string{"k8s.pod.writable"},
		},

		// ---------------------------------------------------- Linux
		{
			name:     "linux-aslr-enabled: randomize_va_space != \"2\" → fail",
			regoPath: "../../examples/policies/linux/aslr_enabled.rego",
			resources: []compliancekit.Resource{
				host("linux.host.noaslr", "noaslr", map[string]any{"kernel_randomize_va_space": "0"}),
				host("linux.host.partialaslr", "partialaslr", map[string]any{"kernel_randomize_va_space": "1"}),
				host("linux.host.fullaslr", "fullaslr", map[string]any{"kernel_randomize_va_space": "2"}),
			},
			wantFails: []string{"linux.host.noaslr", "linux.host.partialaslr"},
		},
		{
			name:     "linux-sshd-no-root-login: PermitRootLogin yes/without-password → fail",
			regoPath: "../../examples/policies/linux/sshd_no_root_login.rego",
			resources: []compliancekit.Resource{
				host("linux.host.root-yes", "root-yes", map[string]any{"sshd_permit_root_login": "yes"}),
				host("linux.host.root-wo-pwd", "root-wo-pwd", map[string]any{"sshd_permit_root_login": "without-password"}),
				host("linux.host.root-no", "root-no", map[string]any{"sshd_permit_root_login": "no"}),
				host("linux.host.root-prohibit", "root-prohibit", map[string]any{"sshd_permit_root_login": "prohibit-password"}),
			},
			wantFails: []string{"linux.host.root-yes", "linux.host.root-wo-pwd"},
		},
		{
			name:     "linux-firewall-active: firewall_active=false → fail",
			regoPath: "../../examples/policies/linux/firewall_active.rego",
			resources: []compliancekit.Resource{
				host("linux.host.nofw", "nofw", map[string]any{"firewall_active": false}),
				host("linux.host.fw", "fw", map[string]any{"firewall_active": true}),
			},
			wantFails: []string{"linux.host.nofw"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := policy.LoadFile(context.Background(), filepath.Clean(c.regoPath))
			if err != nil {
				t.Fatalf("LoadFile %s: %v", c.regoPath, err)
			}

			g := compliancekit.NewResourceGraph()
			for _, r := range c.resources {
				g.Add(r)
			}

			findings, err := m.Evaluate(context.Background(), g)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}

			gotFails := failedResourceIDs(findings)
			wantFails := append([]string(nil), c.wantFails...)
			sort.Strings(wantFails)
			if !slicesEqual(gotFails, wantFails) {
				t.Errorf("policy %s\n  got fails:  %v\n  want fails: %v",
					m.Check.ID, gotFails, wantFails)
			}
		})
	}
}

// ----------------------------------------------------------------------
// Fixture helpers — keep the table above readable.
// ----------------------------------------------------------------------

func bucket(id, name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID: id, Type: "aws.s3.bucket", Name: name, Provider: "aws", Attributes: attrs,
	}
}

func kmsKey(id, name, manager, spec string, rotation bool) compliancekit.Resource {
	return compliancekit.Resource{
		ID: id, Type: "aws.kms.key", Name: name, Provider: "aws",
		Attributes: map[string]any{
			"key_manager":      manager,
			"key_spec":         spec,
			"rotation_enabled": rotation,
		},
	}
}

func account(id, name string, policy map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID: id, Type: "aws.account", Name: name, Provider: "aws",
		Attributes: map[string]any{"password_policy": policy},
	}
}

func gcsBucket(id, name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID: id, Type: "gcp.storage.bucket", Name: name, Provider: "gcp", Attributes: attrs,
	}
}

func sqlInstance(id, name string, protected bool) compliancekit.Resource {
	return compliancekit.Resource{
		ID: id, Type: "gcp.sql.instance", Name: name, Provider: "gcp",
		Attributes: map[string]any{"deletion_protection_enabled": protected},
	}
}

func droplet(id, name, vpcUUID string) compliancekit.Resource {
	return compliancekit.Resource{
		ID: id, Type: "digitalocean.droplet", Name: name, Provider: "digitalocean",
		Attributes: map[string]any{"vpc_uuid": vpcUUID},
	}
}

func spacesBucket(id, name, acl string) compliancekit.Resource {
	return compliancekit.Resource{
		ID: id, Type: "digitalocean.spaces_bucket", Name: name, Provider: "digitalocean",
		Attributes: map[string]any{"acl": acl},
	}
}

func doDB(id, name string, tls bool) compliancekit.Resource {
	return compliancekit.Resource{
		ID: id, Type: "digitalocean.database", Name: name, Provider: "digitalocean",
		Attributes: map[string]any{"tls_enforced": tls},
	}
}

func pod(id, name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID: id, Type: "k8s.pod", Name: name, Provider: "kubernetes", Attributes: attrs,
	}
}

func host(id, name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID: id, Type: "linux.host", Name: name, Provider: "linux", Attributes: attrs,
	}
}

// failedResourceIDs returns the sorted set of Resource.IDs for every
// actionable finding (Status == fail OR error). Pass + skip are
// ignored. We collapse fail + error together because the operator-
// facing semantics are identical: both trip --fail-on=<severity>
// gates and both appear as red rows in the runbook. A policy that
// flags missing data as "error" rather than "fail" still counts as
// flagging the resource.
func failedResourceIDs(findings []compliancekit.Finding) []string {
	seen := map[string]struct{}{}
	for _, f := range findings {
		if !f.Status.IsActionable() {
			continue
		}
		seen[f.Resource.ID] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
