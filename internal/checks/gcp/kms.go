package gcp

import (
	"context"
	"fmt"
	"sort"
	"strings"

	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	"github.com/darpanzope/compliancekit/internal/core"
)

// kmsMaxRotationDays is the threshold for CheckKMSKeyRotation.
// CIS GCP Foundations 1.10 prescribes 90 days as the maximum
// rotation period for symmetric encryption keys.
const kmsMaxRotationDays = 90

// kmsAdminRole is the catch-all role that owns the key. CIS GCP
// 1.11 requires this role be separated from any
// encrypter/decrypter role.
const kmsAdminRole = "roles/cloudkms.admin"

// kmsEncrypterDecrypterRoles are the roles whose holders perform
// crypto operations. A principal granted any of these AND
// cloudkms.admin can rotate or destroy keys while also reading
// the ciphertext they encrypted — defeats the separation-of-duties
// control.
var kmsEncrypterDecrypterRoles = map[string]bool{
	"roles/cloudkms.cryptoKeyEncrypterDecrypter": true,
	"roles/cloudkms.cryptoKeyEncrypter":          true,
	"roles/cloudkms.cryptoKeyDecrypter":          true,
}

// CheckKMSKeyRotation requires symmetric encrypt/decrypt keys to
// rotate at least every 90 days. CIS GCP Foundations 1.10.
var CheckKMSKeyRotation = core.Check{
	ID:           "gcp-kms-key-rotation",
	Title:        "KMS encrypt/decrypt keys must rotate at least every 90 days",
	Severity:     core.SeverityMedium,
	Provider:     "gcp",
	Service:      "kms",
	ResourceType: gcpcol.KMSCryptoKeyType,
	Description: "Periodic rotation of symmetric keys limits the blast radius " +
		"of a compromised key version: once rotated, ciphertext written under " +
		"the old version can still be decrypted but new traffic uses fresh " +
		"material. CIS GCP Foundations 1.10 prescribes a rotation period of " +
		"90 days or less. Asymmetric and signing keys are out of scope (the " +
		"rotation period field doesn't apply).",
	Remediation: "'gcloud kms keys update <key> --keyring=<ring> " +
		"--location=<location> --rotation-period=90d --next-rotation-time=<rfc3339>'. " +
		"For Terraform set rotation_period = \"7776000s\" on the " +
		"google_kms_crypto_key resource.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.11"},
	},
	Tags:    []string{"kms", "key-management", "rotation"},
	Scanner: "kms.KeyRotation",
}

func KMSKeyRotation(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, k := range g.ByType(gcpcol.KMSCryptoKeyType) {
		isED, _ := k.Attributes["is_encrypt_decrypt"].(bool)
		if !isED {
			// Asymmetric / signing keys: rotation field doesn't
			// apply; skip rather than emit a false fail.
			continue
		}
		hasSchedule, _ := k.Attributes["has_rotation_schedule"].(bool)
		days, _ := k.Attributes["rotation_period_days"].(int)
		f := core.Finding{
			CheckID:  CheckKMSKeyRotation.ID,
			Severity: CheckKMSKeyRotation.Severity,
			Resource: k.Ref(),
			Tags:     CheckKMSKeyRotation.Tags,
		}
		switch {
		case !hasSchedule:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("key %q: no rotation schedule", k.Name)
		case days > kmsMaxRotationDays:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("key %q: rotation period %dd (> %dd max)", k.Name, days, kmsMaxRotationDays)
		default:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("key %q: rotates every %dd", k.Name, days)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckKMSAdminUserSeparation forbids the same principal from
// holding cloudkms.admin AND any crypto-operation role on the
// same key. CIS GCP Foundations 1.11.
var CheckKMSAdminUserSeparation = core.Check{
	ID:           "gcp-kms-admin-user-separation",
	Title:        "KMS key admins must be separate from encrypters/decrypters",
	Severity:     core.SeverityMedium,
	Provider:     "gcp",
	Service:      "kms",
	ResourceType: gcpcol.KMSCryptoKeyType,
	Description: "A principal with both roles/cloudkms.admin and " +
		"roles/cloudkms.cryptoKeyEncrypterDecrypter on the same key can " +
		"rotate or destroy keys while also reading ciphertext encrypted " +
		"under them, collapsing the separation of duties that KMS is meant " +
		"to enforce. CIS GCP Foundations 1.11 prescribes that these roles " +
		"never coincide on the same principal at the key level.",
	Remediation: "Audit who holds which key roles: 'gcloud kms keys " +
		"get-iam-policy <key> --keyring=<ring> --location=<loc>'. Remove " +
		"the overlap by either revoking the admin role (typical for " +
		"applications) or moving crypto operations to a dedicated " +
		"service account distinct from the key admin.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"6.7", "6.8"},
	},
	Tags:    []string{"kms", "least-privilege", "separation-of-duties"},
	Scanner: "kms.AdminUserSeparation",
}

func KMSAdminUserSeparation(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, k := range g.ByType(gcpcol.KMSCryptoKeyType) {
		bindings, _ := k.Attributes["iam_bindings"].([]map[string]any)

		admins := map[string]bool{}
		users := map[string]bool{}
		for _, b := range bindings {
			role, _ := b["role"].(string)
			members, _ := b["members"].([]string)
			switch {
			case role == kmsAdminRole:
				for _, m := range members {
					admins[m] = true
				}
			case kmsEncrypterDecrypterRoles[role]:
				for _, m := range members {
					users[m] = true
				}
			}
		}

		var overlap []string
		for m := range admins {
			if users[m] {
				overlap = append(overlap, m)
			}
		}
		sort.Strings(overlap)

		f := core.Finding{
			CheckID:  CheckKMSAdminUserSeparation.ID,
			Severity: CheckKMSAdminUserSeparation.Severity,
			Resource: k.Ref(),
			Tags:     CheckKMSAdminUserSeparation.Tags,
		}
		if len(overlap) == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("key %q: no admin/user role overlap", k.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("key %q: %d principal(s) hold both admin + crypto role: %s",
				k.Name, len(overlap), strings.Join(overlap, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckKMSKeyRotation, KMSKeyRotation)
	core.Register(CheckKMSAdminUserSeparation, KMSAdminUserSeparation)
}
