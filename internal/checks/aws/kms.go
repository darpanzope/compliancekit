package aws

import (
	"context"
	"fmt"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// CheckKMSCMKRotation requires customer-managed symmetric CMKs to
// have key rotation enabled. CIS AWS Foundations 3.8.
var CheckKMSCMKRotation = compliancekit.Check{
	ID:           "aws-kms-cmk-rotation",
	Title:        "Customer-managed symmetric KMS keys must have rotation enabled",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "aws",
	Service:      "kms",
	ResourceType: awscol.KMSKeyType,
	Description: "KMS key rotation automatically rotates the underlying " +
		"cryptographic material every year, capping the exposure window of " +
		"any leaked key. Only customer-managed symmetric keys support " +
		"rotation; AWS-managed and asymmetric keys are out of scope for " +
		"this check. Pending-deletion keys are also skipped (rotation " +
		"during pending-deletion would be misleading). CIS AWS Foundations " +
		"3.8.",
	Remediation: "Enable: 'aws kms enable-key-rotation --key-id <key-id>'. " +
		"Rotation is free and transparent to applications; the old key " +
		"material remains decryptable for already-encrypted data.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.11"},
	},
	Tags:    []string{"kms", "encryption", "rotation"},
	Scanner: "kms.CMKRotation",
}

func KMSCMKRotation(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, k := range g.ByType(awscol.KMSKeyType) {
		f := compliancekit.Finding{
			CheckID:  CheckKMSCMKRotation.ID,
			Severity: CheckKMSCMKRotation.Severity,
			Resource: k.Ref(),
			Tags:     CheckKMSCMKRotation.Tags,
		}
		// rotation_enabled is nil when N/A (AWS-managed, asymmetric,
		// or pending-deletion); skip those.
		rot, present := k.Attributes["rotation_enabled"]
		if !present || rot == nil {
			f.Status = compliancekit.StatusSkip
			f.Message = fmt.Sprintf("key %q: rotation not applicable", k.Name)
			findings = append(findings, f)
			continue
		}
		enabled, _ := rot.(bool)
		if enabled {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("key %q: rotation enabled", k.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("key %q: rotation NOT enabled", k.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckKMSNoPendingDeletion alerts on any customer-managed CMK in
// PendingDeletion state. Keys cannot be undeleted after the window
// closes; this catches an in-flight catastrophic delete before it
// is irreversible.
var CheckKMSNoPendingDeletion = compliancekit.Check{
	ID:           "aws-kms-no-pending-deletion",
	Title:        "Customer-managed KMS keys must not be pending deletion",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "aws",
	Service:      "kms",
	ResourceType: awscol.KMSKeyType,
	Description: "A KMS key in PendingDeletion state will be permanently " +
		"deleted at the end of its waiting window (7-30 days, default 30). " +
		"Once deleted, all data encrypted with that key becomes " +
		"undecryptable forever. This check catches in-flight deletes before " +
		"the window closes -- the cost of catching one false positive is " +
		"trivial, the cost of missing one true positive is catastrophic.",
	Remediation: "Cancel the deletion: 'aws kms cancel-key-deletion --key-id " +
		"<key-id>'. Then audit who scheduled it and why; that's almost " +
		"always an incident worth investigating.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.24", "A.8.13"},
		"cis-v8":   {"3.11", "11.2"},
	},
	Tags:    []string{"kms", "data-loss"},
	Scanner: "kms.NoPendingDeletion",
}

func KMSNoPendingDeletion(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, k := range g.ByType(awscol.KMSKeyType) {
		state, _ := k.Attributes["key_state"].(string)
		manager, _ := k.Attributes["key_manager"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckKMSNoPendingDeletion.ID,
			Severity: CheckKMSNoPendingDeletion.Severity,
			Resource: k.Ref(),
			Tags:     CheckKMSNoPendingDeletion.Tags,
		}
		if manager != "CUSTOMER" {
			f.Status = compliancekit.StatusSkip
			f.Message = fmt.Sprintf("key %q: AWS-managed (skip)", k.Name)
			findings = append(findings, f)
			continue
		}
		if state == "PendingDeletion" {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("key %q: PENDING DELETION (cancel before window closes)", k.Name)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("key %q: state=%s", k.Name, state)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckKMSCMKRotation, KMSCMKRotation)
	compliancekit.Register(CheckKMSNoPendingDeletion, KMSNoPendingDeletion)
}
