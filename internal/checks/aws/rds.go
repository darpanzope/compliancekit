package aws

import (
	"context"
	"fmt"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/internal/core"
)

// CheckRDSEncrypted requires storage encryption at rest. CIS 2.3.1.
var CheckRDSEncrypted = core.Check{
	ID:           "aws-rds-encrypted",
	Title:        "RDS DB instances must be encrypted at rest",
	Severity:     core.SeverityHigh,
	Provider:     "aws",
	Service:      "rds",
	ResourceType: awscol.RDSInstanceType,
	Description: "RDS storage encryption at rest is a checkbox at creation " +
		"time that cannot be retroactively flipped on an existing instance. " +
		"Without it, RDS snapshots, replicas, and underlying storage carry " +
		"unencrypted customer data. CIS AWS Foundations 2.3.1.",
	Remediation: "Encryption cannot be enabled in-place. Snapshot the instance, " +
		"copy the snapshot with --kms-key-id specified, restore the encrypted " +
		"snapshot to a new instance, then cut over via DNS or connection " +
		"strings. For new instances always set --storage-encrypted at " +
		"create-time.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.11"},
	},
	Tags:    []string{"rds", "encryption", "data-at-rest"},
	Scanner: "rds.Encrypted",
}

func RDSEncrypted(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, db := range g.ByType(awscol.RDSInstanceType) {
		encrypted, _ := db.Attributes["storage_encrypted"].(bool)
		f := core.Finding{
			CheckID:  CheckRDSEncrypted.ID,
			Severity: CheckRDSEncrypted.Severity,
			Resource: db.Ref(),
			Tags:     CheckRDSEncrypted.Tags,
		}
		if encrypted {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("RDS %q: storage encrypted", db.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("RDS %q: storage NOT encrypted", db.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckRDSNotPublic forbids public DB instances. CIS 2.3.3.
var CheckRDSNotPublic = core.Check{
	ID:           "aws-rds-not-publicly-accessible",
	Title:        "RDS DB instances must not be publicly accessible",
	Severity:     core.SeverityCritical,
	Provider:     "aws",
	Service:      "rds",
	ResourceType: awscol.RDSInstanceType,
	Description: "A publicly accessible RDS instance receives a public DNS " +
		"name and is reachable from the internet (subject to security group " +
		"rules). Combined with a permissive SG, this is the most common path " +
		"to a database breach. Production databases belong in private subnets, " +
		"reachable only from application security groups inside the VPC. CIS " +
		"AWS Foundations 2.3.3.",
	Remediation: "Set the instance to private: 'aws rds modify-db-instance " +
		"--db-instance-identifier <name> --no-publicly-accessible " +
		"--apply-immediately'. Update the security group to allow ingress " +
		"only from the application tier.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.21"},
		"cis-v8":   {"4.4", "12.2"},
	},
	Tags:    []string{"rds", "network", "exposure"},
	Scanner: "rds.NotPublic",
}

func RDSNotPublic(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, db := range g.ByType(awscol.RDSInstanceType) {
		public, _ := db.Attributes["publicly_accessible"].(bool)
		f := core.Finding{
			CheckID:  CheckRDSNotPublic.ID,
			Severity: CheckRDSNotPublic.Severity,
			Resource: db.Ref(),
			Tags:     CheckRDSNotPublic.Tags,
		}
		if !public {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("RDS %q: not publicly accessible", db.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("RDS %q: publicly accessible", db.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// minBackupRetentionDays is the minimum acceptable retention. CIS
// recommends >= 7.
const minBackupRetentionDays = 7

// CheckRDSBackupRetention requires automated backups with >= 7 days
// retention. CIS doesn't pin a hard number but 7 is the
// industry-standard floor.
var CheckRDSBackupRetention = core.Check{
	ID:           "aws-rds-backup-retention",
	Title:        "RDS DB instances must have backup retention >= 7 days",
	Severity:     core.SeverityMedium,
	Provider:     "aws",
	Service:      "rds",
	ResourceType: awscol.RDSInstanceType,
	Description: "Automated backups are RDS's point-in-time recovery mechanism. " +
		"BackupRetentionPeriod=0 disables them entirely; values < 7 days " +
		"reduce the recovery window below the industry-standard floor for " +
		"production data.",
	Remediation: "Set retention: 'aws rds modify-db-instance --db-instance-identifier " +
		"<name> --backup-retention-period 7 --apply-immediately'. For " +
		"production-tier data consider 30 days.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6", "A1.2"},
		"iso27001": {"A.8.13"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"rds", "backup", "recovery"},
	Scanner: "rds.BackupRetention",
}

func RDSBackupRetention(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, db := range g.ByType(awscol.RDSInstanceType) {
		days, _ := db.Attributes["backup_retention_period"].(int)
		f := core.Finding{
			CheckID:  CheckRDSBackupRetention.ID,
			Severity: CheckRDSBackupRetention.Severity,
			Resource: db.Ref(),
			Tags:     CheckRDSBackupRetention.Tags,
		}
		if days >= minBackupRetentionDays {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("RDS %q: backup retention %d days", db.Name, days)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("RDS %q: backup retention %d days (want >= %d)",
				db.Name, days, minBackupRetentionDays)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckRDSDeletionProtection requires DeletionProtection=true. CIS
// 2.3.2 prescribes this for production instances.
var CheckRDSDeletionProtection = core.Check{
	ID:           "aws-rds-deletion-protection",
	Title:        "RDS DB instances must have deletion protection enabled",
	Severity:     core.SeverityMedium,
	Provider:     "aws",
	Service:      "rds",
	ResourceType: awscol.RDSInstanceType,
	Description: "Deletion protection is a guard against the worst-case " +
		"operator-error / compromised-credential outcome: a single 'aws rds " +
		"delete-db-instance' call destroying customer data. With protection " +
		"on, the call fails with an explicit error and forces the operator " +
		"to disable protection first. CIS AWS Foundations 2.3.2.",
	Remediation: "Enable: 'aws rds modify-db-instance --db-instance-identifier " +
		"<name> --deletion-protection --apply-immediately'. Set as a default " +
		"in IaC modules so new instances inherit it.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.13"},
		"cis-v8":   {"3.3", "5.4"},
	},
	Tags:    []string{"rds", "lifecycle", "guard-rail"},
	Scanner: "rds.DeletionProtection",
}

func RDSDeletionProtection(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, db := range g.ByType(awscol.RDSInstanceType) {
		protected, _ := db.Attributes["deletion_protection"].(bool)
		f := core.Finding{
			CheckID:  CheckRDSDeletionProtection.ID,
			Severity: CheckRDSDeletionProtection.Severity,
			Resource: db.Ref(),
			Tags:     CheckRDSDeletionProtection.Tags,
		}
		if protected {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("RDS %q: deletion protection enabled", db.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("RDS %q: deletion protection disabled", db.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckRDSEncrypted, RDSEncrypted)
	core.Register(CheckRDSNotPublic, RDSNotPublic)
	core.Register(CheckRDSBackupRetention, RDSBackupRetention)
	core.Register(CheckRDSDeletionProtection, RDSDeletionProtection)
}
