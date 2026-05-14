package gcp

import (
	"context"
	"fmt"

	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	"github.com/darpanzope/compliancekit/internal/core"
)

// CheckSQLNoPublicIP forbids public IPv4 on Cloud SQL instances.
// CIS GCP Foundations 6.6.
var CheckSQLNoPublicIP = core.Check{
	ID:           "gcp-sql-no-public-ip",
	Title:        "Cloud SQL instances must not have public IPv4",
	Severity:     core.SeverityHigh,
	Provider:     "gcp",
	Service:      "sql",
	ResourceType: gcpcol.SQLInstanceType,
	Description: "Cloud SQL with a public IPv4 address is reachable from the " +
		"internet, gated only by authorized-network IP allowlists and the " +
		"database engine's own auth. Use private IP (VPC peering) so the " +
		"instance has no public attack surface at all. CIS GCP Foundations " +
		"6.6.",
	Remediation: "Disable public IP: 'gcloud sql instances patch <name> " +
		"--no-assign-ip --network=projects/<project>/global/networks/<vpc>'. " +
		"Apps connect via private IP, the Cloud SQL Auth Proxy, or a " +
		"connector with IAM auth.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"3.3", "12.6"},
	},
	Tags:    []string{"sql", "network-exposure", "public-access"},
	Scanner: "sql.NoPublicIP",
}

func SQLNoPublicIP(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, inst := range g.ByType(gcpcol.SQLInstanceType) {
		ipv4, _ := inst.Attributes["ipv4_enabled"].(bool)
		f := core.Finding{
			CheckID:  CheckSQLNoPublicIP.ID,
			Severity: CheckSQLNoPublicIP.Severity,
			Resource: inst.Ref(),
			Tags:     CheckSQLNoPublicIP.Tags,
		}
		if ipv4 {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("instance %q: public IPv4 enabled", inst.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("instance %q: no public IPv4", inst.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckSQLAutomatedBackups requires automated backups on Cloud SQL.
// CIS GCP Foundations 6.7.
var CheckSQLAutomatedBackups = core.Check{
	ID:           "gcp-sql-automated-backups",
	Title:        "Cloud SQL instances must have automated backups enabled",
	Severity:     core.SeverityMedium,
	Provider:     "gcp",
	Service:      "sql",
	ResourceType: gcpcol.SQLInstanceType,
	Description: "Automated backups are the recovery path from data corruption, " +
		"accidental delete, and ransomware. Without them the operator is one " +
		"DROP TABLE away from total loss. CIS GCP Foundations 6.7.",
	Remediation: "Enable backups: 'gcloud sql instances patch <name> " +
		"--backup-start-time=03:00'. Pair with point-in-time recovery " +
		"(--enable-point-in-time-recovery for Postgres, --enable-bin-log " +
		"for MySQL) for sub-day RPO.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2", "CC7.4"},
		"iso27001": {"A.8.13", "A.8.14"},
		"cis-v8":   {"11.2", "11.3"},
	},
	Tags:    []string{"sql", "backup", "recovery"},
	Scanner: "sql.AutomatedBackups",
}

func SQLAutomatedBackups(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, inst := range g.ByType(gcpcol.SQLInstanceType) {
		enabled, _ := inst.Attributes["backups_enabled"].(bool)
		f := core.Finding{
			CheckID:  CheckSQLAutomatedBackups.ID,
			Severity: CheckSQLAutomatedBackups.Severity,
			Resource: inst.Ref(),
			Tags:     CheckSQLAutomatedBackups.Tags,
		}
		if enabled {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("instance %q: automated backups enabled", inst.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("instance %q: automated backups disabled", inst.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckSQLDeletionProtection requires deletion protection on Cloud
// SQL instances. Last-line guard against `terraform destroy` /
// console fat-fingers.
var CheckSQLDeletionProtection = core.Check{
	ID:           "gcp-sql-deletion-protection",
	Title:        "Cloud SQL instances must have deletion protection enabled",
	Severity:     core.SeverityMedium,
	Provider:     "gcp",
	Service:      "sql",
	ResourceType: gcpcol.SQLInstanceType,
	Description: "Deletion protection blocks accidental instance deletion at the " +
		"API. It's the last guard between a stray Terraform destroy or " +
		"console click and total loss of the production database (along " +
		"with the automated backups, which live inside the instance). " +
		"Cheap to enable, hard to recover without.",
	Remediation: "'gcloud sql instances patch <name> --deletion-protection'. " +
		"For Terraform-managed fleets, set deletion_protection = true on " +
		"the google_sql_database_instance resource.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2", "CC7.4"},
		"iso27001": {"A.8.13"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"sql", "data-protection", "recovery"},
	Scanner: "sql.DeletionProtection",
}

func SQLDeletionProtection(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, inst := range g.ByType(gcpcol.SQLInstanceType) {
		on, _ := inst.Attributes["deletion_protection_enabled"].(bool)
		f := core.Finding{
			CheckID:  CheckSQLDeletionProtection.ID,
			Severity: CheckSQLDeletionProtection.Severity,
			Resource: inst.Ref(),
			Tags:     CheckSQLDeletionProtection.Tags,
		}
		if on {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("instance %q: deletion protection enabled", inst.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("instance %q: deletion protection disabled", inst.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckSQLNoPublicIP, SQLNoPublicIP)
	core.Register(CheckSQLAutomatedBackups, SQLAutomatedBackups)
	core.Register(CheckSQLDeletionProtection, SQLDeletionProtection)
}
