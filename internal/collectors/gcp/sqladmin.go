package gcp

import (
	"context"
	"fmt"

	sqladmin "google.golang.org/api/sqladmin/v1"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// SQLInstanceType is the resource type emitted per Cloud SQL
// instance. Cloud SQL is the REST-only SDK in the GCP family, so
// we use google.golang.org/api/sqladmin/v1 rather than the
// cloud.google.com/go/<svc>/apiv1 grpc clients used by IAM,
// Compute, and GCS.
const SQLInstanceType = "gcp.sql.instance"

// collectSQL enumerates Cloud SQL DatabaseInstances per project.
// Per-project errors emit a placeholder and continue.
func (c *Collector) collectSQL(ctx context.Context, out []core.Resource) []core.Resource {
	for _, projectID := range c.projects {
		updated, err := c.collectSQLForProject(ctx, projectID, out)
		if err != nil {
			out = append(out, c.projectErrorResource(projectID, "sql", err))
			continue
		}
		out = updated
	}
	return out
}

func (c *Collector) collectSQLForProject(ctx context.Context, projectID string, out []core.Resource) ([]core.Resource, error) {
	svc, err := sqladmin.NewService(ctx, c.clientOption())
	if err != nil {
		return out, fmt.Errorf("new sql admin service: %w", err)
	}

	err = svc.Instances.List(projectID).Pages(ctx, func(resp *sqladmin.InstancesListResponse) error {
		for _, inst := range resp.Items {
			out = append(out, c.sqlInstanceResource(projectID, inst))
		}
		return nil
	})
	if err != nil {
		return out, fmt.Errorf("list sql instances: %w", err)
	}
	return out, nil
}

func (c *Collector) sqlInstanceResource(projectID string, inst *sqladmin.DatabaseInstance) core.Resource {
	ipv4Enabled := false
	requireSSL := false
	if inst.Settings != nil && inst.Settings.IpConfiguration != nil {
		ipv4Enabled = inst.Settings.IpConfiguration.Ipv4Enabled
		requireSSL = inst.Settings.IpConfiguration.RequireSsl
	}
	backupsEnabled := false
	pitrEnabled := false
	binaryLogEnabled := false
	if inst.Settings != nil && inst.Settings.BackupConfiguration != nil {
		backupsEnabled = inst.Settings.BackupConfiguration.Enabled
		pitrEnabled = inst.Settings.BackupConfiguration.PointInTimeRecoveryEnabled
		binaryLogEnabled = inst.Settings.BackupConfiguration.BinaryLogEnabled
	}
	deletionProtection := false
	if inst.Settings != nil {
		deletionProtection = inst.Settings.DeletionProtectionEnabled
	}
	r := core.Resource{
		ID:       fmt.Sprintf("gcp.sql.instance.%s.%s", projectID, inst.Name),
		Type:     SQLInstanceType,
		Name:     inst.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"instance_name":               inst.Name,
			"database_version":            inst.DatabaseVersion,
			"instance_type":               inst.InstanceType,
			"region":                      inst.Region,
			"gce_zone":                    inst.GceZone,
			"ipv4_enabled":                ipv4Enabled,
			"require_ssl":                 requireSSL,
			"backups_enabled":             backupsEnabled,
			"point_in_time_recovery":      pitrEnabled,
			"binary_log_enabled":          binaryLogEnabled,
			"deletion_protection_enabled": deletionProtection,
			"backend_type":                inst.BackendType,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: projectID,
		Region:    inst.Region,
	})
	return r
}
