package gcp

import (
	"context"
	"fmt"

	bigquery "google.golang.org/api/bigquery/v2"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// BigQueryDatasetType holds BigQuery datasets. One resource per
// dataset per project. CMEK + public-access checks read this.
const BigQueryDatasetType = "gcp.bigquery.dataset"

// collectBigQuery enumerates BigQuery datasets per project. The
// List endpoint returns a lightweight summary without ACLs or
// CMEK, so each dataset is then fetched in detail. Per-project
// errors emit a placeholder and continue. Per-dataset Get failures
// are captured as a collect_error attribute on the listed
// dataset rather than aborting the whole project.
func (c *Collector) collectBigQuery(ctx context.Context, out []compliancekit.Resource) []compliancekit.Resource {
	for _, projectID := range c.projects {
		updated, err := c.collectBigQueryForProject(ctx, projectID, out)
		if err != nil {
			out = append(out, c.projectErrorResource(projectID, "bigquery", err))
			continue
		}
		out = updated
	}
	return out
}

func (c *Collector) collectBigQueryForProject(ctx context.Context, projectID string, out []compliancekit.Resource) ([]compliancekit.Resource, error) {
	svc, err := bigquery.NewService(ctx, c.clientOption())
	if err != nil {
		return out, fmt.Errorf("new bigquery service: %w", err)
	}

	err = svc.Datasets.List(projectID).All(true).Pages(ctx, func(resp *bigquery.DatasetList) error {
		for _, d := range resp.Datasets {
			if d.DatasetReference == nil {
				continue
			}
			full, err := svc.Datasets.Get(projectID, d.DatasetReference.DatasetId).Context(ctx).Do()
			if err != nil {
				out = append(out, c.bigQueryDatasetErrorResource(projectID, d, err))
				continue
			}
			out = append(out, c.bigQueryDatasetResource(projectID, full))
		}
		return nil
	})
	if err != nil {
		return out, fmt.Errorf("list datasets: %w", err)
	}
	return out, nil
}

func (c *Collector) bigQueryDatasetResource(projectID string, d *bigquery.Dataset) compliancekit.Resource {
	datasetID := ""
	if d.DatasetReference != nil {
		datasetID = d.DatasetReference.DatasetId
	}

	cmekKey := ""
	if d.DefaultEncryptionConfiguration != nil {
		cmekKey = d.DefaultEncryptionConfiguration.KmsKeyName
	}

	access := []map[string]any{}
	for _, a := range d.Access {
		entry := map[string]any{
			"role":          a.Role,
			"special_group": a.SpecialGroup,
			"user_by_email": a.UserByEmail,
			"group_email":   a.GroupByEmail,
			"domain":        a.Domain,
			"iam_member":    a.IamMember,
		}
		access = append(access, entry)
	}

	r := compliancekit.Resource{
		ID:       fmt.Sprintf("gcp.bigquery.dataset.%s.%s", projectID, datasetID),
		Type:     BigQueryDatasetType,
		Name:     datasetID,
		Provider: providerName,
		Attributes: map[string]any{
			"dataset_id":       datasetID,
			"location":         d.Location,
			"description":      d.Description,
			"access":           access,
			"default_cmek":     cmekKey != "",
			"default_cmek_key": cmekKey,
			"labels":           d.Labels,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: projectID,
		Region:    d.Location,
	})
	return r
}

func (c *Collector) bigQueryDatasetErrorResource(projectID string, listed *bigquery.DatasetListDatasets, err error) compliancekit.Resource {
	datasetID := ""
	if listed.DatasetReference != nil {
		datasetID = listed.DatasetReference.DatasetId
	}
	r := compliancekit.Resource{
		ID:       fmt.Sprintf("gcp.bigquery.dataset.%s.%s", projectID, datasetID),
		Type:     BigQueryDatasetType,
		Name:     datasetID,
		Provider: providerName,
		Attributes: map[string]any{
			"dataset_id":    datasetID,
			"location":      listed.Location,
			"collect_error": err.Error(),
			"access":        []map[string]any{},
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: projectID,
		Region:    listed.Location,
	})
	return r
}
