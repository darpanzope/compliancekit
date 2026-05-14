package gcp

import (
	"context"
	"fmt"
	"sort"
	"strings"

	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	"github.com/darpanzope/compliancekit/internal/core"
)

// publicBQSpecialGroups are dataset-access special groups that
// open the dataset to the public. allAuthenticatedUsers is the
// hardest fail (any logged-in Google account); allUsers (anonymous)
// only ever appears via the iamMember path. CIS GCP 7.x guidance
// flags both.
var publicBQSpecialGroups = map[string]bool{
	"allAuthenticatedUsers": true,
}

// publicBQIamMembers are the IAM-member strings BigQuery uses to
// surface anonymous + public-authenticated access. iamMember:
// "allUsers" is the catastrophic one (anonymous internet access).
var publicBQIamMembers = map[string]bool{
	"allUsers":              true,
	"allAuthenticatedUsers": true,
}

// CheckBQNoPublicDatasets forbids public access on BigQuery
// datasets. allUsers or allAuthenticatedUsers in the dataset's
// access list exposes every table in the dataset.
var CheckBQNoPublicDatasets = core.Check{
	ID:           "gcp-bigquery-no-public-datasets",
	Title:        "BigQuery datasets must not grant access to allUsers/allAuthenticatedUsers",
	Severity:     core.SeverityCritical,
	Provider:     "gcp",
	Service:      "bigquery",
	ResourceType: gcpcol.BigQueryDatasetType,
	Description: "Granting any role to allUsers or allAuthenticatedUsers on a " +
		"BigQuery dataset exposes every table, view, and routine inside it. " +
		"allUsers is the anonymous-internet grant; allAuthenticatedUsers is " +
		"any Google account. Both are common shapes of public-data leak.",
	Remediation: "Identify offending access entries: 'bq show " +
		"--format=prettyjson <project>:<dataset>' and remove any access " +
		"entry where specialGroup or iamMember is allUsers or " +
		"allAuthenticatedUsers. Replace with named groups or service " +
		"accounts scoped to the actual consumers.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.3", "A.5.10"},
		"cis-v8":   {"3.3", "3.11"},
	},
	Tags:    []string{"bigquery", "data-exposure", "public-access"},
	Scanner: "bigquery.NoPublicDatasets",
}

func BQNoPublicDatasets(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(gcpcol.BigQueryDatasetType) {
		access, _ := d.Attributes["access"].([]map[string]any)

		var hits []string
		for _, a := range access {
			sg, _ := a["special_group"].(string)
			im, _ := a["iam_member"].(string)
			if publicBQSpecialGroups[sg] {
				hits = append(hits, "specialGroup:"+sg)
			}
			if publicBQIamMembers[im] {
				hits = append(hits, "iamMember:"+im)
			}
		}
		sort.Strings(hits)

		f := core.Finding{
			CheckID:  CheckBQNoPublicDatasets.ID,
			Severity: CheckBQNoPublicDatasets.Severity,
			Resource: d.Ref(),
			Tags:     CheckBQNoPublicDatasets.Tags,
		}
		if len(hits) == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("dataset %q: no public access", d.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("dataset %q: public access via %s", d.Name, strings.Join(hits, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckBQNoAllAuthenticated is a focused variant that flags only
// allAuthenticatedUsers on dataset Access. Separate from the
// public-datasets check so allUsers (critical) and
// allAuthenticatedUsers (high) can carry different severities
// and frameworks emphasis can differ.
var CheckBQNoAllAuthenticated = core.Check{
	ID:           "gcp-bigquery-no-all-authenticated-users",
	Title:        "BigQuery datasets must not grant access to allAuthenticatedUsers",
	Severity:     core.SeverityHigh,
	Provider:     "gcp",
	Service:      "bigquery",
	ResourceType: gcpcol.BigQueryDatasetType,
	Description: "Even when public anonymous access (allUsers) is denied, " +
		"granting allAuthenticatedUsers exposes the dataset to every " +
		"Google account on the internet, not just your organization. This " +
		"is rarely the intent and is a common path to credential-stuffing " +
		"data exfiltration. CIS GCP 7.1 / 7.2 prescribe explicit member " +
		"lists instead.",
	Remediation: "Remove the allAuthenticatedUsers grant: 'bq remove-iam-policy-binding " +
		"<project>:<dataset> --member=allAuthenticatedUsers --role=<role>'. " +
		"Replace with an explicit group or service-account binding.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.10", "A.8.3"},
		"cis-v8":   {"3.3"},
	},
	Tags:    []string{"bigquery", "data-exposure", "public-access"},
	Scanner: "bigquery.NoAllAuthenticated",
}

func BQNoAllAuthenticated(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(gcpcol.BigQueryDatasetType) {
		access, _ := d.Attributes["access"].([]map[string]any)

		offenders := 0
		for _, a := range access {
			sg, _ := a["special_group"].(string)
			im, _ := a["iam_member"].(string)
			if sg == "allAuthenticatedUsers" || im == "allAuthenticatedUsers" {
				offenders++
			}
		}

		f := core.Finding{
			CheckID:  CheckBQNoAllAuthenticated.ID,
			Severity: CheckBQNoAllAuthenticated.Severity,
			Resource: d.Ref(),
			Tags:     CheckBQNoAllAuthenticated.Tags,
		}
		if offenders == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("dataset %q: no allAuthenticatedUsers grant", d.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("dataset %q: %d allAuthenticatedUsers grant(s)", d.Name, offenders)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckBQDefaultCMEK requires datasets to configure a default
// CMEK so new tables inherit customer-managed encryption.
var CheckBQDefaultCMEK = core.Check{
	ID:           "gcp-bigquery-default-cmek",
	Title:        "BigQuery datasets must have a default CMEK configured",
	Severity:     core.SeverityMedium,
	Provider:     "gcp",
	Service:      "bigquery",
	ResourceType: gcpcol.BigQueryDatasetType,
	Description: "BigQuery encrypts data at rest by default with Google-managed " +
		"keys. Setting a default CMEK at the dataset level ensures every " +
		"newly-created table inherits a customer-managed key, which is " +
		"required when downstream controls (audit, key rotation, BYOK, key " +
		"destruction for crypto-shredding) need to apply uniformly across " +
		"tables in a dataset.",
	Remediation: "'bq update --default_kms_key=projects/<proj>/locations/<loc>/keyRings/<ring>/cryptoKeys/<key> " +
		"<project>:<dataset>'. Grant the BigQuery service account " +
		"(bq-<project-number>@bigquery-encryption.iam.gserviceaccount.com) " +
		"the cloudkms.cryptoKeyEncrypterDecrypter role on the key.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.11"},
	},
	Tags:    []string{"bigquery", "encryption", "cmek"},
	Scanner: "bigquery.DefaultCMEK",
}

func BQDefaultCMEK(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, d := range g.ByType(gcpcol.BigQueryDatasetType) {
		on, _ := d.Attributes["default_cmek"].(bool)
		f := core.Finding{
			CheckID:  CheckBQDefaultCMEK.ID,
			Severity: CheckBQDefaultCMEK.Severity,
			Resource: d.Ref(),
			Tags:     CheckBQDefaultCMEK.Tags,
		}
		if on {
			key, _ := d.Attributes["default_cmek_key"].(string)
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("dataset %q: default CMEK %s", d.Name, lastSegment(key))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("dataset %q: no default CMEK (Google-managed encryption only)", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// lastSegment returns the last "/"-separated piece of a KMS key
// path so messages stay compact while still identifying the key.
func lastSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func init() {
	core.Register(CheckBQNoPublicDatasets, BQNoPublicDatasets)
	core.Register(CheckBQNoAllAuthenticated, BQNoAllAuthenticated)
	core.Register(CheckBQDefaultCMEK, BQDefaultCMEK)
}
