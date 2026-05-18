package gcp

import (
	"context"
	"fmt"

	"golang.org/x/oauth2/google"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

const providerName = "gcp"

// ProjectType is the resource type for the synthetic per-project
// anchor resource. Account-level / project-level checks (org-level
// admin MFA, audit logging configuration, etc.) attach findings
// here.
const ProjectType = "gcp.project"

// Options configures a Collector. All fields are optional.
type Options struct {
	// Projects is the explicit list of project IDs to scan. Empty
	// means "use the credential's default project."
	Projects []string

	// CredentialsOverride lets tests inject a fake credentials
	// struct. Production callers pass nil.
	CredentialsOverride *DefaultCredentials
}

// Collector fetches resources from one or more GCP projects.
//
// Construct via New. The zero value is not usable.
type Collector struct {
	creds    *google.Credentials
	projects []string
}

// New constructs a GCP Collector. Credentials are loaded eagerly so
// the doctor command can surface auth issues before any scan work.
func New(ctx context.Context, opts Options) (*Collector, error) {
	var creds *google.Credentials
	defaultProject := ""

	if opts.CredentialsOverride != nil {
		creds = opts.CredentialsOverride.Credentials
		defaultProject = opts.CredentialsOverride.ProjectID
	} else {
		dc, err := LoadCredentials(ctx)
		if err != nil {
			return nil, err
		}
		creds = dc.Credentials
		defaultProject = dc.ProjectID
	}

	projects := opts.Projects
	if len(projects) == 0 {
		if defaultProject == "" {
			return nil, fmt.Errorf("gcp: no projects specified and no default project in credentials (set 'gcloud config set project ...' or pass --projects)")
		}
		projects = []string{defaultProject}
	}

	return &Collector{
		creds:    creds,
		projects: projects,
	}, nil
}

// Name implements compliancekit.Collector. Stable across versions.
func (c *Collector) Name() string { return providerName }

// Projects returns the resolved project list. Public so the doctor
// command + tests can read it.
func (c *Collector) Projects() []string { return c.projects }

// Collect implements compliancekit.Collector. Emits per-project anchors
// plus everything the per-service collectors produce. Per-project
// errors surface as collect-error placeholders inside each service
// helper rather than aborting the entire scan.
func (c *Collector) Collect(ctx context.Context) ([]compliancekit.Resource, error) {
	out := []compliancekit.Resource{}
	for _, projectID := range c.projects {
		out = append(out, c.projectResource(projectID))
	}
	// All seven services are per-project; per-project errors
	// emit gcp.collect_error placeholders inside each helper
	// rather than aborting the entire scan.
	out = c.collectIAM(ctx, out)
	out = c.collectCompute(ctx, out)
	out = c.collectStorage(ctx, out)
	out = c.collectSQL(ctx, out)
	out = c.collectLogging(ctx, out)
	out = c.collectKMS(ctx, out)
	out = c.collectBigQuery(ctx, out)
	// v0.11: GKE for the K8s posture arc.
	out = c.collectGKE(ctx, out)
	return out, nil
}

// projectResource builds the synthetic per-project anchor. Carries
// the project ID stamped via cloudcommon (which sets account_id =
// projectID; for GCP the project IS the billing/scope identity).
func (c *Collector) projectResource(projectID string) compliancekit.Resource {
	r := compliancekit.Resource{
		ID:       fmt.Sprintf("gcp.project.%s", projectID),
		Type:     ProjectType,
		Name:     projectID,
		Provider: providerName,
		Attributes: map[string]any{
			"project_id": projectID,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: projectID,
		// Region empty: project is location-agnostic.
	})
	return r
}
