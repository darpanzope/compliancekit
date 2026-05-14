package gcp

import (
	"context"
	"fmt"

	"golang.org/x/oauth2/google"
)

// DefaultCredentials wraps google.FindDefaultCredentials so the
// collector can resolve a project ID and credentials in one call.
// The returned ProjectID is the credential's default project,
// which the doctor command + the no-explicit-projects scan path
// use.
//
// scopes is the OAuth scope list; the SDK clients add their own
// per-service scopes when they need finer-grained access, so a
// reasonable default at the entry point is the "cloud-platform"
// catch-all that every GCP API accepts.
type DefaultCredentials struct {
	ProjectID   string
	Credentials *google.Credentials
}

// LoadCredentials resolves credentials via the standard ADC chain.
// Returns an error rather than panicking on missing credentials so
// the doctor command can surface a clear message.
func LoadCredentials(ctx context.Context) (DefaultCredentials, error) {
	const scope = "https://www.googleapis.com/auth/cloud-platform"
	creds, err := google.FindDefaultCredentials(ctx, scope)
	if err != nil {
		return DefaultCredentials{}, fmt.Errorf("gcp: load default credentials: %w (set GOOGLE_APPLICATION_CREDENTIALS or run 'gcloud auth application-default login')", err)
	}
	return DefaultCredentials{
		ProjectID:   creds.ProjectID,
		Credentials: creds,
	}, nil
}
