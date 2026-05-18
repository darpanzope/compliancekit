// Package tickets files external tickets (Jira, Linear) for findings
// whose remediation is manual. The package's job ends at "ticket
// created" — it does not poll for closure or sync state back into
// the evidence pack. That belongs to a later milestone (v0.17
// Notifications) if we keep the integration.
//
// Two providers ship at v0.15:
//   - Jira: REST API v3 create-issue, basic auth (email + API token).
//   - Linear: GraphQL issueCreate mutation, API key in Authorization
//     header.
//
// Both are gated by Options: empty credentials → the provider skips
// silently. The caller (CLI in phase 13) reads them from env vars
// JIRA_HOST / JIRA_EMAIL / JIRA_TOKEN / JIRA_PROJECT and
// LINEAR_API_KEY / LINEAR_TEAM_ID. We never read tokens from disk.
//
// Per ADR-011 ticketing is generate-only: this package only files
// tickets, it never closes them. An operator may want to file the
// same ticket repeatedly across runs; the caller is responsible for
// dedup if needed (look at the External-Ref props in poam.oscal.json
// for prior runs' refs).
package tickets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Ticket is the shared shape every provider accepts.
type Ticket struct {
	// Title is the one-line issue summary.
	Title string
	// Description is the body (markdown / wiki markup; provider-
	// specific rendering). Suitable to dump the entire snippet
	// Content + Notes into.
	Description string
	// Labels are provider-specific tag strings ("compliance",
	// "compliancekit", check tags, severity). Empty slice OK.
	Labels []string
	// Severity is mapped to provider-specific priority (Jira
	// priority field; Linear priority enum).
	Severity compliancekit.Severity
	// CheckID and ResourceID are stored on the ticket for cross-
	// reference back into compliancekit's evidence pack.
	CheckID    string
	ResourceID string
}

// Ref identifies a created ticket. Stored in the POA&M as the
// "external-ref" prop so future scans can correlate.
type Ref struct {
	Provider string // "jira" or "linear"
	Key      string // JIRA-1234 or LIN-456
	URL      string
}

// Provider is the contract every ticketing backend implements.
type Provider interface {
	Name() string
	// Configured reports whether the provider has enough config to
	// run. Used by callers to decide whether to skip silently when
	// credentials are missing.
	Configured() bool
	Create(ctx context.Context, t Ticket) (Ref, error)
}

// FileManualFindings is the high-level entry point the CLI calls.
// For every manual snippet (Risk=RiskManual) it builds a Ticket and
// asks each Configured provider to create it. Returns the union of
// successfully created Refs plus any per-provider errors (errors
// are returned as a slice so a single provider's failure doesn't
// abort the others).
func FileManualFindings(ctx context.Context, snippets []remediate.Snippet, providers []Provider) ([]Ref, []error) {
	var refs []Ref
	var errs []error
	for _, sn := range snippets {
		if sn.Risk != remediate.RiskManual {
			continue
		}
		t := Ticket{
			Title:       fmt.Sprintf("[compliancekit] Manual remediation: %s on %s", sn.CheckID, displayResource(sn)),
			Description: buildDescription(sn),
			Labels:      []string{"compliancekit", "compliance", string(sn.Risk)},
			CheckID:     sn.CheckID,
			ResourceID:  sn.Resource.ID,
		}
		for _, p := range providers {
			if !p.Configured() {
				continue
			}
			r, err := p.Create(ctx, t)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", p.Name(), err))
				continue
			}
			refs = append(refs, r)
		}
	}
	return refs, errs
}

func displayResource(sn remediate.Snippet) string {
	if sn.Resource.Name != "" {
		return sn.Resource.Name
	}
	return sn.Resource.ID
}

func buildDescription(sn remediate.Snippet) string {
	var sb bytes.Buffer
	fmt.Fprintf(&sb, "Compliance finding: `%s` on `%s`\n\n", sn.CheckID, sn.Resource.ID)
	if sn.Notes != "" {
		sb.WriteString(sn.Notes)
		sb.WriteString("\n\n")
	}
	if sn.Content != "" {
		sb.WriteString("```\n")
		sb.WriteString(sn.Content)
		sb.WriteString("\n```\n")
	}
	if len(sn.Refs) > 0 {
		sb.WriteString("\nReferences:\n")
		for _, r := range sn.Refs {
			fmt.Fprintf(&sb, "- %s\n", r)
		}
	}
	return sb.String()
}

// httpClient is the package-internal client; small connect/read
// timeouts so a misconfigured provider can't hang the run. Tests
// override via the providers' .client field.
var defaultClient = &http.Client{Timeout: 30 * time.Second}

// doJSON is a tiny helper providers share for posting JSON to an
// authenticated endpoint. Body in, body out. Returns ErrAuth on 401/403
// so the caller can render a helpful "check your credentials" message.
func doJSON(ctx context.Context, client *http.Client, method, url string, headers map[string]string, payload, target any) error {
	if client == nil {
		client = defaultClient
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%w: %s", ErrAuth, string(respBody))
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	if target == nil {
		return nil
	}
	return json.Unmarshal(respBody, target)
}

// ErrAuth indicates a 401/403 from the upstream — credentials are
// either missing or wrong. The CLI surfaces this with a clear message.
var ErrAuth = errors.New("tickets: authentication failed")
