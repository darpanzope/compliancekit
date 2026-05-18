// Package gitleaks implements a native-JSON ingest adapter for
// gitleaks (gitleaks/gitleaks) output. v0.14+. gitleaks scans git
// history (or a filesystem) for leaked credentials. Every match is
// projected into a compliancekit.Finding with a populated compliancekit.Secret block
// whose Fingerprint is REDACTED — the raw secret value never lands
// in the Finding (ADR-010).
//
// Self-registers as `--format=gitleaks-json`.
package gitleaks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/ingest"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

type adapter struct{}

func (adapter) Format() string { return "gitleaks-json" }
func (adapter) Description() string {
	return "gitleaks native JSON — git history + filesystem secret detection (always redacted)"
}

// Ingest decodes a gitleaks JSON report (top-level array of findings).
// Each finding becomes a compliancekit Finding with compliancekit.Secret
// populated; raw secret values are redacted before storage.
func (adapter) Ingest(ctx context.Context, r io.Reader, opts ingest.Options) (ingest.Result, error) {
	var matches []match
	if err := json.NewDecoder(r).Decode(&matches); err != nil {
		return ingest.Result{}, fmt.Errorf("decode gitleaks json: %w", err)
	}
	if opts.Provenance.IngestedAt.IsZero() {
		opts.Provenance.IngestedAt = time.Now().UTC()
	}

	out := ingest.Result{}
	for _, m := range matches {
		if err := ctx.Err(); err != nil {
			return ingest.Result{}, err
		}
		f, phantom := buildSecretFinding(m, opts)
		out.Findings = append(out.Findings, f)
		if phantom != nil {
			out.Resources = append(out.Resources, *phantom)
		}
	}
	if len(out.Findings) == 0 {
		out.Warnings = append(out.Warnings, "gitleaks report had zero findings")
	}
	return out, nil
}

func buildSecretFinding(m match, opts ingest.Options) (compliancekit.Finding, *compliancekit.Resource) {
	subject, phantom := resolveSubject(m, opts)
	severity := severityFromGitleaks(m.RuleID)

	return compliancekit.Finding{
		CheckID:  "ingest.gitleaks." + m.RuleID,
		Status:   compliancekit.StatusFail,
		Severity: severity,
		Resource: subject,
		Message:  fmt.Sprintf("%s detected in %s", m.RuleID, m.File),
		Tags:     []string{"secret", strings.ToLower(m.RuleID)},
		Secret: &compliancekit.Secret{
			RuleID:      m.RuleID,
			RuleName:    m.Description,
			Fingerprint: redactSecret(m.Secret),
			File:        m.File,
			Line:        m.StartLine,
			Commit:      m.Commit,
			Author:      m.Author,
			Email:       m.Email,
			Date:        m.Date,
		},
		Timestamp: opts.Provenance.IngestedAt,
		Source: &compliancekit.Source{
			Type:        "ingest",
			Tool:        "gitleaks",
			ToolVersion: opts.Provenance.ToolVersion,
			Format:      "gitleaks-json",
			File:        opts.Provenance.File,
		},
	}, phantom
}

func resolveSubject(m match, opts ingest.Options) (compliancekit.ResourceRef, *compliancekit.Resource) {
	id := "ingest://gitleaks/" + m.File
	if m.StartLine > 0 {
		id += fmt.Sprintf("#L%d", m.StartLine)
	}
	if opts.Graph != nil {
		if existing, ok := opts.Graph.ByID(id); ok {
			return compliancekit.ResourceRef{
				ID: existing.ID, Type: existing.Type, Name: existing.Name, Provider: existing.Provider,
			}, nil
		}
	}
	phantom := compliancekit.Resource{
		ID:       id,
		Type:     "secret.file",
		Name:     m.File,
		Provider: "ingest",
		Attributes: map[string]any{
			"ingest_source": "gitleaks",
			"commit":        m.Commit,
			"author":        m.Author,
			"date":          m.Date,
		},
	}
	return compliancekit.ResourceRef{
		ID: phantom.ID, Type: phantom.Type, Name: phantom.Name, Provider: phantom.Provider,
	}, &phantom
}

// severityFromGitleaks heuristically maps a rule ID to a severity.
// gitleaks does not ship per-rule severity in its output, so we
// classify by token: credentials with key/token/secret in the name
// land at high; tokens with "test" or "example" land at medium;
// everything else defaults to medium.
func severityFromGitleaks(ruleID string) compliancekit.Severity {
	r := strings.ToLower(ruleID)
	switch {
	case strings.Contains(r, "private-key"),
		strings.Contains(r, "aws-access-key"),
		strings.Contains(r, "stripe"),
		strings.Contains(r, "gcp-service-account"),
		strings.Contains(r, "rsa"),
		strings.Contains(r, "ssh"):
		return compliancekit.SeverityCritical
	case strings.Contains(r, "token"),
		strings.Contains(r, "secret"),
		strings.Contains(r, "password"),
		strings.Contains(r, "api-key"):
		return compliancekit.SeverityHigh
	}
	return compliancekit.SeverityMedium
}

func init() {
	ingest.Register(adapter{})
}
