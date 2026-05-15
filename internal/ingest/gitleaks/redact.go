package gitleaks

import "github.com/darpanzope/compliancekit/internal/ingest"

// redactSecret aliases ingest.RedactSecret (ADR-010: one redaction
// algorithm across every adapter).
func redactSecret(raw string) string {
	return ingest.RedactSecret(raw)
}
