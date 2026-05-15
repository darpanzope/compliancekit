package trivy

import "github.com/darpanzope/compliancekit/internal/ingest"

// redactSecret is the per-adapter alias for ingest.RedactSecret so
// adapter-internal callers (buildSecretFinding) keep their existing
// invocation shape. The shared implementation lives in the parent
// package per ADR-010 to guarantee one redaction algorithm across
// every adapter.
func redactSecret(raw string) string {
	return ingest.RedactSecret(raw)
}
