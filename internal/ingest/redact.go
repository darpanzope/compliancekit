package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// RedactSecret is the canonical helper every ingest adapter MUST
// use before writing a captured credential value into a Finding's
// Secret.Fingerprint field. The function is intentionally simple
// and irreversible:
//
//   - Empty input → empty output.
//   - 16+ characters → first 4 + "..." + last 4. Preserves enough
//     character for operators to visually correlate the same secret
//     across runs without making the credential recoverable.
//   - <16 characters → "sha256:" + first 12 hex chars of SHA-256(raw).
//     Short secrets that survive first4+last4 redaction would leak
//     too much; we collapse them to a hash so the fingerprint is
//     stable but the original is not recoverable.
//
// Per ADR-010 (v0.14): no other transformation of a captured secret
// is permitted in compliancekit. Adapters MUST NOT write the raw
// value into any Finding field; MUST NOT log the raw value;
// SHOULD prefer reading the secret value from the producing tool's
// "fingerprint" or "hash" output where available rather than reading
// the raw match at all.
//
// The function is exported so adapter packages and downstream
// consumers can rely on a single redaction algorithm — drift
// across adapter implementations is the most likely failure mode
// for the redaction property.
func RedactSecret(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if len(raw) >= 16 {
		return raw[:4] + "..." + raw[len(raw)-4:]
	}
	h := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(h[:])[:12]
}
