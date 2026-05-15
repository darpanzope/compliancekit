package trivy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// redactSecret converts a captured secret value into a non-reversible
// fingerprint suitable for storage in core.Finding.Secret. The
// fingerprint preserves enough character to let an operator
// correlate findings across runs ("the same secret hit twice")
// without making the credential itself recoverable from the
// evidence pack.
//
// Strategy: when the secret is long enough to anchor visually, emit
// first 4 + "..." + last 4 chars; otherwise emit a SHA-256 hash
// prefix. Empty input returns "".
//
// ADR-010 (v0.14 Phase 8) codifies the policy: adapters MUST NOT
// emit raw secret values into Findings. This function is the
// canonical entrypoint; tests verify the property.
func redactSecret(raw string) string {
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
