package gitleaks

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// redactSecret implements the ADR-010 secret-handling policy: the
// raw captured credential never appears in compliancekit output.
// Long secrets emit first 4 + "..." + last 4 to support visual
// correlation; short secrets emit a SHA-256 hash prefix.
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
