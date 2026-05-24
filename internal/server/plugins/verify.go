package plugins

// v1.13 phase 3 — manifest signature verification.
//
// The daemon refuses to load unsigned plugins by default. Operators
// opt out with --allow-unsigned-plugins for local development.
//
// Signature convention: alongside the plugin's manifest.yaml lives a
// signature.sig (base64-encoded raw signature bytes) produced by:
//
//   cosign sign-blob --output-signature signature.sig manifest.yaml
//
// The operator points the daemon at the matching public-key PEM via
// --plugin-pubkey or the CK_PLUGIN_PUBKEY env var. Both ECDSA P-256
// and Ed25519 keys are accepted — cosign sign-blob defaults to ECDSA.
//
// Keyless (Sigstore Fulcio + Rekor) verification is a v1.13.x
// follow-up; the v1.13.0 daemon's plugin-trust story is pinned-key
// only because that's what self-hosted operators reach for first.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pubplugin "github.com/darpanzope/compliancekit/pkg/compliancekit/plugin"
)

// ErrNoSignatureFile is returned when a plugin's directory has no
// signature.sig alongside its manifest.
var ErrNoSignatureFile = errors.New("plugins: signature.sig missing")

// ErrUnsupportedKey is returned when the operator's pubkey PEM
// decodes to a type the verifier doesn't handle (only ECDSA P-256
// and Ed25519 are supported at v1.13).
var ErrUnsupportedKey = errors.New("plugins: pubkey type unsupported (want ECDSA P-256 or Ed25519)")

// CosignVerifier checks plugin signatures against a fixed operator-
// supplied public key. One verifier per running daemon — the same
// trust root applies to every installed plugin.
type CosignVerifier struct {
	pubkey crypto.PublicKey
}

// NewCosignVerifier parses pemBytes as a PEM-encoded public key
// (PKIX SubjectPublicKeyInfo) and returns a verifier ready for use.
// Caller's responsibility to source the PEM securely — the daemon
// reads it from disk at boot.
func NewCosignVerifier(pemBytes []byte) (*CosignVerifier, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("plugins: pubkey is not PEM-encoded")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("plugins: parse pubkey: %w", err)
	}
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if k.Curve.Params().Name != "P-256" {
			return nil, fmt.Errorf("%w: ECDSA curve %s", ErrUnsupportedKey, k.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		// ok
	default:
		return nil, ErrUnsupportedKey
	}
	return &CosignVerifier{pubkey: key}, nil
}

// NewCosignVerifierFromFile is a convenience wrapper that reads pem
// bytes from path.
func NewCosignVerifierFromFile(path string) (*CosignVerifier, error) {
	body, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("plugins: read pubkey: %w", err)
	}
	return NewCosignVerifier(body)
}

// Verify implements SignatureVerifier. Reads <pluginDir>/signature.sig
// + recomputes SHA-256(manifest.yaml) and validates the signature
// matches under the verifier's pinned key.
func (v *CosignVerifier) Verify(pluginDir string, _ *pubplugin.Manifest) (bool, error) {
	manifestPath := filepath.Join(pluginDir, "manifest.yaml")
	sigPath := filepath.Join(pluginDir, "signature.sig")

	manifestBody, err := os.ReadFile(manifestPath) //nolint:gosec // operator-controlled plugins dir
	if err != nil {
		return false, fmt.Errorf("plugins: read manifest: %w", err)
	}
	sigBody, err := os.ReadFile(sigPath) //nolint:gosec // operator-controlled plugins dir
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, ErrNoSignatureFile
		}
		return false, fmt.Errorf("plugins: read signature: %w", err)
	}
	sig := decodeSignature(sigBody)
	digest := sha256.Sum256(manifestBody)
	switch k := v.pubkey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest[:], sig) {
			return false, nil
		}
		return true, nil
	case ed25519.PublicKey:
		// Ed25519 verifies the message directly (not the digest); but
		// cosign sign-blob hashes first, so we hand the digest in.
		// This keeps the signature format symmetric across key types.
		if !ed25519.Verify(k, digest[:], sig) {
			return false, nil
		}
		return true, nil
	default:
		return false, ErrUnsupportedKey
	}
}

// decodeSignature accepts either base64-encoded bytes (the cosign
// sign-blob default) or raw binary. Tries base64 first + falls back
// to raw on failure so operators using either format don't have to
// think about it.
func decodeSignature(in []byte) []byte {
	trimmed := strings.TrimSpace(string(in))
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		return decoded
	}
	if decoded, err := base64.URLEncoding.DecodeString(trimmed); err == nil {
		return decoded
	}
	return in
}
