package plugins

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	pubplugin "github.com/darpanzope/compliancekit/pkg/compliancekit/plugin"
)

// signedFixture writes a plugin directory with a valid signature
// produced under the returned public-key PEM. Returns dir + pubPEM.
func signedFixture(t *testing.T, root, name string) (string, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	manifestBody, _ := yaml.Marshal(pubplugin.Manifest{
		APIVersion: pubplugin.APIVersion,
		Name:       name,
		Version:    "v0.1.0",
		Kinds:      []pubplugin.Kind{pubplugin.KindCheck},
		RegoPacks:  []string{"rego/" + name + ".rego"},
	})
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), manifestBody, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	digest := sha256.Sum256(manifestBody)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signature.sig"),
		[]byte(base64.StdEncoding.EncodeToString(sig)), 0o600); err != nil {
		t.Fatalf("write sig: %v", err)
	}
	return dir, pubPEM
}

func TestCosignVerifier_Happy(t *testing.T) {
	root := t.TempDir()
	dir, pubPEM := signedFixture(t, root, "hello")

	v, err := NewCosignVerifier(pubPEM)
	if err != nil {
		t.Fatalf("NewCosignVerifier: %v", err)
	}
	ok, err := v.Verify(dir, &pubplugin.Manifest{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Errorf("expected valid signature, got ok=false")
	}
}

func TestCosignVerifier_TamperedManifest(t *testing.T) {
	root := t.TempDir()
	dir, pubPEM := signedFixture(t, root, "hello")
	// Mutate the manifest after signing.
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"),
		[]byte("apiVersion: compliancekit.io/v1\nname: tampered\n"), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	v, _ := NewCosignVerifier(pubPEM)
	ok, err := v.Verify(dir, &pubplugin.Manifest{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Errorf("tampered manifest should not verify")
	}
}

func TestCosignVerifier_MissingSignature(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "nosig")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, pubPEM := signedFixture(t, root, "ignored")
	v, _ := NewCosignVerifier(pubPEM)
	_, err := v.Verify(dir, &pubplugin.Manifest{})
	if !errors.Is(err, ErrNoSignatureFile) {
		t.Errorf("expected ErrNoSignatureFile, got %v", err)
	}
}

func TestNewCosignVerifier_BadPEM(t *testing.T) {
	if _, err := NewCosignVerifier([]byte("not-pem")); err == nil {
		t.Errorf("expected error on non-PEM input")
	}
}

func TestCatalogRefresh_WithVerifier(t *testing.T) {
	root := t.TempDir()
	_, pubPEM := signedFixture(t, root, "signed-plugin")

	v, err := NewCosignVerifier(pubPEM)
	if err != nil {
		t.Fatalf("NewCosignVerifier: %v", err)
	}
	c := New(root, false).WithVerifier(v)
	res, err := c.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", res.Errors)
	}
	if len(res.Plugins) != 1 || !res.Plugins[0].SignatureValid {
		t.Errorf("expected one signature-valid plugin, got %+v", res.Plugins)
	}
}
