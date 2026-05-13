package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDoctor_NoProvidersFails(t *testing.T) {
	chdir(t, t.TempDir())

	var buf bytes.Buffer
	err := runDoctor(context.Background(), &buf, doctorOptions{checkConfig: true})
	if err == nil {
		t.Error("runDoctor expected to fail with no providers enabled")
	}
	out := buf.String()
	if !strings.Contains(out, "no providers enabled") {
		t.Errorf("output missing expected warning: %s", out)
	}
}

func TestRunDoctor_DOEnabledResolvesToken(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	writeFile(t, filepath.Join(dir, "compliancekit.yaml"), `
providers:
  digitalocean:
    enabled: true
    token_env: DO_API_TOKEN_TEST
`)
	t.Setenv("DO_API_TOKEN_TEST", "fake-test-token-do-not-use")

	var buf bytes.Buffer
	err := runDoctor(context.Background(), &buf, doctorOptions{})
	if err != nil {
		t.Errorf("runDoctor: %v\noutput:\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "DO_API_TOKEN_TEST resolved") {
		t.Errorf("output missing token resolution line:\n%s", out)
	}
	if !strings.Contains(out, "providers.linux: disabled") {
		t.Errorf("output missing linux=disabled line:\n%s", out)
	}
}

func TestRunDoctor_DOMissingTokenReports(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	writeFile(t, filepath.Join(dir, "compliancekit.yaml"), `
providers:
  digitalocean:
    enabled: true
    token_env: DO_API_TOKEN_MISSING
`)
	// Intentionally do NOT set DO_API_TOKEN_MISSING. Also clear any
	// inherited value so the test is deterministic.
	if err := os.Unsetenv("DO_API_TOKEN_MISSING"); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err := runDoctor(context.Background(), &buf, doctorOptions{})
	if err == nil {
		t.Error("runDoctor expected to return error when an enabled provider's token is missing")
	}

	out := buf.String()
	if !strings.Contains(out, "DO_API_TOKEN_MISSING is unset") {
		t.Errorf("output missing missing-token line:\n%s", out)
	}
	if !strings.Contains(out, iconFail) {
		t.Errorf("output missing fail glyph: %s", out)
	}
	// Doctor must keep reporting subsequent providers, not short-circuit.
	if !strings.Contains(out, "providers.linux: disabled") {
		t.Errorf("output should still report subsequent providers after a failure:\n%s", out)
	}
}

func TestRunDoctor_CheckConfigSkipsEnvResolution(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	writeFile(t, filepath.Join(dir, "compliancekit.yaml"), `
providers:
  digitalocean:
    enabled: true
    token_env: DO_API_TOKEN_NOT_SET
`)
	if err := os.Unsetenv("DO_API_TOKEN_NOT_SET"); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err := runDoctor(context.Background(), &buf, doctorOptions{checkConfig: true})
	if err != nil {
		t.Errorf("runDoctor with --check-config: %v\noutput:\n%s", err, buf.String())
	}
	out := buf.String()
	if strings.Contains(out, "is unset") {
		t.Errorf("output should not check env vars with --check-config:\n%s", out)
	}
	if !strings.Contains(out, "skipping env resolution") {
		t.Errorf("output missing skip indicator:\n%s", out)
	}
}

// Helpers shared with config package's tests but local to keep cli isolated.

func chdir(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(orig); err != nil {
			t.Logf("restore wd: %v", err)
		}
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
