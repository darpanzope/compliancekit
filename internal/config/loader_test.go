package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_DefaultsOnly(t *testing.T) {
	chdir(t, t.TempDir())

	cfg, err := Load(LoadOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SourcePath != "" {
		t.Errorf("SourcePath = %q with no file, want empty", cfg.SourcePath)
	}
	if got, want := cfg.Severity.FailOn, "high"; got != want {
		t.Errorf("Severity.FailOn = %q, want %q", got, want)
	}
	if got, want := cfg.Severity.MinReport, "info"; got != want {
		t.Errorf("Severity.MinReport = %q, want %q", got, want)
	}
	if got, want := cfg.Output.OutDir, "./out"; got != want {
		t.Errorf("Output.OutDir = %q, want %q", got, want)
	}
	if got, want := len(cfg.Frameworks), 2; got != want {
		t.Errorf("len(Frameworks) = %d, want %d", got, want)
	}
	if cfg.AnyProviderEnabled() {
		t.Error("AnyProviderEnabled() = true with no config or env, want false")
	}
	// DO token_env defaults to DO_API_TOKEN even when provider is disabled.
	if got, want := cfg.Providers.DigitalOcean.TokenEnv, "DO_API_TOKEN"; got != want {
		t.Errorf("Providers.DigitalOcean.TokenEnv = %q, want %q", got, want)
	}
}

func TestLoad_FileOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	writeFile(t, filepath.Join(dir, "compliancekit.yaml"), `
project: test-project
environment: staging
providers:
  digitalocean:
    enabled: true
    token_env: DO_API_TOKEN
frameworks: [soc2, iso27001]
severity:
  fail_on: critical
  min_report: medium
output:
  format: [json, html]
  out_dir: ./custom-out
`)

	cfg, err := Load(LoadOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Project != "test-project" {
		t.Errorf("Project = %q, want test-project", cfg.Project)
	}
	if cfg.Environment != "staging" {
		t.Errorf("Environment = %q, want staging", cfg.Environment)
	}
	if !cfg.Providers.DigitalOcean.Enabled {
		t.Error("Providers.DigitalOcean.Enabled = false, want true")
	}
	if cfg.Severity.FailOn != "critical" {
		t.Errorf("Severity.FailOn = %q, want critical", cfg.Severity.FailOn)
	}
	if got, want := cfg.Output.OutDir, "./custom-out"; got != want {
		t.Errorf("Output.OutDir = %q, want %q", got, want)
	}
	if got, want := cfg.Frameworks, []string{"soc2", "iso27001"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Frameworks = %v, want %v", got, want)
	}
	if cfg.SourcePath == "" {
		t.Error("SourcePath = empty, want path to loaded file")
	}
}

func TestLoad_EnvVarOverridesFile(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	writeFile(t, filepath.Join(dir, "compliancekit.yaml"), `
severity:
  fail_on: medium
`)

	t.Setenv("COMPLIANCEKIT_SEVERITY_FAIL_ON", "critical")

	cfg, err := Load(LoadOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Severity.FailOn != "critical" {
		t.Errorf("Severity.FailOn = %q, want critical (env should override file)", cfg.Severity.FailOn)
	}
}

func TestLoad_BadSeverityFailsValidation(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	writeFile(t, filepath.Join(dir, "compliancekit.yaml"), `
severity:
  fail_on: ohno
`)

	_, err := Load(LoadOptions{})
	if err == nil {
		t.Error("Load expected to fail validation with bad severity, but succeeded")
	}
}

func TestLoad_ExplicitMissingPathFails(t *testing.T) {
	_, err := Load(LoadOptions{ConfigPath: "/nonexistent/compliancekit.yaml"})
	if err == nil {
		t.Error("Load expected to fail with explicit missing path, but succeeded")
	}
}

func TestLoad_ExplicitPathLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "elsewhere.yaml")
	writeFile(t, path, `
project: elsewhere
`)

	cfg, err := Load(LoadOptions{ConfigPath: path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Project != "elsewhere" {
		t.Errorf("Project = %q, want elsewhere", cfg.Project)
	}
	if cfg.SourcePath != path {
		t.Errorf("SourcePath = %q, want %q", cfg.SourcePath, path)
	}
}

func TestLoad_LinuxRequiresInventory(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	writeFile(t, filepath.Join(dir, "compliancekit.yaml"), `
providers:
  linux:
    enabled: true
`)

	_, err := Load(LoadOptions{})
	if err == nil {
		t.Error("Load expected to fail when linux enabled but inventory empty")
	}
}

func TestLoad_EnvName(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	writeFile(t, filepath.Join(dir, "compliancekit.prod.yaml"), `
project: prod-only
`)

	cfg, err := Load(LoadOptions{EnvName: "prod"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Project != "prod-only" {
		t.Errorf("Project = %q, want prod-only", cfg.Project)
	}
}

// Helpers

// chdir changes the working directory for the duration of the test and
// restores it on cleanup. Tests in this package do not run in parallel
// (no t.Parallel calls), so a process-wide chdir is safe.
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
