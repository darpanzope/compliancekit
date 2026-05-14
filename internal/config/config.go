// Package config defines the parsed shape of compliancekit.yaml and the
// loader that populates it.
//
// Config is the parsed YAML; Load reads it from disk and applies
// environment-variable overrides. See CONFIGURATION.md for the schema
// reference and field-by-field documentation.
//
// At v0.1 only the DigitalOcean and (skeletal) Linux provider blocks are
// consumed by other packages, but the full schema is defined here so
// future providers slot in without re-shaping.
package config

import (
	"fmt"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
)

// Config is the parsed compliancekit.yaml.
type Config struct {
	Project     string                   `mapstructure:"project"     yaml:"project,omitempty"`
	Environment string                   `mapstructure:"environment" yaml:"environment,omitempty"`
	Providers   Providers                `mapstructure:"providers"   yaml:"providers"`
	Frameworks  []string                 `mapstructure:"frameworks"  yaml:"frameworks"`
	Profile     string                   `mapstructure:"profile"     yaml:"profile,omitempty"`
	Profiles    map[string]ProfileConfig `mapstructure:"profiles"    yaml:"profiles,omitempty"`
	Severity    SeverityConfig           `mapstructure:"severity"    yaml:"severity"`
	Output      OutputConfig             `mapstructure:"output"      yaml:"output"`
	State       StateConfig              `mapstructure:"state"       yaml:"state"`

	// SourcePath is the resolved path of the YAML file Load read from, or ""
	// if no file was found and defaults plus environment were used alone.
	// Populated by Load; excluded from marshaling because it is not part
	// of the public schema.
	SourcePath string `mapstructure:"-" yaml:"-" json:"-"`
}

// Providers groups per-provider configuration. Every provider's Enabled
// field defaults to false so a fresh install does nothing until the
// operator explicitly enables a provider.
type Providers struct {
	DigitalOcean DigitalOceanConfig `mapstructure:"digitalocean" yaml:"digitalocean,omitempty"`
	Linux        LinuxConfig        `mapstructure:"linux"        yaml:"linux,omitempty"`
	AWS          AWSConfig          `mapstructure:"aws"          yaml:"aws,omitempty"`
	GCP          GCPConfig          `mapstructure:"gcp"          yaml:"gcp,omitempty"`
	Kubernetes   KubernetesConfig   `mapstructure:"kubernetes"   yaml:"kubernetes,omitempty"`
	Hetzner      HetznerConfig      `mapstructure:"hetzner"      yaml:"hetzner,omitempty"`
}

// AWSConfig configures the AWS collector (v0.7+).
//
// Authentication uses the standard SDK chain (env vars, AWS_PROFILE,
// AWS_ROLE_ARN, IMDSv2, OIDC); none of those need explicit config
// here. The fields below narrow the scan rather than configure
// credentials.
type AWSConfig struct {
	// Enabled flips the provider on. Default false (the scanner does
	// nothing for AWS until explicitly enabled, consistent with every
	// other provider).
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// Regions narrows the per-region scope. Empty (the default) means
	// "all regions the credential can see," resolved via EC2
	// DescribeRegions at scan time. Unknown region names in the list
	// are silently dropped; the scan banner reports the actual region
	// count so typos are observable.
	Regions []string `mapstructure:"regions" yaml:"regions,omitempty"`

	// Profile (optional) overrides AWS_PROFILE. Most operators will
	// leave this empty and rely on the environment.
	Profile string `mapstructure:"profile" yaml:"profile,omitempty"`

	// RoleARN (optional) instructs the SDK to assume this role after
	// loading base credentials. Useful for cross-account scanning.
	// Equivalent to setting AWS_ROLE_ARN env var.
	RoleARN string `mapstructure:"role_arn" yaml:"role_arn,omitempty"`
}

// GCPConfig configures the GCP collector (v0.8+).
//
// Authentication uses Application Default Credentials (ADC):
// GOOGLE_APPLICATION_CREDENTIALS env var pointing at a service-
// account JSON, gcloud's user credentials, GCE/GKE metadata
// server, or Workload Identity Federation. None of those need
// explicit config here; the fields below narrow the scan rather
// than configure credentials.
type GCPConfig struct {
	// Enabled flips the provider on. Default false (consistent
	// with every other provider).
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// Projects narrows the per-project scope. Empty (the default)
	// means "use the default project from credentials." Unknown
	// project IDs surface as per-project gcp.collect_error
	// placeholders rather than aborting the whole scan.
	Projects []string `mapstructure:"projects" yaml:"projects,omitempty"`
}

// DigitalOceanConfig configures the DigitalOcean collector.
type DigitalOceanConfig struct {
	Enabled  bool     `mapstructure:"enabled"   yaml:"enabled"`
	TokenEnv string   `mapstructure:"token_env" yaml:"token_env"`
	Teams    []string `mapstructure:"teams"     yaml:"teams,omitempty"`
	Scope    DOScope  `mapstructure:"scope"     yaml:"scope,omitempty"`
}

// DOScope narrows what the DigitalOcean collector fetches.
type DOScope struct {
	IncludeTags      []string `mapstructure:"include_tags"      yaml:"include_tags,omitempty"`
	ExcludeTags      []string `mapstructure:"exclude_tags"      yaml:"exclude_tags,omitempty"`
	IncludeRegions   []string `mapstructure:"include_regions"   yaml:"include_regions,omitempty"`
	ExcludeRegions   []string `mapstructure:"exclude_regions"   yaml:"exclude_regions,omitempty"`
	IncludeResources []string `mapstructure:"include_resources" yaml:"include_resources,omitempty"`
	ExcludeResources []string `mapstructure:"exclude_resources" yaml:"exclude_resources,omitempty"`
}

// LinuxConfig configures the Linux SSH collector (v0.2+).
type LinuxConfig struct {
	Enabled   bool      `mapstructure:"enabled"   yaml:"enabled"`
	Inventory string    `mapstructure:"inventory" yaml:"inventory,omitempty"`
	SSH       SSHConfig `mapstructure:"ssh"       yaml:"ssh,omitempty"`
}

// SSHConfig configures how the linux collector connects to hosts.
type SSHConfig struct {
	User          string        `mapstructure:"user"            yaml:"user,omitempty"`
	KeyFile       string        `mapstructure:"key_file"        yaml:"key_file,omitempty"`
	Port          int           `mapstructure:"port"            yaml:"port,omitempty"`
	Timeout       time.Duration `mapstructure:"timeout"         yaml:"timeout,omitempty"`
	MaxParallel   int           `mapstructure:"max_parallel"    yaml:"max_parallel,omitempty"`
	StrictHostKey bool          `mapstructure:"strict_host_key" yaml:"strict_host_key,omitempty"`
	Bastion       *Bastion      `mapstructure:"bastion"         yaml:"bastion,omitempty"`
}

// Bastion describes a single SSH jump host.
type Bastion struct {
	Host string `mapstructure:"host" yaml:"host"`
	User string `mapstructure:"user" yaml:"user,omitempty"`
	Port int    `mapstructure:"port" yaml:"port,omitempty"`
}

// KubernetesConfig configures the Kubernetes collector (v0.8+).
type KubernetesConfig struct {
	Enabled    bool     `mapstructure:"enabled"    yaml:"enabled"`
	Kubeconfig string   `mapstructure:"kubeconfig" yaml:"kubeconfig,omitempty"`
	Contexts   []string `mapstructure:"contexts"   yaml:"contexts,omitempty"`
	Namespaces []string `mapstructure:"namespaces" yaml:"namespaces,omitempty"`
}

// HetznerConfig configures the Hetzner Cloud collector (v0.7+).
type HetznerConfig struct {
	Enabled  bool   `mapstructure:"enabled"   yaml:"enabled"`
	TokenEnv string `mapstructure:"token_env" yaml:"token_env"`
}

// SeverityConfig controls how findings are filtered and how the CLI
// chooses its exit code.
//
// FailOn and MinReport are stored as strings rather than core.Severity
// so the config package stays decoupled from core's enum encoding and
// surfaces parse errors via Validate rather than at unmarshal time.
type SeverityConfig struct {
	FailOn    string `mapstructure:"fail_on"    yaml:"fail_on"`
	MinReport string `mapstructure:"min_report" yaml:"min_report"`
}

// FailOnLevel parses the fail_on severity.
func (s SeverityConfig) FailOnLevel() (core.Severity, error) {
	return core.ParseSeverity(s.FailOn)
}

// MinReportLevel parses the min_report severity.
func (s SeverityConfig) MinReportLevel() (core.Severity, error) {
	return core.ParseSeverity(s.MinReport)
}

// OutputConfig controls reporter selection and output paths.
type OutputConfig struct {
	Format     []string `mapstructure:"format"      yaml:"format"`
	OutDir     string   `mapstructure:"out_dir"     yaml:"out_dir"`
	Evidence   bool     `mapstructure:"evidence"    yaml:"evidence"`
	IncludeRaw bool     `mapstructure:"include_raw" yaml:"include_raw"`
	Redaction  string   `mapstructure:"redaction"   yaml:"redaction"`
}

// StateConfig controls the local state store used for drift detection.
type StateConfig struct {
	Dir           string `mapstructure:"dir"            yaml:"dir"`
	Backend       string `mapstructure:"backend"        yaml:"backend"`
	RetentionDays int    `mapstructure:"retention_days" yaml:"retention_days"`
}

// AnyProviderEnabled reports whether at least one provider is enabled.
// The scan command uses this to decide whether to error before doing
// any work; doctor uses it to surface a warning.
func (c Config) AnyProviderEnabled() bool {
	return c.Providers.DigitalOcean.Enabled ||
		c.Providers.Linux.Enabled ||
		c.Providers.AWS.Enabled ||
		c.Providers.GCP.Enabled ||
		c.Providers.Kubernetes.Enabled ||
		c.Providers.Hetzner.Enabled
}

// Validate performs structural sanity checks against the loaded config.
//
// Severity strings must parse to known levels; enabled providers must
// have the minimum required fields. Validate does NOT touch the network
// or resolve env vars -- those are doctor's job at runtime.
func (c Config) Validate() error {
	if _, err := c.Severity.FailOnLevel(); err != nil {
		return fmt.Errorf("severity.fail_on: %w", err)
	}
	if _, err := c.Severity.MinReportLevel(); err != nil {
		return fmt.Errorf("severity.min_report: %w", err)
	}

	if c.Providers.DigitalOcean.Enabled && c.Providers.DigitalOcean.TokenEnv == "" {
		return fmt.Errorf("providers.digitalocean.enabled is true but token_env is empty")
	}
	if c.Providers.Hetzner.Enabled && c.Providers.Hetzner.TokenEnv == "" {
		return fmt.Errorf("providers.hetzner.enabled is true but token_env is empty")
	}
	if c.Providers.Linux.Enabled && c.Providers.Linux.Inventory == "" {
		return fmt.Errorf("providers.linux.enabled is true but inventory path is empty")
	}

	return nil
}

// ProfileConfig is one named subset of the check catalog declared
// under `profiles:` in compliancekit.yaml. Mirrors the selectors on
// internal/profile.Profile; the loader copies fields across into
// the engine type at scan time.
//
// Profiles are pure filters over the registered checks. A profile
// that names zero checks is an error at scan time -- almost always
// a typo in the selectors.
type ProfileConfig struct {
	Description       string   `mapstructure:"description"        yaml:"description,omitempty"`
	IncludeProviders  []string `mapstructure:"include_providers"  yaml:"include_providers,omitempty"`
	ExcludeProviders  []string `mapstructure:"exclude_providers"  yaml:"exclude_providers,omitempty"`
	IncludeSeverities []string `mapstructure:"include_severities" yaml:"include_severities,omitempty"`
	IncludeFrameworks []string `mapstructure:"include_frameworks" yaml:"include_frameworks,omitempty"`
	IncludeTags       []string `mapstructure:"include_tags"       yaml:"include_tags,omitempty"`
	ExcludeTags       []string `mapstructure:"exclude_tags"       yaml:"exclude_tags,omitempty"`
	IncludeIDs        []string `mapstructure:"include_ids"        yaml:"include_ids,omitempty"`
	ExcludeIDs        []string `mapstructure:"exclude_ids"        yaml:"exclude_ids,omitempty"`
}
