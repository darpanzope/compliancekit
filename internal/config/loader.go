package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// LoadOptions controls how Load locates and reads the config file.
type LoadOptions struct {
	// ConfigPath, if set, is an explicit --config=... value. It overrides
	// the search-path lookup and makes a missing file a hard error.
	ConfigPath string

	// EnvName, if set, selects compliancekit.<env>.yaml in the search paths
	// (matches the --env=prod CLI flag). Ignored if ConfigPath is set.
	EnvName string
}

// Load reads the config file (if present) and applies environment-variable
// overrides on top of built-in defaults.
//
// Precedence, lowest to highest:
//  1. Built-in defaults (set in setDefaults)
//  2. Config file values
//  3. Environment variables (COMPLIANCEKIT_<UPPER_SNAKE_PATH>)
//
// A missing config file is not an error when ConfigPath is empty --
// compliancekit can run with environment variables and flags alone. An
// explicitly requested path that does not exist IS an error, because
// the operator clearly intended to use that file.
//
// On success the returned Config has been validated.
func Load(opts LoadOptions) (*Config, error) {
	v := viper.New()
	setDefaults(v)

	if opts.ConfigPath != "" {
		v.SetConfigFile(opts.ConfigPath)
	} else {
		name := "compliancekit"
		if opts.EnvName != "" {
			name = "compliancekit." + opts.EnvName
		}
		v.SetConfigName(name)
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$XDG_CONFIG_HOME/compliancekit")
		v.AddConfigPath("$HOME/.compliancekit")
	}

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if errors.As(err, &notFound) {
			// Implicit lookup missing the file is fine.
			if opts.ConfigPath != "" {
				return nil, fmt.Errorf("config file not found: %s", opts.ConfigPath)
			}
		} else {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	// COMPLIANCEKIT_SEVERITY_FAIL_ON -> severity.fail_on, etc.
	v.SetEnvPrefix("COMPLIANCEKIT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	cfg.SourcePath = v.ConfigFileUsed()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("frameworks", []string{"soc2", "cis-v8"})

	v.SetDefault("severity.fail_on", "high")
	v.SetDefault("severity.min_report", "info")

	v.SetDefault("output.format", []string{"json"})
	v.SetDefault("output.out_dir", "./out")
	v.SetDefault("output.evidence", false)
	v.SetDefault("output.include_raw", false)
	v.SetDefault("output.redaction", "default")

	v.SetDefault("state.dir", ".compliancekit")
	v.SetDefault("state.backend", "file")
	v.SetDefault("state.retention_days", 90)

	v.SetDefault("providers.digitalocean.token_env", "DO_API_TOKEN")
	v.SetDefault("providers.hetzner.token_env", "HCLOUD_TOKEN")

	v.SetDefault("providers.linux.ssh.port", 22)
	v.SetDefault("providers.linux.ssh.timeout", "10s")
	v.SetDefault("providers.linux.ssh.max_parallel", 16)
	v.SetDefault("providers.linux.ssh.strict_host_key", true)
}
