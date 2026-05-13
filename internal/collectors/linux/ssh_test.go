package linux

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/darpanzope/compliancekit/internal/config"
)

func TestMergeHost_DefaultsWhenInventoryEmpty(t *testing.T) {
	host := Host{Host: "web-01"}
	defaults := config.SSHConfig{
		User:          "ops",
		KeyFile:       "/etc/keys/id",
		Port:          22,
		Timeout:       15 * time.Second,
		StrictHostKey: true,
	}

	opts, err := MergeHost(host, defaults)
	if err != nil {
		t.Fatalf("MergeHost: %v", err)
	}
	if opts.User != "ops" {
		t.Errorf("User = %q, want ops", opts.User)
	}
	if opts.KeyFile != "/etc/keys/id" {
		t.Errorf("KeyFile = %q, want /etc/keys/id", opts.KeyFile)
	}
	if opts.Address != "web-01:22" {
		t.Errorf("Address = %q, want web-01:22", opts.Address)
	}
	if !opts.StrictHostKey {
		t.Error("StrictHostKey = false, want true")
	}
	if opts.Timeout != 15*time.Second {
		t.Errorf("Timeout = %v, want 15s", opts.Timeout)
	}
}

func TestMergeHost_PerHostOverridesWin(t *testing.T) {
	off := false
	host := Host{
		Host: "db-01",
		User: "dba",
		Port: 2222,
		SSH: &HostSSH{
			KeyFile:       "/host/key",
			Timeout:       "30s",
			StrictHostKey: &off,
		},
	}
	defaults := config.SSHConfig{
		User:          "ops",
		KeyFile:       "/global/key",
		Port:          22,
		Timeout:       10 * time.Second,
		StrictHostKey: true,
	}

	opts, err := MergeHost(host, defaults)
	if err != nil {
		t.Fatalf("MergeHost: %v", err)
	}
	if opts.User != "dba" {
		t.Errorf("User = %q, want dba (per-host)", opts.User)
	}
	if opts.KeyFile != "/host/key" {
		t.Errorf("KeyFile = %q, want /host/key (per-host)", opts.KeyFile)
	}
	if opts.Address != "db-01:2222" {
		t.Errorf("Address = %q, want db-01:2222", opts.Address)
	}
	if opts.StrictHostKey {
		t.Error("StrictHostKey = true, want false (per-host pointer override)")
	}
	if opts.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", opts.Timeout)
	}
}

func TestMergeHost_BuiltinDefaultsWhenNothingSet(t *testing.T) {
	opts, err := MergeHost(Host{Host: "x"}, config.SSHConfig{})
	if err != nil {
		t.Fatalf("MergeHost: %v", err)
	}
	if opts.Address != "x:22" {
		t.Errorf("Address = %q, want x:22 (built-in default port)", opts.Address)
	}
	if opts.Timeout != defaultSSHTimeout {
		t.Errorf("Timeout = %v, want %v (built-in default)", opts.Timeout, defaultSSHTimeout)
	}
	// User falls back to OS user; just confirm it's non-empty in a normal env.
	if opts.User == "" {
		t.Error("User = \"\", want OS user fallback")
	}
}

func TestMergeHost_HomeExpansion(t *testing.T) {
	host := Host{Host: "x", SSH: &HostSSH{KeyFile: "~/.ssh/test_key"}}
	opts, err := MergeHost(host, config.SSHConfig{})
	if err != nil {
		t.Fatalf("MergeHost: %v", err)
	}
	if strings.HasPrefix(opts.KeyFile, "~/") {
		t.Errorf("KeyFile = %q, want expanded home", opts.KeyFile)
	}
	home, _ := os.UserHomeDir()
	if !strings.HasPrefix(opts.KeyFile, home) {
		t.Errorf("KeyFile = %q, want path starting with %q", opts.KeyFile, home)
	}
}

func TestMergeHost_BadTimeoutErrors(t *testing.T) {
	host := Host{Host: "x", SSH: &HostSSH{Timeout: "not a duration"}}
	_, err := MergeHost(host, config.SSHConfig{})
	if err == nil {
		t.Error("expected error for invalid timeout string")
	}
}

func TestBuildClientConfig_FailsWithoutAuth(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "") // disable agent
	opts := DialOptions{
		Address:       "x:22",
		User:          "ops",
		StrictHostKey: false,
		Timeout:       time.Second,
	}
	if _, err := buildClientConfig(opts); err == nil {
		t.Error("expected error when no SSH agent and no key file")
	}
}

func TestBuildClientConfig_FailsOnMissingKeyFile(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	opts := DialOptions{
		Address:       "x:22",
		User:          "ops",
		KeyFile:       "/nonexistent/path/key",
		StrictHostKey: false,
		Timeout:       time.Second,
	}
	_, err := buildClientConfig(opts)
	if err == nil {
		t.Error("expected error when key_file path does not exist")
	}
	if !strings.Contains(err.Error(), "read key file") {
		t.Errorf("error should mention read key file: %v", err)
	}
}

func TestBuildClientConfig_AcceptsValidKey(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")

	keyPath := writeTestEd25519Key(t)
	opts := DialOptions{
		Address:       "x:22",
		User:          "ops",
		KeyFile:       keyPath,
		StrictHostKey: false,
		Timeout:       time.Second,
	}
	cfg, err := buildClientConfig(opts)
	if err != nil {
		t.Fatalf("buildClientConfig: %v", err)
	}
	if cfg.User != "ops" {
		t.Errorf("User = %q, want ops", cfg.User)
	}
	if len(cfg.Auth) != 1 {
		t.Errorf("len(Auth) = %d, want 1 (key only, agent disabled)", len(cfg.Auth))
	}
}

func TestBuildHostKeyCallback_InsecureWhenNotStrict(t *testing.T) {
	cb, err := buildHostKeyCallback(DialOptions{StrictHostKey: false})
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}
	if cb == nil {
		t.Fatal("got nil callback")
	}
	// InsecureIgnoreHostKey returns a callback that always returns nil.
	if err := cb("example.com:22", nil, nil); err != nil {
		t.Errorf("insecure callback should accept everything: %v", err)
	}
}

func TestBuildHostKeyCallback_StrictRequiresKnownHostsFile(t *testing.T) {
	_, err := buildHostKeyCallback(DialOptions{
		StrictHostKey:  true,
		KnownHostsFile: "/nonexistent/known_hosts",
	})
	if err == nil {
		t.Error("expected error when known_hosts file is missing")
	}
}

// writeTestEd25519Key generates an in-memory ed25519 key, writes it to
// a temp file in PEM form, and returns the path. The key is real but
// never used to connect anywhere; it just exercises the parse path.
func writeTestEd25519Key(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// MarshalPrivateKey is the simplest way to get a usable PEM block
	// that ssh.ParsePrivateKey accepts.
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path
}
