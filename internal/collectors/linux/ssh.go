package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/darpanzope/compliancekit/internal/config"
)

// Defaults applied when neither the inventory nor compliancekit.yaml
// sets an explicit value.
const (
	defaultSSHPort    = 22
	defaultSSHTimeout = 10 * time.Second

	// maxOutput bounds RunCommand's captured output so a misbehaving
	// host cannot OOM the scanner with unbounded stdout. 1 MiB covers
	// every legitimate compliance probe (sshd_config is ~1 KB,
	// `ufw status numbered` ~50 KB at worst) with a healthy margin.
	maxOutput = 1 << 20
)

// DialOptions are the merged SSH parameters for one host. Built by
// MergeHost from compliancekit.yaml's providers.linux.ssh defaults plus
// any per-host overrides in inventory.yaml.
type DialOptions struct {
	// Address is "host:port" suitable for net.Dial.
	Address string

	// User is the SSH login. Falls back to the current OS user when
	// neither the global default nor the per-host override sets it.
	User string

	// KeyFile is an absolute path to a PEM private key. Empty means
	// "use SSH agent only".
	KeyFile string

	// KnownHostsFile is the path to known_hosts for strict host-key
	// verification. Defaults to ~/.ssh/known_hosts when empty and
	// StrictHostKey is true.
	KnownHostsFile string

	// Timeout is the connection deadline.
	Timeout time.Duration

	// StrictHostKey controls whether the host key must be in
	// known_hosts. Default true; setting false disables verification
	// entirely (documented as insecure in CONFIGURATION.md).
	StrictHostKey bool

	// Bastion, when non-nil, instructs Dial to connect to the bastion
	// first and tunnel to Address through it. The bastion itself is
	// configured by another DialOptions value (so the same auth /
	// host-key logic applies).
	Bastion *DialOptions
}

// MergeHost combines the global SSH defaults (from compliancekit.yaml's
// providers.linux.ssh) with the per-host overrides parsed from
// inventory.yaml.
//
// Precedence, lowest to highest:
//  1. Built-in defaults (port 22, timeout 10s, current OS user)
//  2. Global SSH defaults from compliancekit.yaml
//  3. Per-host overrides from inventory.yaml
//
// Bastion wiring is the caller's job (the bastion is configured at the
// provider level, not per host, so it does not belong inside this
// merge). Phase 6 wires it on the scan command side.
func MergeHost(host Host, defaults config.SSHConfig) (DialOptions, error) {
	port := host.Port
	if port == 0 {
		port = defaults.Port
	}
	if port == 0 {
		port = defaultSSHPort
	}

	opts := DialOptions{
		Address:       net.JoinHostPort(host.Host, strconv.Itoa(port)),
		User:          coalesceString(host.User, defaults.User, currentUser()),
		KeyFile:       expandHome(coalesceString(perHostKeyFile(host), defaults.KeyFile)),
		StrictHostKey: defaults.StrictHostKey,
		Timeout:       defaults.Timeout,
	}

	if host.SSH != nil && host.SSH.StrictHostKey != nil {
		opts.StrictHostKey = *host.SSH.StrictHostKey
	}

	if host.SSH != nil && host.SSH.Timeout != "" {
		d, err := time.ParseDuration(host.SSH.Timeout)
		if err != nil {
			return opts, fmt.Errorf("host %s: invalid timeout %q: %w", host.Host, host.SSH.Timeout, err)
		}
		opts.Timeout = d
	}
	if opts.Timeout == 0 {
		opts.Timeout = defaultSSHTimeout
	}

	return opts, nil
}

// Dial opens an SSH connection per opts. Honors ctx for the dial path
// (the underlying ssh.Dial would otherwise hang for Timeout regardless
// of upstream cancellation).
func Dial(ctx context.Context, opts DialOptions) (*ssh.Client, error) {
	cfg, err := buildClientConfig(opts)
	if err != nil {
		return nil, err
	}
	if opts.Bastion != nil {
		return dialViaBastion(ctx, opts, cfg)
	}
	return dialDirect(ctx, opts.Address, cfg)
}

// RunCommand executes cmd over an existing SSH connection and returns
// combined stdout+stderr, the exit code, and any error.
//
// A non-zero exit from cmd does NOT produce a Go error -- that is
// expected ("test -f /etc/foo" returning 1 is signal, not failure).
// Errors are reserved for transport problems (session setup, ctx
// cancellation, etc.).
//
// Output is bounded to maxOutput bytes; longer outputs are truncated
// with a trailing notice.
func RunCommand(ctx context.Context, client *ssh.Client, cmd string) (output string, exitCode int, err error) {
	session, err := client.NewSession()
	if err != nil {
		return "", 0, fmt.Errorf("new session: %w", err)
	}
	defer func() { _ = session.Close() }()

	var out bytes.Buffer
	session.Stdout = &out
	session.Stderr = &out

	done := make(chan error, 1)
	go func() {
		done <- session.Run(cmd)
	}()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGTERM)
		return out.String(), -1, ctx.Err()
	case runErr := <-done:
		output := out.String()
		if len(output) > maxOutput {
			output = output[:maxOutput] + "\n[output truncated]"
		}
		if runErr == nil {
			return output, 0, nil
		}
		var ee *ssh.ExitError
		if errors.As(runErr, &ee) {
			return output, ee.ExitStatus(), nil
		}
		return output, -1, fmt.Errorf("ssh run: %w", runErr)
	}
}

// buildClientConfig assembles the ssh.ClientConfig from auth, host-key,
// and timing settings in opts. SSH agent and key file are both tried;
// at least one must succeed.
func buildClientConfig(opts DialOptions) (*ssh.ClientConfig, error) {
	var authMethods []ssh.AuthMethod

	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			authMethods = append(authMethods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}

	if opts.KeyFile != "" {
		key, err := os.ReadFile(opts.KeyFile) //nolint:gosec // path is operator-supplied via config
		if err != nil {
			return nil, fmt.Errorf("read key file %s: %w", opts.KeyFile, err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse key file %s: %w", opts.KeyFile, err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if len(authMethods) == 0 {
		return nil, errors.New("no SSH auth method available: set SSH_AUTH_SOCK (agent) or key_file")
	}

	hostKeyCallback, err := buildHostKeyCallback(opts)
	if err != nil {
		return nil, err
	}

	return &ssh.ClientConfig{
		User:            opts.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         opts.Timeout,
	}, nil
}

// buildHostKeyCallback returns the ssh.HostKeyCallback per StrictHostKey.
// Strict mode reads known_hosts; relaxed mode skips verification entirely.
func buildHostKeyCallback(opts DialOptions) (ssh.HostKeyCallback, error) {
	if !opts.StrictHostKey {
		return ssh.InsecureIgnoreHostKey(), nil //nolint:gosec // explicit operator opt-out documented in CONFIGURATION.md
	}
	path := opts.KnownHostsFile
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home: %w", err)
		}
		path = filepath.Join(home, ".ssh", "known_hosts")
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts %s: %w", path, err)
	}
	return cb, nil
}

// dialDirect dials opts.Address respecting ctx cancellation.
func dialDirect(ctx context.Context, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	type result struct {
		client *ssh.Client
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ssh.Dial("tcp", addr, cfg)
		ch <- result{c, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.client, r.err
	}
}

// dialViaBastion connects to the bastion first, then tunnels TCP to
// the target and performs the SSH handshake over that tunnel.
func dialViaBastion(ctx context.Context, opts DialOptions, targetCfg *ssh.ClientConfig) (*ssh.Client, error) {
	bastionCfg, err := buildClientConfig(*opts.Bastion)
	if err != nil {
		return nil, fmt.Errorf("bastion config: %w", err)
	}
	bastion, err := dialDirect(ctx, opts.Bastion.Address, bastionCfg)
	if err != nil {
		return nil, fmt.Errorf("dial bastion %s: %w", opts.Bastion.Address, err)
	}

	tunnel, err := bastion.Dial("tcp", opts.Address)
	if err != nil {
		_ = bastion.Close()
		return nil, fmt.Errorf("dial target %s via bastion: %w", opts.Address, err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(tunnel, opts.Address, targetCfg)
	if err != nil {
		_ = tunnel.Close()
		_ = bastion.Close()
		return nil, fmt.Errorf("ssh handshake with target: %w", err)
	}
	return ssh.NewClient(conn, chans, reqs), nil
}

// coalesceString returns the first non-empty value from values, or "".
func coalesceString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// currentUser returns the running OS user's login, or "" on failure.
// Used as the final fallback when neither config nor inventory sets a
// user -- matches OpenSSH's default behavior.
func currentUser() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.Username
}

// expandHome replaces a leading ~/ with the user's home directory. The
// ssh package itself does not do this expansion, and operators commonly
// write ~/.ssh/key in YAML.
func expandHome(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}

// perHostKeyFile returns Host.SSH.KeyFile or "" if SSH overrides are absent.
// Kept separate so MergeHost's coalesce chain reads linearly.
func perHostKeyFile(h Host) string {
	if h.SSH == nil {
		return ""
	}
	return h.SSH.KeyFile
}
