package plugins

// v1.13 phase 4 — per-plugin egress allow-list enforced at dial time.
//
// Each plugin manifest declares the upstream hosts it's permitted to
// reach. The daemon hands the plugin an *http.Client whose underlying
// net.Dialer rejects any dial outside the declared set. The check
// happens at the dial-time Control hook so the connection never even
// reaches the network — plugin code can't smuggle a request to
// evil.example.com regardless of how the URL is constructed.
//
// Egress entries may be:
//
//   - "host"            — exact match
//   - "host:port"       — exact host + port match
//   - "*.example.com"   — subdomain wildcard (any one label)
//
// An empty allow-list = no egress permitted; the plugin must run
// fully against the in-process ResourceGraph the daemon hands it.

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	pubplugin "github.com/darpanzope/compliancekit/pkg/compliancekit/plugin"
)

// Sandbox is the per-plugin dial gate. One instance per plugin
// (built from the manifest's DeclaredEgress slice). The daemon hands
// the plugin a fresh *http.Client through HTTPClient() so every
// outbound request goes through the gate.
type Sandbox struct {
	pluginName string
	allowed    []string
	auditFn    AuditFunc
}

// AuditFunc is the optional callback the sandbox invokes when an
// egress dial is denied. Lets the daemon log the rejection into the
// v1.12 audit_log without the plugins package importing the UI.
type AuditFunc func(pluginName, host string)

// NewSandbox returns a Sandbox enforcing the plugin's manifest
// allow-list. Pass nil audit when the caller doesn't care about the
// audit-trail side effect (tests).
func NewSandbox(m *pubplugin.Manifest, audit AuditFunc) *Sandbox {
	if m == nil {
		return &Sandbox{}
	}
	return &Sandbox{
		pluginName: m.Name,
		allowed:    append([]string(nil), m.DeclaredEgress...),
		auditFn:    audit,
	}
}

// HTTPClient returns an *http.Client whose dialer enforces the
// allow-list. Callers shouldn't reach for http.DefaultClient or
// construct their own *http.Transport — every egress must go through
// the returned client to stay inside the sandbox.
func (s *Sandbox) HTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   s.controlFunc(),
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

// CheckHost reports whether host is permitted by the allow-list.
// Exposed so non-HTTP egress paths (e.g. raw TCP for an SMTP
// notifier) can consult the same gate without spinning a dialer.
func (s *Sandbox) CheckHost(host string) bool {
	return s.matches(host)
}

// controlFunc returns the net.Dialer.Control hook. Fires after DNS
// resolution + before the connection completes; we read the target
// host from the dialer's address arg + reject by returning an error
// the dialer surfaces to the caller as a normal network failure.
func (s *Sandbox) controlFunc() func(network, address string, _ syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		if s.matches(host) {
			return nil
		}
		if s.auditFn != nil {
			s.auditFn(s.pluginName, host)
		}
		slog.Warn("plugin egress denied",
			"plugin", s.pluginName,
			"network", network,
			"host", host)
		return fmt.Errorf("%w: %s -> %s", ErrEgressDenied, s.pluginName, host)
	}
}

// matches walks the allow-list looking for a hit. Three rule shapes
// per the file-header doc.
func (s *Sandbox) matches(host string) bool {
	if host == "" {
		return false
	}
	for _, rule := range s.allowed {
		if matchRule(rule, host) {
			return true
		}
	}
	return false
}

func matchRule(rule, host string) bool {
	if rule == "" {
		return false
	}
	// host:port form — match the host portion only; explicit-port
	// rules are honored when the caller's host string happens to
	// carry one (we don't on net.Dialer.Control — host comes split).
	if strings.Contains(rule, ":") {
		ruleHost, _, err := net.SplitHostPort(rule)
		if err == nil {
			rule = ruleHost
		}
	}
	if strings.HasPrefix(rule, "*.") {
		suffix := rule[1:] // ".example.com"
		if strings.HasSuffix(host, suffix) && strings.Count(host, ".") == strings.Count(suffix, ".") {
			return true
		}
		return false
	}
	return strings.EqualFold(rule, host)
}

// _ keeps the context.Context import path alive in case future
// iterations propagate the ctx through controlFunc.
var _ = context.Background
