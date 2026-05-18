// Package notify dispatches compliancekit Findings to operator-
// configured channels (Slack, Discord, Teams, email, generic webhook,
// GitHub PR comments, Jira, PagerDuty) per the v0.17 milestone.
//
// Per ADR-006 the binary remains read-only end-to-end: a notification
// is *generation* — the package POSTs a payload an operator already
// asked to receive. The same constraints that apply to remediate +
// ingest apply here: no telemetry, no phone-home, no analytics.
// Every notification target is operator-configured via env vars and
// `compliancekit.yaml`. A sink with missing credentials reports
// Configured()=false and is skipped silently; one failing sink
// never blocks the others.
//
// Package layout:
//
//	internal/notify/notify.go        — this file: Notifier interface,
//	                                    Registry, Notification + Result
//	                                    types, severity gate, builder.
//	internal/notify/config.go        — typed config block (`notify:`
//	                                    in compliancekit.yaml).
//	internal/notify/<sink>.go        — one file per sink: slack.go,
//	                                    discord.go, teams.go, webhook.go,
//	                                    email.go, github.go, jira.go,
//	                                    pagerduty.go.
//	internal/notify/<sink>_test.go   — per-sink httptest contract test.
//
// CLI surface is `compliancekit notify --in=findings.json
// --config=compliancekit.yaml` (Phase 10).
package notify

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Notifier is the contract every channel implements. Implementations
// must be stateless: the same instance is reused across notify
// invocations and across goroutines. Per-call state flows through
// the Notification slice + the context.
type Notifier interface {
	// Name returns a short, unique, kebab-case identifier for the
	// sink. Used in error messages, `compliancekit doctor` output,
	// the per-sink `notify:` config block, and the Result rendering.
	Name() string

	// Configured reports whether the sink has enough config to call
	// its upstream. Missing credentials = not configured = caller
	// skips silently. This is the same pattern as the v0.15 ticket
	// providers.
	Configured() bool

	// Threshold returns the per-sink severity floor below which
	// notifications are dropped. compliancekit.SeverityInfo means "send
	// everything". The CLI / config layer can override per-sink.
	Threshold() compliancekit.Severity

	// Send dispatches the slice of Notification objects already
	// filtered by the global severity gate. Returns a Result tally;
	// transport errors return the second return value but never
	// abort other Notifications in the slice — sinks should partial-
	// succeed and report partial-error counts.
	Send(ctx context.Context, notifications []Notification) (Result, error)
}

// Notification is the canonical shape every Notifier consumes. It
// carries the original Finding plus pre-rendered text (title + body)
// that sinks adapt to their wire format. Sinks needing rich shapes
// (PagerDuty event JSON, Slack blocks) build them from Finding +
// rendered text together.
type Notification struct {
	// Finding is the upstream finding. Sinks needing fields beyond
	// title/body (severity color, CheckID, framework refs) pull
	// them from here.
	Finding compliancekit.Finding

	// Title is a single-line headline rendered for the sink (e.g.
	// "[CRITICAL] aws-s3-public-access-block on prod-data-bucket").
	Title string

	// Body is the per-notification body in CommonMark (plain markdown).
	// Each sink may convert: Discord + Slack render natively; Teams
	// converts to MessageCard; email wraps in multipart MIME;
	// webhook + PagerDuty pass as-is in a body field.
	Body string

	// URL points operators at where to act: usually the
	// `compliancekit checks show <id>` URL, the GitHub PR, or the
	// finding's evidence-pack URL. Optional — sinks omit when empty.
	URL string

	// Tags are sink-routing hints (e.g. "team:security",
	// "service:checkout"). Sinks that support tagging surface them;
	// sinks that don't (PagerDuty, email subject) ignore.
	Tags []string

	// Fingerprint is the dedup key. Built from
	// Finding.Fingerprint()+sink-name so the same finding fires once
	// per sink, not once per sink × notification window. Populated
	// by the dispatcher (Phase 10), not by the sink itself.
	Fingerprint string
}

// Result reports what a sink did with the notifications it was sent.
// Returned per Send call; the dispatcher aggregates across sinks.
type Result struct {
	Sent     int      // delivered to the upstream successfully
	Skipped  int      // under the sink's threshold OR deduped
	Errors   int      // permanent failures (4xx, parse errors)
	Messages []string // one human-readable line per notification's outcome
}

// Add accumulates b into a. Used by the dispatcher to roll up
// per-sink Results into a single per-run summary.
func (a *Result) Add(b Result) {
	a.Sent += b.Sent
	a.Skipped += b.Skipped
	a.Errors += b.Errors
	a.Messages = append(a.Messages, b.Messages...)
}

// Registry holds every registered Notifier. Sinks self-register via
// notify.Register(...) from their init(). The CLI side-effect
// imports each sink subpackage so importing this package is enough
// to make every shipped sink available.
type Registry struct {
	mu    sync.RWMutex
	sinks map[string]Notifier
}

// NewRegistry returns an empty Registry. Tests use this for
// isolation; production code goes through Default.
func NewRegistry() *Registry { return &Registry{sinks: map[string]Notifier{}} }

// Register adds n to the registry. Panics on duplicate Name() —
// duplicate sink names are a programmer error caught at init time,
// not a runtime condition.
func (r *Registry) Register(n Notifier) {
	if n == nil {
		panic("notify: Register called with nil notifier")
	}
	name := n.Name()
	if name == "" {
		panic("notify: Notifier.Name() returned empty string")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.sinks[name]; exists {
		panic(fmt.Sprintf("notify: duplicate sink registration: %s", name))
	}
	r.sinks[name] = n
}

// Lookup returns the sink registered under name + whether it exists.
func (r *Registry) Lookup(name string) (Notifier, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n, ok := r.sinks[name]
	return n, ok
}

// Sinks returns every registered Notifier, sorted by Name() for
// stable output. Used by `compliancekit doctor` to enumerate
// configuration status and by the CLI when no per-sink filter is
// passed.
func (r *Registry) Sinks() []Notifier {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Notifier, 0, len(r.sinks))
	for _, n := range r.sinks {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Names returns the sorted list of registered sink names.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.sinks))
	for n := range r.sinks {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Default is the process-wide registry every sink package registers
// against from init(). The CLI uses Default.Sinks(); tests build
// isolated registries via NewRegistry.
var Default = NewRegistry()

// Register installs a sink into Default.
func Register(n Notifier) { Default.Register(n) }

// BuildNotifications converts a Findings slice into the canonical
// Notification slice every sink consumes. Caller-provided Options
// control rendering (URL prefix for "checks show", baseline for
// only-new-findings mode — Phase 10).
//
// Severity gating is applied per-sink inside Dispatch, not here —
// the same Notification slice may flow to a low-threshold sink
// (Slack: all-medium-plus) and a high-threshold one (PagerDuty:
// critical-only). Building once and gating per sink keeps the
// rendering cost amortized.
func BuildNotifications(findings []compliancekit.Finding, opts BuildOptions) []Notification {
	out := make([]Notification, 0, len(findings))
	for _, f := range findings {
		if !f.Status.IsActionable() {
			continue
		}
		n := Notification{
			Finding: f,
			Title:   defaultTitle(f),
			Body:    defaultBody(f, opts),
			URL:     defaultURL(f, opts),
			Tags:    append([]string(nil), f.Tags...),
		}
		// Deterministic fingerprint = finding fingerprint + first 8
		// hex of sha256(builder-version) so the dispatcher can
		// dedup across runs without needing a separate per-sink
		// rotation.
		h := sha256.Sum256([]byte(f.Fingerprint()))
		n.Fingerprint = fmt.Sprintf("%x", h[:8])
		out = append(out, n)
	}
	return out
}

// BuildOptions controls Notification rendering.
type BuildOptions struct {
	// URLPrefix is prepended to a per-finding deep-link path. Empty
	// string means no URL is rendered. Operators with a hosted
	// evidence pack point this at their dashboard.
	URLPrefix string

	// Project is the project identifier stamped into the title +
	// tags so cross-project notifications stay distinguishable.
	Project string
}

// Dispatch fans the notifications out to every Configured sink in
// the registry whose Threshold permits them. Errors from individual
// sinks are reported in the aggregated Result.Messages; a failing
// sink never blocks others.
//
// Returns the aggregated Result + the slice of per-sink (sinkName,
// error) pairs for the CLI to format. Per-sink errors are wrapped
// with the sink name so the operator knows which channel failed.
func Dispatch(ctx context.Context, r *Registry, notifications []Notification) (Result, []error) {
	if r == nil {
		r = Default
	}
	var aggregate Result
	var errs []error
	for _, n := range r.Sinks() {
		if !n.Configured() {
			continue
		}
		gated := gateBySeverity(notifications, n.Threshold())
		if len(gated) == 0 {
			continue
		}
		res, err := n.Send(ctx, gated)
		aggregate.Add(res)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n.Name(), err))
		}
	}
	return aggregate, errs
}

// gateBySeverity drops Notifications whose Finding.Severity is
// below threshold. compliancekit.SeverityInfo as threshold means "everything
// actionable passes".
func gateBySeverity(notifications []Notification, threshold compliancekit.Severity) []Notification {
	out := make([]Notification, 0, len(notifications))
	for _, n := range notifications {
		if n.Finding.Severity < threshold {
			continue
		}
		out = append(out, n)
	}
	return out
}

// defaultTitle is the canonical one-line headline. Format:
//
//	[CRITICAL] aws-s3-public-access-block on prod-data
func defaultTitle(f compliancekit.Finding) string {
	resName := f.Resource.Name
	if resName == "" {
		resName = f.Resource.ID
	}
	return fmt.Sprintf("[%s] %s on %s",
		strings.ToUpper(f.Severity.String()),
		f.CheckID,
		resName,
	)
}

// defaultBody is the canonical CommonMark body. Renders title,
// optional message, optional resource detail block, and a footer
// pointing at the deep-link URL (when present).
func defaultBody(f compliancekit.Finding, opts BuildOptions) string {
	var sb strings.Builder
	if f.Message != "" {
		fmt.Fprintf(&sb, "%s\n\n", f.Message)
	}
	fmt.Fprintf(&sb, "- **Severity:** %s\n", f.Severity)
	fmt.Fprintf(&sb, "- **Status:** %s\n", f.Status)
	if f.Resource.Provider != "" {
		fmt.Fprintf(&sb, "- **Provider:** %s\n", f.Resource.Provider)
	}
	if f.Resource.Region != "" {
		fmt.Fprintf(&sb, "- **Region:** %s\n", f.Resource.Region)
	}
	if f.Resource.AccountID != "" {
		fmt.Fprintf(&sb, "- **Account:** %s\n", f.Resource.AccountID)
	}
	if opts.Project != "" {
		fmt.Fprintf(&sb, "- **Project:** %s\n", opts.Project)
	}
	if len(f.Tags) > 0 {
		fmt.Fprintf(&sb, "- **Tags:** %s\n", strings.Join(f.Tags, ", "))
	}
	if url := defaultURL(f, opts); url != "" {
		fmt.Fprintf(&sb, "\nDetails: %s\n", url)
	}
	return sb.String()
}

// defaultURL constructs the deep-link URL from URLPrefix + the
// finding's CheckID + resource ID. Returns "" when no prefix is
// configured. Operators with a hosted evidence pack point
// URLPrefix at their dashboard.
func defaultURL(f compliancekit.Finding, opts BuildOptions) string {
	if opts.URLPrefix == "" {
		return ""
	}
	return fmt.Sprintf("%s/findings/%s/%s",
		strings.TrimRight(opts.URLPrefix, "/"),
		f.CheckID,
		strings.ReplaceAll(f.Resource.ID, "/", "_"),
	)
}

// HTTPClient is the shared http.Client every webhook-based sink
// uses. Single connection pool + 30s timeout so a misconfigured
// sink can't hang the dispatch. Tests can substitute their own via
// the per-sink config struct.
var HTTPClient = &http.Client{Timeout: 30 * time.Second}

// ErrAuth is returned by sinks on 401/403. The CLI surfaces this
// with a clear "check your credentials" message.
var ErrAuth = errors.New("notify: authentication failed")
