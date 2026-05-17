package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/notify"
)

// newNotifyCmd builds `compliancekit notify`, which dispatches
// findings to every configured notification channel (Slack, Discord,
// Teams, Email, Webhook, GitHub PR, Jira, PagerDuty) per v0.17.
//
// Two modes:
//   - `notify --list`            enumerate registered sinks + status
//   - `notify --in=findings.json` dispatch with optional --baseline,
//     --severity, --project, --url-prefix
//
// Per ADR-006: notification is generation, not telemetry. Every sink
// is operator-configured via env vars or compliancekit.yaml; missing
// credentials = sink skipped silently.
func newNotifyCmd() *cobra.Command {
	var opts notifyOptions
	cmd := &cobra.Command{
		Use:   "notify",
		Short: "Dispatch findings to Slack / Discord / Teams / Email / Webhook / GitHub PR / Jira / PagerDuty",
		Long: `Send compliancekit findings to operator-configured notification
channels. Each sink reads its credentials from env vars (or the
notify: block in compliancekit.yaml); a sink with missing credentials
is skipped silently — one channel never blocks the others.

Workflows:

  # See registered sinks + per-sink configuration status
  compliancekit notify --list

  # Dispatch every actionable finding to every configured sink
  compliancekit scan --config=compliancekit.yaml --out=findings.json
  compliancekit notify --in=findings.json

  # Only-new mode: dispatch only findings that appeared since the
  # last baseline (no spam on every scan)
  compliancekit notify --in=findings.json --baseline=.compliancekit/baseline.json

  # Restrict to a single severity floor across every sink
  compliancekit notify --in=findings.json --severity=high

Per-sink severity thresholds apply on top of --severity. A sink set
to PAGERDUTY_THRESHOLD=critical still pages on critical only even
when --severity=medium is passed.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runNotify(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}
	cmd.Flags().BoolVar(&opts.list, "list", false, "list registered sinks + per-sink configured/threshold status, then exit")
	cmd.Flags().StringVar(&opts.in, "in", "", "path to findings JSON (output of `scan` or `ingest`; - for stdin)")
	cmd.Flags().StringVar(&opts.baseline, "baseline", "", "path to baseline.json; only findings new since baseline are dispatched (v0.6+)")
	cmd.Flags().StringVar(&opts.severity, "severity", "", "global severity floor: info | low | medium | high | critical (overrides per-sink floor when stricter)")
	cmd.Flags().StringVar(&opts.project, "project", "", "project identifier stamped into notification body")
	cmd.Flags().StringVar(&opts.urlPrefix, "url-prefix", "", "URL prefix for deep-link buttons (e.g. https://compliance.acme.com)")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "render notifications + show per-sink plan; do not send")
	return cmd
}

type notifyOptions struct {
	list      bool
	in        string
	baseline  string
	severity  string
	project   string
	urlPrefix string
	dryRun    bool
}

func runNotify(ctx context.Context, stdout io.Writer, opts notifyOptions) error {
	if opts.list {
		return runNotifyList(stdout)
	}
	if opts.in == "" {
		return fmt.Errorf("notify: --in is required (path to findings JSON or '-' for stdin)")
	}

	findings, err := loadNotifyFindings(opts.in)
	if err != nil {
		return fmt.Errorf("load findings: %w", err)
	}
	findings, err = applyFilters(stdout, findings, opts)
	if err != nil {
		return err
	}

	notifications := notify.BuildNotifications(findings, notify.BuildOptions{
		URLPrefix: opts.urlPrefix,
		Project:   opts.project,
	})

	if opts.dryRun {
		return printDispatchPlan(stdout, notifications)
	}
	return dispatchAndReport(ctx, stdout, notifications)
}

// applyFilters runs the baseline subtraction + global severity floor.
// Extracted so runNotify stays under the gocyclo ceiling.
func applyFilters(stdout io.Writer, findings []core.Finding, opts notifyOptions) ([]core.Finding, error) {
	if opts.baseline != "" {
		baseFingerprints, err := loadBaselineFingerprints(opts.baseline)
		if err != nil {
			return nil, fmt.Errorf("load baseline: %w", err)
		}
		var filtered []core.Finding
		for _, f := range findings {
			if !baseFingerprints[f.Fingerprint()] {
				filtered = append(filtered, f)
			}
		}
		fmt.Fprintf(stdout, "Only-new-findings mode: %d → %d after subtracting %d baseline fingerprints.\n",
			len(findings), len(filtered), len(baseFingerprints))
		findings = filtered
	}
	if opts.severity == "" {
		return findings, nil
	}
	floor, err := core.ParseSeverity(opts.severity)
	if err != nil {
		return nil, fmt.Errorf("--severity: %w", err)
	}
	var filtered []core.Finding
	for _, f := range findings {
		if f.Severity >= floor {
			filtered = append(filtered, f)
		}
	}
	fmt.Fprintf(stdout, "Global severity floor=%s: %d → %d.\n", floor, len(findings), len(filtered))
	return filtered, nil
}

// dispatchAndReport fans out to every Configured sink + prints the
// per-sink message log. Returns a non-nil error iff any sink failed.
func dispatchAndReport(ctx context.Context, stdout io.Writer, notifications []notify.Notification) error {
	res, errs := notify.Dispatch(ctx, notify.Default, notifications)
	fmt.Fprintf(stdout, "Dispatch summary: sent=%d, errors=%d (across %d sinks)\n",
		res.Sent, res.Errors, configuredSinkCount())
	for _, m := range res.Messages {
		fmt.Fprintf(stdout, "  %s\n", m)
	}
	for _, e := range errs {
		fmt.Fprintf(stdout, "  ERR: %v\n", e)
	}
	if len(errs) > 0 {
		return fmt.Errorf("notify: %d sink(s) reported errors", len(errs))
	}
	return nil
}

// runNotifyList prints the registered sinks + their per-sink
// Configured() + Threshold() so operators can verify env-driven
// configuration at a glance.
func runNotifyList(stdout io.Writer) error {
	sinks := notify.Default.Sinks()
	fmt.Fprintf(stdout, "%-14s %-12s %s\n", "SINK", "CONFIGURED", "THRESHOLD")
	fmt.Fprintf(stdout, "%s\n", strings.Repeat("-", 50))
	for _, s := range sinks {
		fmt.Fprintf(stdout, "%-14s %-12v %s\n", s.Name(), s.Configured(), s.Threshold())
	}
	fmt.Fprintf(stdout, "\n%d sink(s) registered, %d configured.\n",
		len(sinks), configuredSinkCount())
	return nil
}

// printDispatchPlan prints the per-sink plan without actually
// sending. Used by --dry-run for verifying which findings would
// land on which sink.
func printDispatchPlan(stdout io.Writer, notifications []notify.Notification) error {
	fmt.Fprintf(stdout, "Dry run — %d notification(s) prepared.\n\n", len(notifications))
	sinks := notify.Default.Sinks()
	for _, s := range sinks {
		if !s.Configured() {
			fmt.Fprintf(stdout, "[skip ] %s — not configured\n", s.Name())
			continue
		}
		passing := 0
		for _, n := range notifications {
			if n.Finding.Severity >= s.Threshold() {
				passing++
			}
		}
		fmt.Fprintf(stdout, "[ready] %s — %d/%d would be sent (threshold=%s)\n",
			s.Name(), passing, len(notifications), s.Threshold())
	}
	return nil
}

// configuredSinkCount returns the count of sinks whose Configured()
// returns true. Used in the summary line.
func configuredSinkCount() int {
	n := 0
	for _, s := range notify.Default.Sinks() {
		if s.Configured() {
			n++
		}
	}
	return n
}

// loadNotifyFindings reads findings JSON from path (or stdin when
// path is "-"). Reuses the shared loadFindings from evidence.go for
// the path case; only owns the stdin case.
func loadNotifyFindings(path string) ([]core.Finding, error) {
	if path != "-" {
		return loadFindings(path)
	}
	body, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}
	var env struct {
		Findings []core.Finding `json:"findings"`
	}
	if err := json.Unmarshal(body, &env); err == nil && env.Findings != nil {
		return env.Findings, nil
	}
	var arr []core.Finding
	if err := json.Unmarshal(body, &arr); err == nil {
		return arr, nil
	}
	return nil, fmt.Errorf("unrecognized findings JSON shape on stdin")
}

// loadBaselineFingerprints reads the baseline.json produced by
// `compliancekit baseline` and returns the set of Finding.Fingerprint
// values. Findings whose Fingerprint is in this set are considered
// pre-existing (not new) and dropped by only-new-findings mode.
//
// Schema accepts both the canonical {"findings": [...]} envelope and
// a bare array — same as the loaders in evidence.go and remediate.go.
func loadBaselineFingerprints(path string) (map[string]bool, error) {
	findings, err := loadFindings(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(findings))
	for _, f := range findings {
		out[f.Fingerprint()] = true
	}
	return out, nil
}

// sortNotificationsBySeverityDesc sorts highest severity first.
// Used by the dispatch plan + some sinks that show "top N" lists.
// Currently unused by the CLI proper but exposed for tests + future
// sinks (PagerDuty-incident-rollup).
func sortNotificationsBySeverityDesc(notifications []notify.Notification) {
	sort.SliceStable(notifications, func(i, j int) bool {
		return notifications[i].Finding.Severity > notifications[j].Finding.Severity
	})
}

// nowTimestamp is a small helper for tests that want to assert the
// dispatch ran at a deterministic time. Unused in production.
func nowTimestamp() time.Time { return time.Now().UTC() }

var _ = sortNotificationsBySeverityDesc
var _ = nowTimestamp
