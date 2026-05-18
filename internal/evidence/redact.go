package evidence

import (
	"regexp"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Redaction policy: messages emitted by checks at v0.3 contain hostnames,
// droplet names, sysctl values, and similar low-sensitivity strings.
// They do NOT contain credentials -- we deliberately do not log
// password hashes, SSH keys, or API tokens. The redactor below is a
// belt-and-braces filter for the edge cases (a custom check that
// accidentally captures a token, or future raw-collector payloads in
// v0.5) and is wired in now so the seam exists before we need it.
//
// When IncludeRaw is false (the default), the redactor runs over the
// Message and Evidence fields of every finding before serialization.
// When IncludeRaw is true the redactor is a no-op -- the operator has
// explicitly asked for an unredacted pack for the auditor-trusted
// case, and double-masking would surprise them.

// patterns lists the regex + replacement pairs applied to every
// message in redact mode. Ordering matters only insofar as some
// patterns are subsets of others (e.g. an AWS access key id matches
// the more general "long alphanumeric token" pattern); each rule is
// independent and the more specific patterns are listed first.
var patterns = []struct {
	rx     *regexp.Regexp
	repl   string
	reason string
}{
	// AWS access key id (AKIA + 16 base32). Listed before the
	// generic API key rule so the redacted output names the type.
	{
		rx:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		repl:   "[REDACTED:aws-access-key]",
		reason: "aws-access-key",
	},
	// GitHub personal access tokens (classic + fine-grained share
	// the gh? prefix family).
	{
		rx:     regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),
		repl:   "[REDACTED:github-token]",
		reason: "github-token",
	},
	// Slack tokens (xoxb-, xoxp-, xoxa-, xoxr-).
	{
		rx:     regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),
		repl:   "[REDACTED:slack-token]",
		reason: "slack-token",
	},
	// Generic Bearer/Authorization header values. The leading
	// whitespace-or-equals capture is preserved so the original
	// surrounding text remains readable.
	{
		rx:     regexp.MustCompile(`(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._\-]+`),
		repl:   "${1}[REDACTED:bearer-token]",
		reason: "bearer-token",
	},
	// Email addresses. Conservative: strip to domain so an auditor
	// can still see "internal vs external" without seeing the user.
	{
		rx:     regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b`),
		repl:   "[REDACTED:email]@$1",
		reason: "email",
	},
}

// redactFindings applies the redaction policy to every finding's
// Message and Evidence.Path. When includeRaw is true the input is
// returned unchanged. The returned slice is a new slice; the original
// is not mutated so reporters running after the evidence pack still
// see the unredacted findings.
func redactFindings(in []compliancekit.Finding, includeRaw bool) []compliancekit.Finding {
	if includeRaw {
		return in
	}
	out := make([]compliancekit.Finding, len(in))
	for i, f := range in {
		f.Message = redactString(f.Message)
		// Evidence.Path is filesystem-local and may include a user
		// home directory or other identifying path; mask it too.
		if f.Evidence.Path != "" {
			f.Evidence.Path = redactString(f.Evidence.Path)
		}
		out[i] = f
	}
	return out
}

// redactString runs every pattern over s and returns the redacted
// result. Patterns are non-overlapping in practice (each looks for a
// distinct token shape); when they do overlap, the order in the
// patterns slice determines which label wins.
func redactString(s string) string {
	for _, p := range patterns {
		s = p.rx.ReplaceAllString(s, p.repl)
	}
	return s
}
