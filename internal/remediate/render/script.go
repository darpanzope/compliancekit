// Package render holds small shared helpers strategy packages use to
// emit safe, well-formatted snippet content. The helpers are
// intentionally tiny — strategies are hand-written Go, not template
// engines — but the few primitives that have a wrong-and-quiet failure
// mode (shell quoting, HCL escaping, YAML key ordering) live here so
// every strategy in every subpackage shares the same implementation.
package render

import (
	"fmt"
	"strings"
)

// ShellQuote wraps s in single quotes with embedded single quotes
// escaped via the POSIX-portable '"'"' dance. Use it for any value
// the operator's shell will interpret — bucket names, ARNs, IDs,
// regions, anything that could plausibly contain a space, a $, or
// a backtick.
//
// Returns "”" for the empty string so the resulting command line
// still parses as the empty argument rather than silently dropping
// a positional slot.
func ShellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !needsQuoting(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// ShellQuoteAll applies ShellQuote to every element and joins with
// single spaces. Convenience for the common "build a command line"
// pattern in cloud-CLI strategies.
func ShellQuoteAll(args ...string) string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = ShellQuote(a)
	}
	return strings.Join(out, " ")
}

// needsQuoting reports whether s contains any character that would
// be interpreted by /bin/sh. We err on the side of quoting more
// often: a few extra quotes hurt nothing; a missing one is a
// command-injection footgun.
func needsQuoting(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.' || r == '/' || r == ':':
		default:
			return true
		}
	}
	return false
}

// CommentBash wraps text as a POSIX-sh comment block. Used by every
// strategy to prefix its Content with a one-line summary the operator
// reads before pasting. Multi-line input is split on \n; each line
// gets its own '# ' prefix.
func CommentBash(text string) string {
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = "# " + l
	}
	return strings.Join(lines, "\n")
}

// Heredoc wraps body in a bash heredoc with the given delimiter.
// Used by strategies that need to pipe multi-line payloads into a
// CLI (e.g. `aws s3api put-bucket-policy --policy "$(cat <<'EOF'
// {...} EOF )"`). The single-quoted delimiter disables variable
// interpolation — important because policy JSON often contains
// $-prefixed Principal fields.
func Heredoc(delim, body string) string {
	if delim == "" {
		delim = "EOF"
	}
	body = strings.TrimRight(body, "\n")
	return fmt.Sprintf("<<'%s'\n%s\n%s", delim, body, delim)
}
