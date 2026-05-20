package comments

import (
	"regexp"
	"strings"
)

// mentionRE matches @<token> where token is a sequence of letters,
// digits, underscores, dots, dashes. The lookbehind for "not in the
// middle of a word" is approximated by requiring whitespace, line
// start, or specific punctuation before the @.
var mentionRE = regexp.MustCompile(`(^|[\s\(\[\{,;:!?])@([A-Za-z0-9._-]+)`)

// ExtractMentions returns the unique @handles referenced in body,
// preserving insertion order. The handle is everything between the
// "@" and the first non-handle character — typically a username,
// email local-part, or "team-<slug>".
//
// The pattern is conservative: a token starting with a dot or dash
// is dropped, and minimum length is 2 characters so common false
// positives ("@", "@.", "@@") drop out.
func ExtractMentions(body string) []string {
	if body == "" {
		return nil
	}
	matches := mentionRE.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		handle := strings.TrimSpace(m[2])
		// Reject ":" and other separators (regex shouldn't return them
		// anyway, but cheap defensive trim).
		handle = strings.TrimRight(handle, ".,;:!?")
		if len(handle) < 2 {
			continue
		}
		if handle[0] == '.' || handle[0] == '-' {
			continue
		}
		if seen[handle] {
			continue
		}
		seen[handle] = true
		out = append(out, handle)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
