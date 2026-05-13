package evidence

import (
	"strings"
	"unicode"
)

// maxSlugLen caps the slug portion of <control-id>-<slug> directory
// names so cross-platform filesystem limits (Windows 260 / NTFS 255
// byte path component limit) are not reached even when nested two
// levels deep under a long out-dir. 40 is comfortably below all of
// those once you account for the framework prefix and control ID.
const maxSlugLen = 40

// slugify lowercases s, collapses non-alphanumeric runs into single
// dashes, trims leading and trailing dashes, and caps the result at
// maxSlugLen. Empty inputs (or inputs that contain no alphanumerics)
// return "control" so the produced directory name is never just the
// control ID with a trailing dash.
//
// Used to derive folder names like "CC6.1-logical-and-physical-access"
// from a (control ID, control name) pair. Stable across runs: same
// input always yields same output.
func slugify(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevDash := true
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(unicode.ToLower(r))
			prevDash = false
		case prevDash:
			// collapse run of separators
		default:
			b.WriteByte('-')
			prevDash = true
		}
	}
	out := strings.TrimRight(b.String(), "-")
	if out == "" {
		return "control"
	}
	if len(out) > maxSlugLen {
		out = strings.TrimRight(out[:maxSlugLen], "-")
	}
	return out
}
