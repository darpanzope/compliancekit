package ui

import (
	"io"
	"os"
)

// IsColorEnabled reports whether the calling subcommand should emit
// ANSI-colored output to w. The decision walks the following gates
// in order; the first negative wins.
//
//  1. The --no-color CLI flag (passed in by the caller via forceOff)
//     forces plain output even on a TTY.
//  2. NO_COLOR set to any value (per no-color.org) → plain.
//  3. CLICOLOR=0 → plain (legacy convention from BSDs / git).
//  4. w is not a *os.File whose Fd() is a terminal → plain. CI runs
//     and piped output land here.
//
// The default when none of the above triggers is color-on.
//
// Subcommands call this once at startup, pass the result to
// [NewStyler], and never branch on it themselves.
func IsColorEnabled(w io.Writer, forceOff bool) bool {
	if forceOff {
		return false
	}
	if _, present := os.LookupEnv("NO_COLOR"); present {
		return false
	}
	if v, present := os.LookupEnv("CLICOLOR"); present && v == "0" {
		return false
	}
	return isTerminal(w)
}

// isTerminal reports whether w is a writer attached to a terminal
// (vs. a pipe, file, or in-memory buffer). Only *os.File whose
// underlying file descriptor refers to a tty returns true.
//
// Kept un-mockable on purpose — the env-var gates in IsColorEnabled
// are what tests vary; tty-ness for tests is "is the test writer a
// real terminal," which is always false under `go test`.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return isFdTerminal(f.Fd())
}
