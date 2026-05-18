// Package ui owns the terminal styling primitives shared across every
// compliancekit subcommand: the severity-and-status color palette,
// the status glyph set, the TTY/NO_COLOR detector, and a thin Styler
// over lipgloss that subcommands ask for their colors instead of
// hand-coding ANSI escapes.
//
// One source of truth keeps the look consistent across `scan`,
// `diff`, `doctor`, `checks list`, `waivers list`, `mapping list`,
// `notify --list`, and `policy validate`. A palette tweak lands in
// one place; snapshot tests under both color and plain modes catch
// accidental drift.
//
// # Disabling color
//
// Output is plain (no ANSI, no Unicode glyphs beyond ASCII fallbacks)
// when any of the following is true:
//
//   - stdout is not a TTY (CI runs, piped through tee, redirected
//     to a file)
//   - the NO_COLOR environment variable is set, per the
//     [no-color.org spec]
//   - the --no-color CLI flag is passed (forces plain even on a TTY)
//   - the CLICOLOR=0 environment variable is set
//
// Subcommands query [IsColorEnabled] once at startup and pass the
// result through to a [Styler] (via [NewStyler]). The Styler renders
// either ANSI-colored or plain output depending on that one
// decision — no per-call branching in the call sites.
//
// # Audience for this package
//
// Authors of internal/cli/* subcommands. Not part of pkg/compliancekit;
// internal/ui is implementation detail and may evolve freely.
//
// [no-color.org spec]: https://no-color.org
package ui
