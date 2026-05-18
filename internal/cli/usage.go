package cli

import (
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/ui"
)

// styleHelp installs a custom help printer on the root command (and
// recursively on every subcommand) so the `--help` output picks up
// section headers in bold + an accented command name. The template
// shape mirrors Cobra's default minus the boilerplate the project
// doesn't use (no aliases, no global commands list — every
// subcommand is reachable directly).
//
// The Styler is constructed lazily inside the help printer because
// the --no-color flag must be parsed before we can render, and
// Cobra calls help at a point where the persistent flag set is
// finalized.
func styleHelp(root *cobra.Command) {
	root.SetHelpFunc(func(cmd *cobra.Command, _ []string) {
		st := stylerFor(cmd)
		w := cmd.OutOrStdout()
		printStyledHelp(w, st, cmd)
	})
}

// printStyledHelp renders cmd's help text with section headers in
// bold + the command name accented. The layout mirrors Cobra's
// default — `Description` paragraph, then optional `Examples`,
// then `Usage`, `Aliases`, `Available Commands`, `Flags`,
// `Global Flags`, and the `Use "X help [cmd]" for more` footer.
func printStyledHelp(w io.Writer, st *ui.Styler, cmd *cobra.Command) {
	section := func(title string) {
		_, _ = io.WriteString(w, "\n"+st.Bold(title)+"\n")
	}
	body := func(text string) {
		_, _ = io.WriteString(w, "  "+text+"\n")
	}

	// Header: bold command name + short.
	if cmd.Short != "" {
		_, _ = io.WriteString(w, st.Accent(cmd.CommandPath())+" — "+cmd.Short+"\n")
	} else {
		_, _ = io.WriteString(w, st.Accent(cmd.CommandPath())+"\n")
	}

	if cmd.Long != "" {
		_, _ = io.WriteString(w, "\n"+cmd.Long+"\n")
	}

	// Usage line.
	section("Usage:")
	body(cmd.UseLine())
	if cmd.HasAvailableSubCommands() {
		body(cmd.CommandPath() + " [command]")
	}

	// Available commands (only direct, non-hidden children).
	if cmd.HasAvailableSubCommands() {
		section("Available Commands:")
		maxNameLen := longestCommandName(cmd)
		for _, sub := range cmd.Commands() {
			if !sub.IsAvailableCommand() || sub.Name() == "help" {
				continue
			}
			name := sub.Name() + strings.Repeat(" ", maxNameLen-len(sub.Name()))
			body(st.Accent(name) + "   " + sub.Short)
		}
	}

	// Local flags.
	if hasFlags(cmd) {
		section("Flags:")
		_, _ = io.WriteString(w, indentLines(cmd.LocalFlags().FlagUsages(), 2))
	}
	if hasInheritedFlags(cmd) {
		section("Global Flags:")
		_, _ = io.WriteString(w, indentLines(cmd.InheritedFlags().FlagUsages(), 2))
	}

	// Footer pointer back to per-subcommand help.
	if cmd.HasAvailableSubCommands() {
		_, _ = io.WriteString(w, "\n"+st.Muted("Use \""+cmd.CommandPath()+" [command] --help\" for more information about a command.")+"\n")
	}
}

// longestCommandName returns the max name length across cmd's
// available subcommands, used to align the description column in
// the "Available Commands" section.
func longestCommandName(cmd *cobra.Command) int {
	maxLen := 0
	for _, sub := range cmd.Commands() {
		if !sub.IsAvailableCommand() || sub.Name() == "help" {
			continue
		}
		if n := len(sub.Name()); n > maxLen {
			maxLen = n
		}
	}
	return maxLen
}

func hasFlags(cmd *cobra.Command) bool {
	return cmd.LocalFlags().HasAvailableFlags()
}

func hasInheritedFlags(cmd *cobra.Command) bool {
	return cmd.InheritedFlags().HasAvailableFlags()
}

// indentLines prefixes every line of s with n spaces. Used to nest
// Cobra's pre-formatted FlagUsages output under the styled section
// headers.
func indentLines(s string, n int) string {
	if s == "" {
		return ""
	}
	pad := strings.Repeat(" ", n)
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n") + "\n"
}
