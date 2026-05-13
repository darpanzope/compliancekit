// Package main is the entry point for the compliancekit binary.
//
// All real work happens in internal/cli — this file exists to inject
// build-time version metadata and delegate to the CLI.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/darpanzope/compliancekit/internal/cli"

	// Side-effect import: each checks package's init() registers its
	// CheckFuncs into the default registry so the scan command can find
	// them. Adding a new provider's checks package means adding one
	// import line here.
	_ "github.com/darpanzope/compliancekit/internal/checks/digitalocean"
)

// These vars are populated by `-ldflags "-X main.version=..."` at build time.
// Default values apply when running via `go run` without ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// main delegates to run so deferred functions (notably the signal
// context cleanup) execute before os.Exit terminates the process.
// Calling os.Exit inside main would skip them.
func main() {
	os.Exit(run())
}

// run executes the CLI and returns the intended process exit code.
//
// The split lets defers in this function (signal cancel, file closers)
// run before the process terminates. The pattern is the standard Go
// answer to gocritic's exitAfterDefer warning.
func run() int {
	// ctx is canceled when the user hits Ctrl-C or the system sends SIGTERM.
	// Every long-lived path in compliancekit accepts a context — this is the root.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	err := cli.Execute(ctx, cli.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	})
	if err == nil {
		return 0
	}

	// ExitCodeError carries an intentional non-zero exit code for outcomes
	// that are not "the tool failed" (e.g. scan found high-severity
	// findings). Other errors print with "error:" and exit 1.
	var ec *cli.ExitCodeError
	if errors.As(err, &ec) {
		fmt.Fprintln(os.Stderr, ec.Message)
		return ec.Code
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	return 1
}
