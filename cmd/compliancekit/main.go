// Package main is the entry point for the compliancekit binary.
//
// All real work happens in internal/cli — this file exists to inject
// build-time version metadata and delegate to the CLI.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/darpanzope/compliancekit/internal/cli"
)

// These vars are populated by `-ldflags "-X main.version=..."` at build time.
// Default values apply when running via `go run` without ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// ctx is cancelled when the user hits Ctrl-C or the system sends SIGTERM.
	// Every long-lived path in compliancekit accepts a context — this is the root.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := cli.Execute(ctx, cli.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
