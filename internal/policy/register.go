package policy

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Per-process Rego module registry. Loaded modules live here so
// `checks list` / `checks show` can answer "what file did this
// check come from" without having to keep a side-table in the CLI.
//
// The Go-check registry is compliancekit.DefaultRegistry (one CheckFunc per
// CheckID). The Rego registry adds metadata that wouldn't make sense
// on a Go check (.rego source path, raw body for `checks show`).
// We mirror writes into compliancekit.DefaultRegistry so the scan engine
// doesn't need to know Rego exists.
var (
	regoMu      sync.RWMutex
	regoModules = map[string]*Module{}
)

// RegisterModule adds one already-loaded Module to both the policy
// package's metadata registry and compliancekit.DefaultRegistry. Mutual
// exclusion with Go checks: if a Go check has already registered
// under the same ID, this returns an error rather than silently
// overwriting. Conflicts are a programmer error — two authors
// gave their checks the same ID — and should fail loud at startup.
func RegisterModule(m *Module) error {
	if m == nil {
		return fmt.Errorf("policy: nil module")
	}
	if m.Check.ID == "" {
		return fmt.Errorf("policy: module %s has empty Check.ID", m.SourcePath)
	}
	if existing, ok := compliancekit.LookupCheck(m.Check.ID); ok {
		source := "Go"
		if existing.Policy != "" {
			source = fmt.Sprintf("Rego (%s)", existing.Policy)
		}
		return fmt.Errorf("policy %s: CheckID %q already registered by %s — duplicate ID",
			m.SourcePath, m.Check.ID, source)
	}

	regoMu.Lock()
	regoModules[m.Check.ID] = m
	regoMu.Unlock()

	compliancekit.Register(m.Check, m.CheckFunc())
	return nil
}

// LoadAndRegisterDir is the production entry point: walks dir for
// .rego files, parses each, registers the successful modules, and
// returns the aggregate of per-file errors. Used by the CLI's
// startup hook in `internal/cli/policy_load.go` (Phase 3).
//
// Returns the number of modules successfully registered + a single
// error wrapping every per-file failure (or nil on full success).
// The caller decides whether to abort on a non-nil error or print
// it as a warning — for embedded policies we want a hard fail; for
// a user-supplied directory we surface and continue.
func LoadAndRegisterDir(ctx context.Context, dir string) (int, error) {
	modules, loadErrs := LoadDir(ctx, dir)
	var registerErrs []error
	registered := 0
	for _, m := range modules {
		if err := RegisterModule(m); err != nil {
			registerErrs = append(registerErrs, err)
			continue
		}
		registered++
	}
	all := append([]error(nil), loadErrs...)
	all = append(all, registerErrs...)
	if len(all) == 0 {
		return registered, nil
	}
	return registered, joinErrs(all)
}

// LoadAndRegisterFS is the embedded-policies entry point: walks an
// fs.FS rooted at root (typically a go:embed FS) and registers every
// .rego found. Mirrors LoadAndRegisterDir's contract.
//
// Embedding policies under internal/policies/ via go:embed is how
// the binary ships built-in policies without a separate data
// directory. Phase 5's side-by-side reimplementations live there.
func LoadAndRegisterFS(ctx context.Context, fsys fs.FS, root string) (int, error) {
	var paths []string
	walkErr := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".rego") && !strings.HasSuffix(path, "_test.rego") {
			paths = append(paths, path)
		}
		return nil
	})
	if walkErr != nil {
		// Missing root inside the embed FS is not an error — gives
		// callers freedom to ship an empty embed and add policies
		// later without changing the bootstrap code. ErrNotExist is
		// the only swallowed case; other walk errors propagate.
		if errors.Is(walkErr, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("policy: walk embed root %q: %w", root, walkErr)
	}
	sort.Strings(paths)

	var loadErrs []error
	var registered int
	for _, p := range paths {
		body, err := fs.ReadFile(fsys, p)
		if err != nil {
			loadErrs = append(loadErrs, fmt.Errorf("policy: read %s: %w", p, err))
			continue
		}
		m, err := Compile(ctx, p, string(body))
		if err != nil {
			loadErrs = append(loadErrs, err)
			continue
		}
		if err := RegisterModule(m); err != nil {
			loadErrs = append(loadErrs, err)
			continue
		}
		registered++
	}
	if len(loadErrs) > 0 {
		return registered, joinErrs(loadErrs)
	}
	return registered, nil
}

// Module returns the registered Module for the given CheckID, or
// nil if the check is not Rego-backed. `checks show` calls this
// to render the source path + body.
func Lookup(id string) *Module {
	regoMu.RLock()
	defer regoMu.RUnlock()
	return regoModules[id]
}

// RegisteredIDs returns the sorted list of Check IDs backed by Rego
// policies. Tests and `policy list` use it to enumerate coverage.
func RegisteredIDs() []string {
	regoMu.RLock()
	defer regoMu.RUnlock()
	out := make([]string, 0, len(regoModules))
	for id := range regoModules {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Reset clears the policy registry AND removes the matching entries
// from compliancekit.DefaultRegistry. Test-only — production code must not
// call this. Symmetry matters: if the policy package mirrors a
// registration into core, the cleanup needs to undo both sides or
// suite-ordering bugs leak state across tests.
func Reset() {
	regoMu.Lock()
	ids := make([]string, 0, len(regoModules))
	for id := range regoModules {
		ids = append(ids, id)
	}
	regoModules = map[string]*Module{}
	regoMu.Unlock()
	for _, id := range ids {
		compliancekit.Unregister(id)
	}
}

// joinErrs formats a slice of errors as a single multi-line error
// readable in CLI output. Avoids `errors.Join` to keep error
// messages render predictably across the codebase.
func joinErrs(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d policy errors:\n", len(errs))
	for i, e := range errs {
		fmt.Fprintf(&sb, "  %d) %s\n", i+1, e.Error())
	}
	return fmt.Errorf("%s", sb.String())
}
