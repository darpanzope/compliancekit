// Package repocheck holds repo-wide structural invariants enforced as
// Go tests so the per-commit gate catches drift.
//
// v0.22 introduces the first invariant: no check-registration file
// under internal/checks/ may exceed 600 LoC. Bigger files become
// hard to scan + diff + refactor; the v0.20 spec-driven pattern
// dramatically cuts new-check LoC, so the ceiling stays achievable
// even as the catalog grows.
package repocheck

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// maxCheckFileLOC is the v0.22 invariant ceiling. Splitting a file
// past this triggers a CI failure (caught at pre-commit). Test files
// are excluded — they often duplicate fixture data + are read in
// isolation per check shape.
const maxCheckFileLOC = 600

// legacyOversizeAllowlist enumerates the files that breached the
// 600-LoC invariant at v0.22 entry, with their measured LoC. The
// ratchet shape mirrors TestParity_DigitalOcean / TestParity_Linux /
// TestParity_Kubernetes:
//
//   - A NEW file >600 LoC fails the test (would have to be added to
//     the allowlist explicitly — code review catches that).
//   - A LEGACY file that drops to ≤600 LoC ALSO fails (the ratchet is
//     stale; the entry must be removed from the map).
//
// As v0.22 Phases 1-3 split each oversize file, its allowlist entry
// is removed in the same commit. By Phase 3 close the map is empty +
// the test becomes a strict equality gate.
var legacyOversizeAllowlist = map[string]int{
	// rbac.go split out at v0.22 phase 1 (→ rbac_roles.go + rbac_bindings.go).
	// pods.go split out at v0.22 phase 2 (→ pods_resources.go + pods_volumes.go).
	"internal/checks/k8s/network.go":       879,
	"internal/checks/k8s/cluster.go":       701,
	"internal/checks/k8s/reliability.go":   671,
	"internal/checks/k8s/eks.go":           649,
	"internal/checks/aws/iam.go":           635,
	"internal/checks/k8s/pods_extra.go":    627,
	"internal/checks/digitalocean/tail.go": 602,
}

func TestCheckFilesUnderSizeLimit(t *testing.T) {
	// Walk from the repo root via the package's own location. Tests
	// run with CWD = the package dir, so traverse up to find the
	// internal/checks/ tree.
	root := findRepoRoot(t)
	checksDir := filepath.Join(root, "internal", "checks")

	type oversizeEntry struct {
		path string
		loc  int
	}
	var allOversize []oversizeEntry

	err := filepath.Walk(checksDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		loc, err := countLines(path)
		if err != nil {
			return err
		}
		if loc > maxCheckFileLOC {
			rel, _ := filepath.Rel(root, path)
			allOversize = append(allOversize, oversizeEntry{path: rel, loc: loc})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", checksDir, err)
	}

	sort.Slice(allOversize, func(i, j int) bool { return allOversize[i].path < allOversize[j].path })

	// Bucket the current oversize set against the allowlist.
	var unexpected, fixed []string
	currentlyOversize := map[string]int{}
	for _, e := range allOversize {
		currentlyOversize[e.path] = e.loc
		if _, allowed := legacyOversizeAllowlist[e.path]; !allowed {
			unexpected = append(unexpected, formatOversize(e.path, e.loc))
		}
	}
	for path := range legacyOversizeAllowlist {
		if _, stillOversize := currentlyOversize[path]; !stillOversize {
			fixed = append(fixed, path)
		}
	}

	switch {
	case len(unexpected) > 0:
		t.Errorf("CHECK-FILE SIZE INVARIANT REGRESSED: %d new file(s) breached %d-LoC ceiling.\n"+
			"v0.22 invariant: every internal/checks/ file ≤ %d LoC. Split this file along its existing\n"+
			"logical boundaries (the spec-driven pattern documented in docs/DEVELOPMENT.md keeps the\n"+
			"split cheap). If the file genuinely warrants the size, add it to legacyOversizeAllowlist\n"+
			"in this test with a code-review-approved rationale.\n\nOver-ceiling:\n  %s",
			len(unexpected), maxCheckFileLOC, maxCheckFileLOC, strings.Join(unexpected, "\n  "))
	case len(fixed) > 0:
		t.Errorf("CHECK-FILE SIZE INVARIANT IMPROVED past ratchet: %d allowlist entr(y/ies) no longer\n"+
			"breach the %d-LoC ceiling. Remove from legacyOversizeAllowlist in this test so future\n"+
			"regressions get caught.\n\nNow under ceiling:\n  %s",
			len(fixed), maxCheckFileLOC, strings.Join(fixed, "\n  "))
	}

	totalLOC := 0
	for _, e := range allOversize {
		totalLOC += e.loc
	}
	t.Logf("Check-file size: %d total .go files | %d still over %d-LoC ceiling (all allow-listed) | %d LoC in oversize files",
		countNonTestGoFiles(t, checksDir), len(allOversize), maxCheckFileLOC, totalLOC)
}

func formatOversize(path string, loc int) string {
	return fmt.Sprintf("%s (%d LoC)", path, loc)
}

// countLines returns the number of '\n'-terminated lines in path,
// plus 1 if the final line lacks a newline. Matches `wc -l` semantics
// closely enough for the invariant check.
func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	n := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		n++
	}
	return n, scanner.Err()
}

// countNonTestGoFiles walks the dir + counts .go files excluding tests.
func countNonTestGoFiles(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			n++
		}
		return nil
	})
	return n
}

// findRepoRoot walks up from the package's runtime CWD looking for
// go.mod. Used so the test works no matter where `go test` is invoked.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find go.mod from %s", dir)
		}
		dir = parent
	}
}
