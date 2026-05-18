// Command gencheckdocs renders the canonical check catalog to
// docs/checks.md by introspecting the global core registry.
//
// Run:
//
//	go run ./cmd/gencheckdocs              # writes docs/checks.md
//	go run ./cmd/gencheckdocs -check       # diff against on-disk, exit 1 if stale
//	go run ./cmd/gencheckdocs -out=foo.md  # write somewhere else
//
// The -check mode is what CI runs: 'make docs-check' fails the build
// when the committed catalog drifts from the registry, so a new
// check or a tweaked Title cannot land without the docs being
// regenerated in the same PR.
//
// Why a separate tool rather than a //go:generate sitting inside
// internal/cli? Two reasons. First, the generator must import every
// check package for its init() side-effects, and dragging that import
// graph into a unit test or another command pollutes the binary.
// Second, the registry is intentionally process-global: this is the
// one place we can rely on it being fully populated without
// inventing a sentinel.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	// Side-effect imports populate the default check registry. Mirrors
	// cmd/compliancekit/main.go; if a new provider is added there, it
	// must be added here too -- the docs-check CI gate will fail if
	// the catalog is generated without all provider inits running.
	_ "github.com/darpanzope/compliancekit/internal/checks/aws"
	_ "github.com/darpanzope/compliancekit/internal/checks/digitalocean"
	_ "github.com/darpanzope/compliancekit/internal/checks/gcp"
	_ "github.com/darpanzope/compliancekit/internal/checks/hetzner"
	_ "github.com/darpanzope/compliancekit/internal/checks/k8s"
	_ "github.com/darpanzope/compliancekit/internal/checks/linux"

	"github.com/darpanzope/compliancekit/internal/frameworks"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func main() {
	var (
		outPath = flag.String("out", "docs/checks.md", "output path")
		check   = flag.Bool("check", false, "exit 1 if the output differs from on-disk")
	)
	flag.Parse()

	rendered, err := renderCatalogue()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gencheckdocs: %v\n", err)
		os.Exit(1)
	}

	if *check {
		// G304: outPath is operator-controlled (test gate input).
		//nolint:gosec // operator-supplied input path
		existing, err := os.ReadFile(*outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gencheckdocs: read %s: %v\n", *outPath, err)
			os.Exit(1)
		}
		if !bytes.Equal(existing, rendered) {
			fmt.Fprintf(os.Stderr, "gencheckdocs: %s is stale; run 'make docs'\n", *outPath)
			os.Exit(1)
		}
		fmt.Printf("gencheckdocs: %s is up to date (%d checks)\n", *outPath, len(compliancekit.DefaultRegistry().Checks()))
		return
	}

	if err := os.WriteFile(*outPath, rendered, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "gencheckdocs: write %s: %v\n", *outPath, err)
		os.Exit(1)
	}
	fmt.Printf("gencheckdocs: wrote %s (%d checks)\n", *outPath, len(compliancekit.DefaultRegistry().Checks()))
}

// renderCatalogue assembles the entire docs/checks.md body. Determinism
// is critical: the -check mode compares byte-for-byte against the
// committed file, so map iteration order, time stamps, or sort
// instability would produce false CI failures. The renderer therefore
// sorts every collection and omits any wall-clock content (the
// "generated at" comment is the only timestamp and it is in the
// header banner only).
func renderCatalogue() ([]byte, error) {
	checks := compliancekit.DefaultRegistry().Checks()
	if len(checks) == 0 {
		return nil, fmt.Errorf("registry is empty -- side-effect imports missing")
	}

	var b bytes.Buffer
	writeHeader(&b, len(checks))
	writeCountsByProvider(&b, checks)
	writeCountsBySeverity(&b, checks)
	writeProviderSections(&b, checks)
	return b.Bytes(), nil
}

func writeHeader(b *bytes.Buffer, total int) {
	fmt.Fprintln(b, "# Check catalog")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "<!--")
	fmt.Fprintln(b, "  AUTO-GENERATED FILE -- DO NOT EDIT BY HAND.")
	fmt.Fprintln(b, "  Regenerate with: make docs")
	fmt.Fprintln(b, "  Source of truth: internal/checks/**/*.go (the compliancekit.Check vars).")
	fmt.Fprintln(b, "-->")
	fmt.Fprintln(b)
	fmt.Fprintf(b, "This catalog is generated from the live registry on each release. "+
		"At the current revision, compliancekit ships **%d checks** across the providers below.\n", total)
	fmt.Fprintln(b)
	fmt.Fprintln(b, "Each check below has:")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "- A stable **ID** (the string CI gates and waiver files reference).")
	fmt.Fprintln(b, "- A **severity** in {`critical`, `high`, `medium`, `low`, `info`}.")
	fmt.Fprintln(b, "- A list of **framework controls** it maps to (SOC 2 TSC, ISO 27001:2022 Annex A, CIS Controls v8).")
	fmt.Fprintln(b, "- A **description** of the underlying concern.")
	fmt.Fprintln(b, "- A copy-pastable **remediation** for the typical hosting setup.")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "To inspect a single check from the CLI: `compliancekit checks show <id>`.")
	fmt.Fprintln(b)
}

func writeCountsByProvider(b *bytes.Buffer, checks []compliancekit.Check) {
	counts := map[string]int{}
	for _, c := range checks {
		counts[c.Provider]++
	}
	providers := sortedKeys(counts)

	fmt.Fprintln(b, "## By provider")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "| Provider | Checks |")
	fmt.Fprintln(b, "|---|---:|")
	for _, p := range providers {
		fmt.Fprintf(b, "| `%s` | %d |\n", p, counts[p])
	}
	fmt.Fprintf(b, "| **total** | **%d** |\n", len(checks))
	fmt.Fprintln(b)
}

func writeCountsBySeverity(b *bytes.Buffer, checks []compliancekit.Check) {
	counts := map[string]int{}
	for _, c := range checks {
		counts[c.Severity.String()]++
	}
	order := []string{"critical", "high", "medium", "low", "info"}

	fmt.Fprintln(b, "## By severity")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "| Severity | Checks |")
	fmt.Fprintln(b, "|---|---:|")
	for _, sev := range order {
		if counts[sev] > 0 {
			fmt.Fprintf(b, "| `%s` | %d |\n", sev, counts[sev])
		}
	}
	fmt.Fprintln(b)
}

func writeProviderSections(b *bytes.Buffer, checks []compliancekit.Check) {
	byProvider := map[string][]compliancekit.Check{}
	for _, c := range checks {
		byProvider[c.Provider] = append(byProvider[c.Provider], c)
	}
	for _, p := range sortedKeys(byProvider) {
		list := byProvider[p]
		sort.SliceStable(list, func(i, j int) bool { return list[i].ID < list[j].ID })

		fmt.Fprintf(b, "## %s\n\n", p)
		for _, c := range list {
			writeCheck(b, c)
		}
	}
}

func writeCheck(b *bytes.Buffer, c compliancekit.Check) {
	fmt.Fprintf(b, "### `%s`\n\n", c.ID)
	fmt.Fprintf(b, "**%s** &middot; severity `%s` &middot; service `%s` &middot; resource `%s`\n\n",
		c.Title, c.Severity, c.Service, c.ResourceType)

	if desc := strings.TrimSpace(c.Description); desc != "" {
		fmt.Fprintln(b, desc)
		fmt.Fprintln(b)
	}

	if rem := strings.TrimSpace(c.Remediation); rem != "" {
		fmt.Fprintln(b, "_Remediation:_")
		fmt.Fprintln(b)
		fmt.Fprintf(b, "> %s\n\n", rem)
	}

	if len(c.Frameworks) > 0 {
		writeFrameworkTable(b, c.Frameworks)
	}

	if len(c.Tags) > 0 {
		tags := make([]string, len(c.Tags))
		copy(tags, c.Tags)
		sort.Strings(tags)
		fmt.Fprintf(b, "_Tags:_ `%s`\n\n", strings.Join(tags, "`, `"))
	}
	fmt.Fprintln(b, "---")
	fmt.Fprintln(b)
}

// writeFrameworkTable renders the (framework, control) pairs as a
// small table. Resolves control names from the embedded catalog so a
// reader unfamiliar with control codes ("A.8.21") can see what each
// one represents.
func writeFrameworkTable(b *bytes.Buffer, m map[string][]string) {
	resolved := frameworks.ResolveCheckControls(m)
	// Stable order: by framework ID then by control ID.
	sort.Slice(resolved, func(i, j int) bool {
		if resolved[i].Framework.ID != resolved[j].Framework.ID {
			return resolved[i].Framework.ID < resolved[j].Framework.ID
		}
		return resolved[i].Control.ID < resolved[j].Control.ID
	})

	fmt.Fprintln(b, "_Maps to:_")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "| Framework | Control | Title |")
	fmt.Fprintln(b, "|---|---|---|")
	for _, r := range resolved {
		fmt.Fprintf(b, "| `%s` | `%s` | %s |\n", r.Framework.ID, r.Control.ID, r.Control.Name)
	}
	fmt.Fprintln(b)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
