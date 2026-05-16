package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/darpanzope/compliancekit/internal/core"
)

// LoadDir walks dir for *.rego files, parses each into a Module
// with its catalog metadata extracted, and returns the modules
// sorted by Check.ID for deterministic iteration order.
//
// Missing dir is not an error — returns nil, nil. This lets the
// CLI side-effect-load a default policies directory without
// crashing on a fresh checkout that doesn't ship any.
//
// Per-file errors are bundled: one bad file does not block loading
// the rest. The caller decides whether to fail the run on a
// non-empty error slice.
func LoadDir(ctx context.Context, dir string) ([]*Module, []error) {
	if dir == "" {
		return nil, []error{errors.New("policy: LoadDir: empty dir")}
	}
	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []error{fmt.Errorf("policy: stat %s: %w", dir, err)}
	}
	if !info.IsDir() {
		return nil, []error{fmt.Errorf("policy: %s is not a directory", dir)}
	}

	var paths []string
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
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
		return nil, []error{fmt.Errorf("policy: walk %s: %w", dir, walkErr)}
	}
	sort.Strings(paths)

	modules := make([]*Module, 0, len(paths))
	var errs []error
	for _, p := range paths {
		m, err := LoadFile(ctx, p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		modules = append(modules, m)
	}
	sort.SliceStable(modules, func(i, j int) bool {
		return modules[i].Check.ID < modules[j].Check.ID
	})
	return modules, errs
}

// LoadFile parses a single .rego file into a Module. Compile errors
// surface verbatim from OPA; metadata-extraction errors carry a
// per-file prefix so the operator can locate the offending policy.
//
// A loaded module is guaranteed to:
//   - parse + compile cleanly via OPA's rego.New(...)
//   - declare a `metadata` constant matching the required schema
//   - declare a `findings` rule (presence is verified at first
//     Evaluate; loader does not invoke OPA against an empty graph).
func LoadFile(ctx context.Context, path string) (*Module, error) {
	// #nosec G304 — path is operator-supplied (compliancekit.yaml or
	// embedded ship-policy dir).
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	return Compile(ctx, path, string(body))
}

// Compile parses + validates rego source already in memory.
// Splitting this out makes the tests dependency-free of the
// filesystem and lets future callers (Phase 4 `policy test`
// subcommand) pass a stdin-loaded payload.
func Compile(ctx context.Context, path, body string) (*Module, error) {
	pkg, err := extractPackage(body)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}

	// Validate via OPA's parser. We compile to surface syntax errors
	// at load time, not at first Evaluate.
	if _, err := rego.New(rego.Module(path, body), rego.Query(fmt.Sprintf("data.%s", pkg))).PrepareForEval(ctx); err != nil {
		return nil, fmt.Errorf("policy %s: compile: %w", path, err)
	}

	check, err := extractMetadata(ctx, path, body, pkg)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}

	check.Policy = path
	check.Scanner = "" // mutual exclusion — Scanner & Policy can't coexist.

	return &Module{
		SourcePath:  path,
		PackageName: pkg,
		Body:        body,
		Check:       check,
	}, nil
}

// packageRegex captures the Rego `package` line.
var packageRegex = regexp.MustCompile(`(?m)^\s*package\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s*$`)

func extractPackage(body string) (string, error) {
	m := packageRegex.FindStringSubmatch(body)
	if len(m) != 2 {
		return "", errors.New("missing or malformed `package` declaration")
	}
	return m[1], nil
}

// extractMetadata evaluates the policy's `metadata` rule and lifts
// the resulting object onto a core.Check struct. Every policy MUST
// declare a `metadata := { ... }` constant or `metadata = { ... }`
// rule producing an object with at least `id`, `title`, `severity`,
// `provider`, `description`. Missing required fields fail loading
// with a clear pointer to the offending key.
//
// Optional fields lifted verbatim:
//
//	service, resource_type, rationale, remediation, tags[],
//	references[], frameworks{<framework_id>: [...controls]}.
func extractMetadata(ctx context.Context, path, body, pkg string) (core.Check, error) {
	query := fmt.Sprintf("data.%s.metadata", pkg)
	r := rego.New(rego.Query(query), rego.Module(path, body))
	rs, err := r.Eval(ctx)
	if err != nil {
		return core.Check{}, fmt.Errorf("evaluate metadata rule: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 || rs[0].Expressions[0].Value == nil {
		return core.Check{}, errors.New("missing `metadata` rule (declare `metadata := {...}` at the top of the file)")
	}
	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return core.Check{}, fmt.Errorf("marshal metadata: %w", err)
	}
	var meta metadataDoc
	if err := json.Unmarshal(raw, &meta); err != nil {
		return core.Check{}, fmt.Errorf("decode metadata: %w", err)
	}
	return meta.toCheck()
}

// metadataDoc mirrors the Rego `metadata` object shape. Field names
// are snake_case in Rego (the idiomatic style); we map them to the
// PascalCase core.Check fields here.
type metadataDoc struct {
	ID           string              `json:"id"`
	Title        string              `json:"title"`
	Severity     string              `json:"severity"`
	Provider     string              `json:"provider"`
	Service      string              `json:"service"`
	ResourceType string              `json:"resource_type"`
	Description  string              `json:"description"`
	Rationale    string              `json:"rationale"`
	Remediation  string              `json:"remediation"`
	Frameworks   map[string][]string `json:"frameworks"`
	Tags         []string            `json:"tags"`
	References   []string            `json:"references"`
}

func (m metadataDoc) toCheck() (core.Check, error) {
	missing := func(field string) error {
		return fmt.Errorf("metadata.%s is required", field)
	}
	if m.ID == "" {
		return core.Check{}, missing("id")
	}
	if m.Title == "" {
		return core.Check{}, missing("title")
	}
	if m.Description == "" {
		return core.Check{}, missing("description")
	}
	if m.Severity == "" {
		return core.Check{}, missing("severity")
	}
	if m.Provider == "" {
		return core.Check{}, missing("provider")
	}
	sev, err := core.ParseSeverity(m.Severity)
	if err != nil {
		return core.Check{}, fmt.Errorf("metadata.severity: %w", err)
	}
	return core.Check{
		ID:           m.ID,
		Title:        m.Title,
		Severity:     sev,
		Provider:     m.Provider,
		Service:      m.Service,
		ResourceType: m.ResourceType,
		Description:  m.Description,
		Rationale:    m.Rationale,
		Remediation:  m.Remediation,
		Frameworks:   m.Frameworks,
		Tags:         m.Tags,
		References:   m.References,
	}, nil
}
