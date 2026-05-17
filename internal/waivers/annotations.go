package waivers

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ScanAnnotations walks `root` for files matching the v0.18
// annotation comment convention and lifts each match into a Waiver
// suitable for merging into a WaiverList.
//
// Comment shape (line-anchored regex, applied per line):
//
//	# compliancekit:waive <check-id> <resource-id> [reason="..."] [approver=...] [expires=YYYY-MM-DD]
//
// Languages handled:
//   - Terraform / HCL (.tf, .tfvars)        — `#` and `//` line comments
//   - YAML (.yaml, .yml)                    — `#` line comments
//   - Bash / sh (.sh, .bash)                — `#` line comments
//   - Python (.py)                          — `#` line comments
//   - Dockerfile (Dockerfile, *.dockerfile) — `#` line comments
//   - Go (.go)                              — `//` line comments
//
// File extensions outside this set are silently skipped — adding a
// new one is a one-line change in the languageHandlers map below.
//
// Missing root is NOT an error — returns empty slice + nil so the
// scan engine can call this unconditionally. Read errors on
// individual files emit a warning to errs and continue.
//
// Reason + approver + expires are OPTIONAL on the annotation line
// (the operator may keep those in a sibling waivers.yaml and use
// the annotation as a pointer). When the annotation OMITS them:
//   - reason defaults to "annotation in <path>:<line>"
//   - approver defaults to "@annotation" (operator can override
//     repo-wide via WAIVER_ANNOTATION_APPROVER env var; out of
//     scope for v0.18 — keeps the spec narrow)
//   - expires defaults to 90 days from `now` (forces re-review)
//
// These defaults are intentionally lenient at the scanner level;
// Validate still runs (so a reason that ends up < 16 chars after
// substitution gets rejected at NewWaiverList time, surfacing in
// `compliancekit waivers validate` output).
func ScanAnnotations(root string, now time.Time) ([]Waiver, []error) {
	if root == "" {
		return nil, nil
	}
	info, err := os.Stat(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []error{fmt.Errorf("waivers: scan annotations: stat %s: %w", root, err)}
	}
	if !info.IsDir() {
		// Single file — useful when callers want to scan one specific
		// IaC module without walking a whole tree.
		return scanFile(root, now)
	}

	var waivers []Waiver
	var errs []error
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !shouldScanFile(path) {
			return nil
		}
		fileWaivers, fileErrs := scanFile(path, now)
		waivers = append(waivers, fileWaivers...)
		errs = append(errs, fileErrs...)
		return nil
	})
	if walkErr != nil {
		errs = append(errs, fmt.Errorf("waivers: walk %s: %w", root, walkErr))
	}
	return waivers, errs
}

// annotationRegex captures the v0.18 annotation comment shape.
// Anchored on either `#` or `//` (per the languageHandlers table)
// so file types using line-comment syntax other than these two are
// silently ignored.
//
// Capture groups:
//
//	1: check_id   (required, kebab-case)
//	2: resource_id (required, dot-separated; allows `*` `?` `[`)
//	3: trailing keyword args (optional reason="..." approver=... expires=...)
//
// The keyword-arg part is parsed by parseAnnotationKVs.
var annotationRegex = regexp.MustCompile(
	`(?:#|//)\s*compliancekit:waive\s+([A-Za-z0-9_.\-*?\[\]]+)\s+([A-Za-z0-9_./\-:*?\[\]]+)(.*)$`,
)

// scanFile opens path + scans line-by-line for annotation matches.
// Each match lifts to a Waiver with defaults applied for missing
// keyword args.
func scanFile(path string, now time.Time) ([]Waiver, []error) {
	// #nosec G304 — caller-supplied root; this is the documented input.
	f, err := os.Open(path)
	if err != nil {
		return nil, []error{fmt.Errorf("waivers: open %s: %w", path, err)}
	}
	defer func() { _ = f.Close() }()

	var waivers []Waiver
	var errs []error
	scanner := bufio.NewScanner(f)
	// Allow up to 1 MB per line — IaC sometimes has very long
	// inlined JSON values, and we want the scanner not to choke.
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for line := 1; scanner.Scan(); line++ {
		m := annotationRegex.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		w, err := buildAnnotationWaiver(path, line, m[1], m[2], m[3], now)
		if err != nil {
			errs = append(errs, fmt.Errorf("waivers: %s:%d: %w", path, line, err))
			continue
		}
		waivers = append(waivers, w)
	}
	if err := scanner.Err(); err != nil {
		errs = append(errs, fmt.Errorf("waivers: scan %s: %w", path, err))
	}
	return waivers, errs
}

// buildAnnotationWaiver assembles the Waiver from a regex match,
// applying defaults for any missing keyword args.
func buildAnnotationWaiver(path string, line int, checkID, resourceID, kvTail string, now time.Time) (Waiver, error) {
	kvs := parseAnnotationKVs(kvTail)

	reason := kvs["reason"]
	if reason == "" {
		reason = fmt.Sprintf("annotation in %s:%d (auto-defaulted; replace with a real justification)", path, line)
	}
	approver := kvs["approver"]
	if approver == "" {
		approver = "@annotation"
	}

	var expires time.Time
	if e := kvs["expires"]; e != "" {
		t, err := parseExpiryDate(e)
		if err != nil {
			return Waiver{}, fmt.Errorf("expires: %w", err)
		}
		expires = t
	} else {
		expires = now.AddDate(0, 0, 90)
	}

	return Waiver{
		CheckID:    checkID,
		ResourceID: resourceID,
		Reason:     reason,
		Approver:   approver,
		Expires:    expires,
		Source:     "annotation",
		SourcePath: fmt.Sprintf("%s:%d", path, line),
	}, nil
}

// kvRegex matches `key="value with spaces"` or `key=value` tokens
// inside the annotation tail. Quoted values get the quotes
// stripped; bare values stop at the next whitespace.
var kvRegex = regexp.MustCompile(`(\w+)=(?:"([^"]*)"|(\S+))`)

// parseAnnotationKVs extracts keyword args from the annotation tail.
// Returns a map; unknown keys are silently ignored (forward-
// compatibility for future annotation extensions).
func parseAnnotationKVs(tail string) map[string]string {
	out := map[string]string{}
	for _, m := range kvRegex.FindAllStringSubmatch(tail, -1) {
		key := strings.ToLower(m[1])
		val := m[2]
		if val == "" {
			val = m[3]
		}
		out[key] = val
	}
	return out
}

// shouldScanFile returns true for file extensions we know how to
// handle. Conservative by default — adding a new extension is a
// one-line change.
func shouldScanFile(path string) bool {
	base := filepath.Base(path)
	if base == "Dockerfile" || strings.HasSuffix(base, ".dockerfile") {
		return true
	}
	switch filepath.Ext(base) {
	case ".tf", ".tfvars", ".yaml", ".yml", ".sh", ".bash", ".py", ".go":
		return true
	}
	return false
}

// shouldSkipDir returns true for directories the walker never
// descends into — vendor dirs, build output, source-control
// metadata. Conservative + matches what every linter excludes
// by default.
func shouldSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".terraform", "dist", "build", ".cache":
		return true
	}
	return false
}
