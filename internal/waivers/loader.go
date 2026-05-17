package waivers

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// LoadFile reads waivers.yaml from path and returns the parsed
// WaiverList. Missing file is NOT an error — operators may run
// without waivers, so a non-existent path returns an empty list +
// nil. Other read errors (permission denied, IO failure) surface.
//
// The `now` argument is injected (not derived from time.Now) so the
// caller — typically the scan engine or the CLI's `waivers` command
// — can pin a deterministic clock for tests + reproducible expiry
// classification.
//
// Validation runs against every entry; per-entry errors are returned
// in the second slice. The loader fails the run on a non-empty
// error slice; the `waivers validate` CLI subcommand surfaces and
// continues.
func LoadFile(path string, now time.Time) (*WaiverList, []error) {
	if path == "" {
		return &WaiverList{}, []error{errors.New("waivers: LoadFile: empty path")}
	}
	// #nosec G304 — operator-supplied waivers file is the documented input.
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &WaiverList{}, nil
		}
		return &WaiverList{}, []error{fmt.Errorf("waivers: read %s: %w", path, err)}
	}
	return Load(body, path, now)
}

// Load parses + validates waivers YAML in memory. Splitting this
// out makes the tests dependency-free of the filesystem and lets
// the CLI's `waivers validate` subcommand consume stdin or pipe
// input without writing to disk first.
//
// `path` is stamped into every Waiver's SourcePath field so a
// later reporter or POA&M emit can surface "this waiver came from
// waivers.yaml line N" provenance. Empty path = "<inline>" stamp.
func Load(body []byte, path string, now time.Time) (*WaiverList, []error) {
	if len(body) == 0 {
		return &WaiverList{}, nil
	}
	if path == "" {
		path = "<inline>"
	}
	var doc waiversDoc
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return &WaiverList{}, []error{fmt.Errorf("waivers: parse %s: %w", path, err)}
	}

	entries := make([]Waiver, 0, len(doc.Waivers))
	for _, e := range doc.Waivers {
		w, err := e.toWaiver(path)
		if err != nil {
			// Parse-level errors (bad date format, unknown YAML
			// keys) are surfaced as load-time errors but bundled
			// so a single bad entry does not block the others.
			// The loader returns the partial list + the error
			// slice; the caller decides fail vs warn.
			return nil, []error{fmt.Errorf("waivers: %s entry %q: %w", path, e.CheckID, err)}
		}
		entries = append(entries, w)
	}

	return NewWaiverList(entries, now)
}

// waiversDoc is the top-level YAML shape. Single key (`waivers`) so
// the file is self-describing — an empty waivers.yaml is just
// `waivers: []` rather than a bare list. Matches the `ingest:` block
// convention in compliancekit.yaml.
type waiversDoc struct {
	Waivers []rawWaiver `yaml:"waivers"`
}

// rawWaiver is the on-disk YAML shape before date parsing + field
// validation. Separate from the typed Waiver struct so the loader
// can attach better error messages ("expires must be YYYY-MM-DD,
// got %q") than `time.Time`'s default unmarshal would.
type rawWaiver struct {
	CheckID    string `yaml:"check_id"`
	ResourceID string `yaml:"resource_id"`
	Reason     string `yaml:"reason"`
	Approver   string `yaml:"approver"`
	Expires    string `yaml:"expires"` // YYYY-MM-DD
}

// toWaiver converts the raw shape to the typed one. Performs date
// parsing here so the surrounding loader catches malformed expiry
// fields with a precise error message.
func (r rawWaiver) toWaiver(sourcePath string) (Waiver, error) {
	expires, err := parseExpiryDate(strings.TrimSpace(r.Expires))
	if err != nil {
		return Waiver{}, fmt.Errorf("expires: %w", err)
	}
	return Waiver{
		CheckID:    strings.TrimSpace(r.CheckID),
		ResourceID: strings.TrimSpace(r.ResourceID),
		Reason:     strings.TrimSpace(r.Reason),
		Approver:   strings.TrimSpace(r.Approver),
		Expires:    expires,
		Source:     "file",
		SourcePath: sourcePath,
	}, nil
}

// parseExpiryDate accepts YYYY-MM-DD (preferred) plus RFC3339
// (lenient — operators copy-pasting from incident-management
// tools sometimes get full timestamps). UTC interpretation in
// both cases; midnight start-of-day for the YYYY-MM-DD form.
func parseExpiryDate(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("missing or empty")
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("must be YYYY-MM-DD or RFC3339; got %q", s)
}
