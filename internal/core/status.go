package core

// Status is the outcome of evaluating a check against a resource.
//
// A single check can produce findings of mixed status — for a graph of
// 10 buckets a Spaces check might emit 7 StatusPass, 2 StatusFail, and
// 1 StatusSkip. Only StatusFail and StatusError count against severity
// gates; StatusPass and StatusSkip are recorded for evidence-pack
// completeness but never cause a non-zero exit code.
type Status string

const (
	// StatusPass means the resource is compliant with the check.
	StatusPass Status = "pass"

	// StatusFail means the resource is non-compliant with the check.
	StatusFail Status = "fail"

	// StatusSkip means the check did not apply (resource type mismatch,
	// feature not enabled, etc.). Skipped checks still appear in the
	// evidence pack so an auditor sees the full coverage matrix.
	StatusSkip Status = "skip"

	// StatusError means the check could not be evaluated due to missing
	// or ambiguous data. An error is not the same as a failing resource;
	// it signals "we don't know" rather than "we know it's bad."
	StatusError Status = "error"
)

// IsActionable returns true for statuses that warrant operator attention.
// The CLI uses this to decide whether a finding contributes to the
// --fail-on threshold.
func (s Status) IsActionable() bool {
	return s == StatusFail || s == StatusError
}

// ParseStatus parses the textual status name (case-insensitive)
// produced by external callers — Rego policies, ingest adapters,
// the CLI's --status flag. Returns the typed Status or an error
// listing the four valid values.
//
// Unlike Severity which uses an int enum, Status is already a typed
// string so this helper is mostly an "unknown value" guard.
func ParseStatus(s string) (Status, error) {
	switch s {
	case "pass", "PASS", "Pass":
		return StatusPass, nil
	case "fail", "FAIL", "Fail":
		return StatusFail, nil
	case "skip", "SKIP", "Skip":
		return StatusSkip, nil
	case "error", "ERROR", "Error":
		return StatusError, nil
	}
	return "", &unknownStatusError{got: s}
}

type unknownStatusError struct{ got string }

func (e *unknownStatusError) Error() string {
	return "unknown status " + e.got + " (want pass | fail | skip | error)"
}
