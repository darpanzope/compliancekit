package cli

import "fmt"

// ExitCodeError wraps an error that should produce a specific process
// exit code in main(). Used for outcomes that are not "the tool failed"
// but still warrant non-zero exit -- e.g. a scan that ran successfully
// but produced findings at or above the configured fail-on severity.
//
// main.go checks errors.As(err, *ExitCodeError) and uses Code; cobra
// just sees a normal error and propagates it up.
type ExitCodeError struct {
	Code    int
	Message string
}

// Error implements error.
func (e *ExitCodeError) Error() string { return e.Message }

// ExitCode returns the intended process exit code.
func (e *ExitCodeError) ExitCode() int { return e.Code }

// NewExitCode returns an ExitCodeError with the given exit code and a
// formatted message.
func NewExitCode(code int, format string, args ...any) *ExitCodeError {
	return &ExitCodeError{Code: code, Message: fmt.Sprintf(format, args...)}
}
