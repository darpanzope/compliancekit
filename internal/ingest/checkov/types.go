package checkov

// report is one Checkov check-type result block. A `checkov` invocation
// against a multi-framework codebase emits a JSON array of these; a
// single-framework run emits a single object.
type report struct {
	CheckType string     `json:"check_type,omitempty"`
	Summary   summaryObj `json:"summary,omitempty"`
	Results   results    `json:"results"`
}

type summaryObj struct {
	Passed         int    `json:"passed,omitempty"`
	Failed         int    `json:"failed,omitempty"`
	Skipped        int    `json:"skipped,omitempty"`
	ParsingErrors  int    `json:"parsing_errors,omitempty"`
	ResourceCount  int    `json:"resource_count,omitempty"`
	CheckovVersion string `json:"checkov_version,omitempty"`
}

type results struct {
	PassedChecks  []failedCheck `json:"passed_checks,omitempty"`
	FailedChecks  []failedCheck `json:"failed_checks,omitempty"`
	SkippedChecks []failedCheck `json:"skipped_checks,omitempty"`
	ParsingErrors []string      `json:"parsing_errors,omitempty"`
}

// failedCheck is one rule-violation record (the same struct shape
// also describes passed_checks and skipped_checks).
type failedCheck struct {
	CheckID       string      `json:"check_id"`
	BCCheckID     string      `json:"bc_check_id,omitempty"`
	CheckName     string      `json:"check_name,omitempty"`
	CheckClass    string      `json:"check_class,omitempty"`
	FilePath      string      `json:"file_path,omitempty"`
	FileLineRange []int       `json:"file_line_range,omitempty"`
	Resource      string      `json:"resource,omitempty"`
	Severity      string      `json:"severity,omitempty"`
	Guideline     string      `json:"guideline,omitempty"`
	CheckResult   checkResult `json:"check_result,omitempty"`
}

type checkResult struct {
	Result string `json:"result,omitempty"`
}
