package gitleaks

// match is one gitleaks finding. gitleaks emits a JSON array of these
// at the top level (no envelope object). Field shape matches
// gitleaks v8+ output schema.
type match struct {
	Description string `json:"Description,omitempty"`
	StartLine   int    `json:"StartLine,omitempty"`
	EndLine     int    `json:"EndLine,omitempty"`
	StartColumn int    `json:"StartColumn,omitempty"`
	EndColumn   int    `json:"EndColumn,omitempty"`
	Match       string `json:"Match,omitempty"`
	// Secret is the raw captured credential value — NEVER persisted
	// into compliancekit.Finding.Secret unredacted. The adapter funnels it
	// through redactSecret before storage.
	Secret  string   `json:"Secret,omitempty"`
	File    string   `json:"File,omitempty"`
	Commit  string   `json:"Commit,omitempty"`
	Entropy float64  `json:"Entropy,omitempty"`
	Author  string   `json:"Author,omitempty"`
	Email   string   `json:"Email,omitempty"`
	Date    string   `json:"Date,omitempty"`
	Message string   `json:"Message,omitempty"`
	Tags    []string `json:"Tags,omitempty"`
	RuleID  string   `json:"RuleID"`
}
