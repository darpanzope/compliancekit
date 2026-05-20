package tui

// v1.7 phase 2 — command-mode parser. `:command` syntax:
//
//   :sev=critical          severity exact match
//   :sev>=high             severity gte (critical > high > medium > low > info)
//   :status=fail           status exact match (fail / pass / error / skip)
//   :provider=aws          provider exact match
//   :check=do-droplet-no   check id contains
//   :fw=soc2               framework id contains (looked up via registry)
//   :reset                 clear every active filter
//
// Multiple criteria can be chained: `:sev>=high status=fail` —
// space-separated, all AND'd.
//
// Phase 7 layers tab-completion + history; phase 2 ships the
// parser + the matcher.

import (
	"strings"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

type filterCriteria struct {
	sevEq       compliancekit.Severity
	sevEqSet    bool
	sevGte      compliancekit.Severity
	sevGteSet   bool
	statusEq    string
	provider    string
	checkSub    string
	frameworkID string
	search      string // /-search substring across check_id + resource
}

// apply returns true iff f matches every set criterion.
func (c filterCriteria) apply(f compliancekit.Finding) bool {
	if !c.matchesSeverity(f) || !c.matchesStatus(f) || !c.matchesProvider(f) {
		return false
	}
	if !c.matchesCheck(f) || !c.matchesFramework(f) || !c.matchesSearch(f) {
		return false
	}
	return true
}

func (c filterCriteria) matchesSeverity(f compliancekit.Finding) bool {
	if c.sevEqSet && f.Severity != c.sevEq {
		return false
	}
	if c.sevGteSet && f.Severity < c.sevGte {
		return false
	}
	return true
}

func (c filterCriteria) matchesStatus(f compliancekit.Finding) bool {
	return c.statusEq == "" || string(f.Status) == c.statusEq
}

func (c filterCriteria) matchesProvider(f compliancekit.Finding) bool {
	if c.provider == "" {
		return true
	}
	p := f.Resource.Provider
	if p == "" {
		p = providerFromType(f.Resource.Type)
	}
	return p == c.provider
}

func (c filterCriteria) matchesCheck(f compliancekit.Finding) bool {
	return c.checkSub == "" || strings.Contains(f.CheckID, c.checkSub)
}

func (c filterCriteria) matchesFramework(f compliancekit.Finding) bool {
	if c.frameworkID == "" {
		return true
	}
	// Pull from the registry; nil-safe — checks loaded out-of-band
	// (e.g. file source on a daemon-newer findings.json) gracefully
	// skip the match (treated as "framework unknown for this row").
	check, ok := compliancekit.LookupCheck(f.CheckID)
	if !ok {
		return false
	}
	_, hit := check.Frameworks[c.frameworkID]
	return hit
}

func (c filterCriteria) matchesSearch(f compliancekit.Finding) bool {
	if c.search == "" {
		return true
	}
	needle := strings.ToLower(c.search)
	hay := strings.ToLower(f.CheckID + " " + f.Resource.Name + " " + f.Resource.ID + " " + f.Message)
	return strings.Contains(hay, needle)
}

// parseCommandLine reads a colon-mode input + returns the matching
// criteria. Unknown tokens are silently dropped — operators get
// immediate visual feedback (the result list narrows or widens)
// rather than a syntax-error popup. `:reset` returns a zero
// criteria value.
func parseCommandLine(line string) filterCriteria {
	out := filterCriteria{}
	line = strings.TrimSpace(strings.TrimPrefix(line, ":"))
	if line == "" || line == "reset" {
		return out
	}
	for _, tok := range strings.Fields(line) {
		if strings.HasPrefix(tok, "sev>=") {
			out.sevGte = parseSeverityToken(tok[len("sev>="):])
			out.sevGteSet = true
			continue
		}
		if strings.HasPrefix(tok, "sev=") {
			out.sevEq = parseSeverityToken(tok[len("sev="):])
			out.sevEqSet = true
			continue
		}
		if strings.HasPrefix(tok, "status=") {
			out.statusEq = tok[len("status="):]
			continue
		}
		if strings.HasPrefix(tok, "provider=") {
			out.provider = tok[len("provider="):]
			continue
		}
		if strings.HasPrefix(tok, "check=") {
			out.checkSub = tok[len("check="):]
			continue
		}
		if strings.HasPrefix(tok, "fw=") {
			out.frameworkID = tok[len("fw="):]
			continue
		}
	}
	return out
}

func parseSeverityToken(s string) compliancekit.Severity {
	switch strings.ToLower(s) {
	case "critical", "crit":
		return compliancekit.SeverityCritical
	case "high":
		return compliancekit.SeverityHigh
	case "medium", "med":
		return compliancekit.SeverityMedium
	case "low":
		return compliancekit.SeverityLow
	default:
		return compliancekit.SeverityInfo
	}
}
