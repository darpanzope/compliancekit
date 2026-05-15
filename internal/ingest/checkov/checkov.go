// Package checkov implements a native-JSON ingest adapter for
// Checkov (bridgecrewio/checkov) output. v0.14+. Checkov's JSON
// carries richer per-resource detail than its SARIF projection —
// the originating Terraform resource id, file + line range,
// guideline URL, and the result enumeration (passed/failed/skipped)
// per check. We project failed/skipped into Findings.
//
// Two on-wire shapes supported, auto-detected from the first
// non-whitespace byte:
//
//   - Single-check-type object: `{check_type, results: {failed_checks, ...}}`
//   - Multi-check-type array:   `[{check_type, results: {...}}, ...]`
//
// Self-registers as `--format=checkov-json`.
package checkov

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/ingest"
)

type adapter struct{}

func (adapter) Format() string { return "checkov-json" }
func (adapter) Description() string {
	return "Checkov native JSON — Terraform/CloudFormation/K8s/Dockerfile, per-resource graph projection"
}

func (adapter) Ingest(ctx context.Context, r io.Reader, opts ingest.Options) (ingest.Result, error) {
	if opts.Provenance.IngestedAt.IsZero() {
		opts.Provenance.IngestedAt = time.Now().UTC()
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return ingest.Result{}, fmt.Errorf("read checkov json: %w", err)
	}
	reports, err := decodeAuto(body)
	if err != nil {
		return ingest.Result{}, err
	}

	out := ingest.Result{}
	for _, rep := range reports {
		if err := ctx.Err(); err != nil {
			return ingest.Result{}, err
		}
		for _, c := range rep.Results.FailedChecks {
			f, phantom := buildFinding(c, rep.CheckType, core.StatusFail, opts)
			out.Findings = append(out.Findings, f)
			if phantom != nil {
				out.Resources = append(out.Resources, *phantom)
			}
		}
		for _, c := range rep.Results.SkippedChecks {
			f, phantom := buildFinding(c, rep.CheckType, core.StatusSkip, opts)
			out.Findings = append(out.Findings, f)
			if phantom != nil {
				out.Resources = append(out.Resources, *phantom)
			}
		}
	}
	return out, nil
}

// decodeAuto picks between the single-object and array shapes by
// sniffing the first non-whitespace byte.
func decodeAuto(body []byte) ([]report, error) {
	first := firstNonWhitespace(body)
	switch first {
	case '[':
		var arr []report
		if err := json.Unmarshal(body, &arr); err != nil {
			return nil, fmt.Errorf("decode checkov array: %w", err)
		}
		return arr, nil
	case '{':
		var rep report
		if err := json.Unmarshal(body, &rep); err != nil {
			return nil, fmt.Errorf("decode checkov object: %w", err)
		}
		return []report{rep}, nil
	default:
		return nil, fmt.Errorf("checkov json: unexpected first character %q", first)
	}
}

func firstNonWhitespace(body []byte) byte {
	for _, b := range body {
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			return b
		}
	}
	return 0
}

func buildFinding(c failedCheck, checkType string, status core.Status, opts ingest.Options) (core.Finding, *core.Resource) {
	severity := severityFromCheckov(c.Severity)
	subject, phantom := resolveSubject(c, checkType, opts)

	msg := c.CheckName
	if c.Resource != "" {
		msg = fmt.Sprintf("%s — %s", c.CheckName, c.Resource)
	}

	tags := []string{"misconfiguration", strings.ToLower(checkType)}

	return core.Finding{
		CheckID:   "ingest.checkov." + c.CheckID,
		Status:    status,
		Severity:  severity,
		Resource:  subject,
		Message:   msg,
		Tags:      tags,
		Timestamp: opts.Provenance.IngestedAt,
		Source: &core.Source{
			Type:        "ingest",
			Tool:        "checkov",
			ToolVersion: opts.Provenance.ToolVersion,
			Format:      "checkov-json",
			File:        opts.Provenance.File,
		},
	}, phantom
}

func resolveSubject(c failedCheck, checkType string, opts ingest.Options) (core.ResourceRef, *core.Resource) {
	id := "ingest://checkov/" + c.FilePath
	if c.Resource != "" {
		id += "#" + c.Resource
	}
	if opts.Graph != nil {
		if existing, ok := opts.Graph.ByID(id); ok {
			return core.ResourceRef{
				ID: existing.ID, Type: existing.Type, Name: existing.Name, Provider: existing.Provider,
			}, nil
		}
	}
	kind := "checkov." + strings.ToLower(checkType) + ".resource"
	name := c.Resource
	if name == "" {
		name = c.FilePath
	}
	startLine := 0
	endLine := 0
	if len(c.FileLineRange) == 2 {
		startLine = c.FileLineRange[0]
		endLine = c.FileLineRange[1]
	}
	phantom := core.Resource{
		ID:       id,
		Type:     kind,
		Name:     name,
		Provider: "ingest",
		Attributes: map[string]any{
			"ingest_source":    "checkov",
			"file_path":        c.FilePath,
			"resource":         c.Resource,
			"start_line":       startLine,
			"end_line":         endLine,
			"checkov_check_id": c.CheckID,
			"check_type":       checkType,
		},
	}
	return core.ResourceRef{
		ID: phantom.ID, Type: phantom.Type, Name: phantom.Name, Provider: phantom.Provider,
	}, &phantom
}

// severityFromCheckov maps Checkov's severity strings to compliancekit
// severities. Checkov uses CRITICAL/HIGH/MEDIUM/LOW/INFO (sometimes
// blank, in which case we fall through to MEDIUM since these are
// failed checks).
func severityFromCheckov(s string) core.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return core.SeverityCritical
	case "HIGH":
		return core.SeverityHigh
	case "MEDIUM":
		return core.SeverityMedium
	case "LOW":
		return core.SeverityLow
	case "INFO":
		return core.SeverityInfo
	}
	return core.SeverityMedium
}

func init() {
	ingest.Register(adapter{})
}
