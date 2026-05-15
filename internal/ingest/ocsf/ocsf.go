package ocsf

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/ingest"
)

type adapter struct{}

// Format implements ingest.Ingester.
func (adapter) Format() string { return "ocsf" }

// Description implements ingest.Ingester.
func (adapter) Description() string {
	return "OCSF 1.x — AWS Security Hub, GCP Security Command Center, Microsoft Defender for Cloud"
}

// Ingest reads OCSF events from r and produces compliancekit findings.
// Supports three on-the-wire shapes:
//
//   - single object: `{"class_uid": 2003, …}`
//   - JSON array:    `[{...}, {...}]`
//   - JSONL stream:  one object per line (AWS Security Hub S3 export)
//
// The adapter sniffs the first non-whitespace byte to decide which
// shape to decode.
func (adapter) Ingest(ctx context.Context, r io.Reader, opts ingest.Options) (ingest.Result, error) {
	events, err := readEvents(r)
	if err != nil {
		return ingest.Result{}, err
	}
	if len(events) == 0 {
		return ingest.Result{}, errors.New("ocsf payload has zero events")
	}

	if opts.Provenance.IngestedAt.IsZero() {
		opts.Provenance.IngestedAt = time.Now().UTC()
	}

	out := ingest.Result{}
	for idx, ev := range events {
		if err := ctx.Err(); err != nil {
			return ingest.Result{}, err
		}
		productID := canonicalProduct(opts.Provenance.Tool, ev.Metadata.Product)
		toolVersion := firstNonEmpty(opts.Provenance.ToolVersion, ev.Metadata.Product.Version)

		mapping := opts.Mapping
		if mapping == nil {
			mapping = lookupBuiltinMapping(productID)
		}

		finding, resource, warns := projectEvent(ev, productID, toolVersion, mapping, opts)
		out.Findings = append(out.Findings, finding)
		if resource != nil {
			out.Resources = append(out.Resources, *resource)
		}
		out.Warnings = append(out.Warnings, warns...)

		if opts.FailOnUnmapped && mapping != nil {
			if ruleID := ruleIDFor(ev); ruleID != "" {
				if _, ok := mapping.Lookup(ruleID); !ok {
					return ingest.Result{}, fmt.Errorf(
						"event[%d]: rule %q has no mapping in table %q",
						idx, ruleID, mapping.Tool)
				}
			}
		}
	}
	return out, nil
}

// readEvents auto-detects the input shape (single object, array, or
// JSONL). Decoding is streaming where possible so we don't materialize
// huge Security Hub exports in memory.
func readEvents(r io.Reader) ([]event, error) {
	br := bufio.NewReader(r)
	first, err := peekFirstNonWhitespace(br)
	if err != nil {
		return nil, fmt.Errorf("read ocsf: %w", err)
	}
	switch first {
	case '[':
		var arr []event
		if err := json.NewDecoder(br).Decode(&arr); err != nil {
			return nil, fmt.Errorf("decode ocsf array: %w", err)
		}
		return arr, nil
	case '{':
		// Could be a single object OR a JSONL stream. The
		// distinguishing test is whether the JSON decoder
		// consumed everything or left another object trailing.
		body, err := io.ReadAll(br)
		if err != nil {
			return nil, fmt.Errorf("read ocsf body: %w", err)
		}
		return decodeObjectOrJSONL(body)
	default:
		return nil, fmt.Errorf("unexpected first character %q (want '{' or '[')", first)
	}
}

// peekFirstNonWhitespace returns the first non-whitespace byte from r
// without consuming it from the buffered reader's stream.
func peekFirstNonWhitespace(br *bufio.Reader) (byte, error) {
	for {
		b, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		if !isWS(b) {
			return b, br.UnreadByte()
		}
	}
}

func isWS(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// decodeObjectOrJSONL tries to parse body as a single JSON object
// first; if that consumes the full body, returns the singleton. If
// the decoder leaves trailing content, falls back to JSONL line-by-
// line decoding.
func decodeObjectOrJSONL(body []byte) ([]event, error) {
	// Try single-object shape.
	dec := json.NewDecoder(bytes.NewReader(body))
	var single event
	if err := dec.Decode(&single); err == nil && allWhitespace(body[dec.InputOffset():]) {
		return []event{single}, nil
	}
	// Fall back to JSONL: one object per line.
	var events []event
	scanner := bufio.NewScanner(bytes.NewReader(body))
	// Security Hub exports occasionally produce 100KB+ lines. Lift
	// the default 64KB scanner cap.
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev event
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("jsonl decode: %w", err)
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("jsonl scan: %w", err)
	}
	return events, nil
}

func allWhitespace(b []byte) bool {
	for _, c := range b {
		if !isWS(c) {
			return false
		}
	}
	return true
}

// canonicalProduct picks the canonical product identifier for mapping
// table lookup. Explicit Provenance.Tool wins; otherwise the
// metadata.product.name is normalized to one of:
//
//	aws-security-hub
//	gcp-scc
//	defender-for-cloud
//	prowler
//
// Unknown names pass through lowercased.
func canonicalProduct(explicit string, p product) string {
	if explicit != "" {
		return strings.ToLower(strings.TrimSpace(explicit))
	}
	name := strings.ToLower(strings.TrimSpace(p.Name))
	vendor := strings.ToLower(strings.TrimSpace(p.Vendor))
	switch {
	case strings.Contains(name, "security hub"), strings.Contains(name, "securityhub"):
		return "aws-security-hub"
	case strings.Contains(name, "security command center"), strings.Contains(name, "scc"):
		return "gcp-scc"
	case strings.Contains(name, "defender"):
		return "defender-for-cloud"
	case strings.Contains(name, "prowler"):
		return "prowler"
	case strings.Contains(name, "wiz"):
		return "wiz"
	}
	if name != "" {
		return name
	}
	return vendor
}

// projectEvent converts one OCSF event into a compliancekit Finding.
// Resource projection: if the event names an AWS ARN, GCP project
// path, or Azure resource ID that's already in opts.Graph, the
// existing resource is reused; otherwise a phantom is emitted for
// the caller to add. Severity is taken from the mapping override or
// the event's severity_id; status from status_id.
func projectEvent(
	ev event,
	productID, toolVersion string,
	mapping *ingest.MappingTable,
	opts ingest.Options,
) (core.Finding, *core.Resource, []string) {
	var warnings []string
	ruleID := ruleIDFor(ev)

	subject, phantom := resolveSubject(ev, productID, opts)
	severity := resolveSeverity(ev, mapping, ruleID, opts.DefaultSeverity)
	status := resolveStatus(ev)

	tags := []string{}
	if mapping != nil {
		if m, ok := mapping.Lookup(ruleID); ok {
			tags = append(tags, m.Tags...)
		} else if ruleID != "" && !opts.FailOnUnmapped {
			warnings = append(warnings,
				fmt.Sprintf("no mapping for %s rule %q (finding emitted without framework attribution)",
					productID, ruleID))
		}
	}

	checkID := composeCheckID(productID, ruleID)
	finding := core.Finding{
		CheckID:   checkID,
		Status:    status,
		Severity:  severity,
		Resource:  subject,
		Message:   composeMessage(ev),
		Tags:      tags,
		Timestamp: timestampFromEvent(ev, opts.Provenance.IngestedAt),
		Source: &core.Source{
			Type:        "ingest",
			Tool:        productID,
			ToolVersion: toolVersion,
			Format:      "ocsf",
			File:        opts.Provenance.File,
		},
	}
	return finding, phantom, warnings
}

// ruleIDFor extracts the most-meaningful rule identifier from an event.
// Order of preference: finding_info.types[0] (AWS Security Hub puts
// "Software and Configuration Checks/Industry and Regulatory Standards/
// .../S3.4" here), then finding_info.analytic.uid, then
// finding_info.uid, then metadata.product.feature.uid.
func ruleIDFor(ev event) string {
	if ev.Finding != nil {
		if len(ev.Finding.Types) > 0 && ev.Finding.Types[0] != "" {
			parts := strings.Split(ev.Finding.Types[0], "/")
			return strings.TrimSpace(parts[len(parts)-1])
		}
		if ev.Finding.Analytic != nil && ev.Finding.Analytic.UID != "" {
			return ev.Finding.Analytic.UID
		}
		if ev.Finding.UID != "" {
			return ev.Finding.UID
		}
	}
	if ev.Metadata.Product.FeatureRef != nil && ev.Metadata.Product.FeatureRef.UID != "" {
		return ev.Metadata.Product.FeatureRef.UID
	}
	return ""
}

func resolveSubject(ev event, productID string, opts ingest.Options) (core.ResourceRef, *core.Resource) {
	if len(ev.Resources) == 0 {
		// Synthetic catch-all for events that name no resource.
		id := fmt.Sprintf("ingest://%s/unknown", productID)
		phantom := core.Resource{
			ID:       id,
			Type:     "ingest." + productID + ".unknown",
			Name:     "<no-resource>",
			Provider: "ingest",
		}
		return core.ResourceRef{
			ID: id, Type: phantom.Type, Name: phantom.Name, Provider: phantom.Provider,
		}, &phantom
	}
	first := ev.Resources[0]
	id := first.UID
	if id == "" {
		id = fmt.Sprintf("ingest://%s/%s", productID, first.Name)
	}
	if opts.Graph != nil {
		if existing, ok := opts.Graph.ByID(id); ok {
			return core.ResourceRef{
				ID: existing.ID, Type: existing.Type, Name: existing.Name,
				Provider: existing.Provider, Region: existing.Region,
				AccountID: accountIDFromEvent(ev),
			}, nil
		}
	}
	region := first.Region
	if region == "" && ev.Cloud != nil {
		region = ev.Cloud.Region
	}
	phantom := core.Resource{
		ID:       id,
		Type:     normalizeResourceType(first.Type, productID),
		Name:     firstNonEmpty(first.Name, lastSegment(id)),
		Provider: "ingest",
		Region:   region,
		Attributes: map[string]any{
			"ingest_source": productID,
			"ocsf_uid":      first.UID,
			"ocsf_type_raw": first.Type,
		},
	}
	return core.ResourceRef{
		ID:        phantom.ID,
		Type:      phantom.Type,
		Name:      phantom.Name,
		Provider:  phantom.Provider,
		Region:    region,
		AccountID: accountIDFromEvent(ev),
	}, &phantom
}

func resolveSeverity(ev event, mapping *ingest.MappingTable, ruleID string, def core.Severity) core.Severity {
	if mapping != nil && ruleID != "" {
		if m, ok := mapping.Lookup(ruleID); ok && m.Severity != "" {
			if s, err := core.ParseSeverity(m.Severity); err == nil {
				return s
			}
		}
	}
	// OCSF severity_id: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical, 6=Fatal
	switch ev.SeverityID {
	case 5, 6:
		return core.SeverityCritical
	case 4:
		return core.SeverityHigh
	case 3:
		return core.SeverityMedium
	case 2:
		return core.SeverityLow
	case 1:
		return core.SeverityInfo
	}
	if ev.Severity != "" {
		if s, err := core.ParseSeverity(ev.Severity); err == nil {
			return s
		}
	}
	if def == core.SeverityInfo {
		return core.SeverityMedium
	}
	return def
}

// resolveStatus maps OCSF status_id to compliancekit Status. OCSF
// status_id 1=New, 2=In Progress, 3=Suppressed, 4=Resolved, 99=Other,
// 0=Unknown. Anything but Resolved/Suppressed counts as actionable
// (StatusFail). A compliance.status_id can refine this further.
func resolveStatus(ev event) core.Status {
	if ev.Compliance != nil {
		// OCSF compliance.status_id: 1=Compliant, 2=Non-Compliant,
		// 3=Not Applicable, 4=Manual, 99=Other.
		switch ev.Compliance.StatusID {
		case 1:
			return core.StatusPass
		case 2:
			return core.StatusFail
		case 3, 4:
			return core.StatusSkip
		}
	}
	switch ev.StatusID {
	case 4: // Resolved
		return core.StatusPass
	case 3: // Suppressed
		return core.StatusSkip
	default:
		return core.StatusFail
	}
}

func normalizeResourceType(raw, productID string) string {
	if raw != "" {
		return raw
	}
	return "ingest." + productID + ".resource"
}

func accountIDFromEvent(ev event) string {
	if ev.Cloud != nil && ev.Cloud.Account != nil {
		return ev.Cloud.Account.UID
	}
	if len(ev.Resources) > 0 && ev.Resources[0].Cloud != nil && ev.Resources[0].Cloud.Account != nil {
		return ev.Resources[0].Cloud.Account.UID
	}
	return ""
}

func composeCheckID(productID, ruleID string) string {
	if ruleID == "" {
		ruleID = "unspecified"
	}
	normalized := strings.ReplaceAll(ruleID, "/", ".")
	normalized = strings.ReplaceAll(normalized, " ", "_")
	return fmt.Sprintf("ingest.%s.%s", productID, normalized)
}

func composeMessage(ev event) string {
	if ev.Finding != nil && ev.Finding.Description != "" {
		return ev.Finding.Description
	}
	if ev.Finding != nil && ev.Finding.Title != "" {
		return ev.Finding.Title
	}
	if ev.Message != "" {
		return ev.Message
	}
	return "OCSF event (no message)"
}

func timestampFromEvent(ev event, fallback time.Time) time.Time {
	if ev.Time == 0 {
		return fallback
	}
	return time.UnixMilli(ev.Time).UTC()
}

func lastSegment(uri string) string {
	if i := strings.LastIndex(uri, "/"); i >= 0 && i < len(uri)-1 {
		return uri[i+1:]
	}
	if i := strings.LastIndex(uri, ":"); i >= 0 && i < len(uri)-1 {
		return uri[i+1:]
	}
	return uri
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

func init() {
	ingest.Register(adapter{})
}
