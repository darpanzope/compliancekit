package warehouse

// OpenLineage emit — v1.17 phase 5. Every scan emits a START + a
// COMPLETE (or FAIL) event to an operator-configured OpenLineage
// receiver. Marquez + DataHub validate the events cleanly per the
// 1.0 spec. We hand-roll the JSON instead of pulling the OpenLineage
// Go client because the surface we use is tiny (4 fields per event)
// and the client library brings significant transitive deps.
//
// Schema reference: https://openlineage.io/apidocs/openapi/#tag/Run

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OpenLineageEvent mirrors the wire shape per the 1.0 spec.
// EventType is one of START / RUNNING / COMPLETE / ABORT / FAIL.
// Inputs + Outputs are arrays of {namespace, name} datasets.
type OpenLineageEvent struct {
	EventType string               `json:"eventType"`
	EventTime string               `json:"eventTime"`
	Producer  string               `json:"producer"`
	SchemaURL string               `json:"schemaURL"`
	Run       OpenLineageRun       `json:"run"`
	Job       OpenLineageJob       `json:"job"`
	Inputs    []OpenLineageDataset `json:"inputs,omitempty"`
	Outputs   []OpenLineageDataset `json:"outputs,omitempty"`
}

type OpenLineageRun struct {
	RunID string `json:"runId"`
}

type OpenLineageJob struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type OpenLineageDataset struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

const (
	openLineageProducer  = "https://github.com/darpanzope/compliancekit"
	openLineageSchemaURL = "https://openlineage.io/spec/1-0-5/OpenLineage.json"
	openLineageNamespace = "compliancekit"
)

// OpenLineageEmitter posts events to an operator-configured receiver
// URL (Marquez: http://marquez:5000/api/v1/lineage; DataHub:
// http://datahub-gms:8080/openapi/v1/lineage; Astronomer: per their
// docs). Construct with NewOpenLineageEmitter; the zero value is a
// no-op emitter.
type OpenLineageEmitter struct {
	URL        string
	httpClient *http.Client
}

// NewOpenLineageEmitter returns an emitter that POSTs to url. Pass
// empty url to disable emission (every method becomes a no-op).
func NewOpenLineageEmitter(url string) *OpenLineageEmitter {
	return &OpenLineageEmitter{
		URL:        url,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// EmitScanStart fires a START event when a scan begins. inputs are
// the providers the scan is configured to read (compliancekit:
// provider/aws, compliancekit: provider/gcp, etc.).
func (e *OpenLineageEmitter) EmitScanStart(ctx context.Context, runID string, providers []string) error {
	if e == nil || e.URL == "" {
		return nil
	}
	return e.emit(ctx, OpenLineageEvent{
		EventType: "START",
		EventTime: time.Now().UTC().Format(time.RFC3339Nano),
		Producer:  openLineageProducer,
		SchemaURL: openLineageSchemaURL,
		Run:       OpenLineageRun{RunID: runID},
		Job:       OpenLineageJob{Namespace: openLineageNamespace, Name: "scan"},
		Inputs:    providersToDatasets(providers),
	})
}

// EmitScanComplete fires a COMPLETE event with the canonical output
// datasets (the 4 warehouse tables the scan produced rows into).
// outputs is typically AllTables so the lineage graph captures every
// downstream artifact.
func (e *OpenLineageEmitter) EmitScanComplete(ctx context.Context, runID string, providers []string, outputs []Table) error {
	if e == nil || e.URL == "" {
		return nil
	}
	out := make([]OpenLineageDataset, len(outputs))
	for i, t := range outputs {
		out[i] = OpenLineageDataset{Namespace: openLineageNamespace, Name: string(t)}
	}
	return e.emit(ctx, OpenLineageEvent{
		EventType: "COMPLETE",
		EventTime: time.Now().UTC().Format(time.RFC3339Nano),
		Producer:  openLineageProducer,
		SchemaURL: openLineageSchemaURL,
		Run:       OpenLineageRun{RunID: runID},
		Job:       OpenLineageJob{Namespace: openLineageNamespace, Name: "scan"},
		Inputs:    providersToDatasets(providers),
		Outputs:   out,
	})
}

// EmitScanFail fires a FAIL event with the error message in the run
// facets (future v1.17.x will populate facets; v1.17.0 ships the
// minimal envelope so Marquez/DataHub link the failure to the run).
func (e *OpenLineageEmitter) EmitScanFail(ctx context.Context, runID string, providers []string, _ error) error {
	if e == nil || e.URL == "" {
		return nil
	}
	return e.emit(ctx, OpenLineageEvent{
		EventType: "FAIL",
		EventTime: time.Now().UTC().Format(time.RFC3339Nano),
		Producer:  openLineageProducer,
		SchemaURL: openLineageSchemaURL,
		Run:       OpenLineageRun{RunID: runID},
		Job:       OpenLineageJob{Namespace: openLineageNamespace, Name: "scan"},
		Inputs:    providersToDatasets(providers),
	})
}

func (e *OpenLineageEmitter) emit(ctx context.Context, ev OpenLineageEvent) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("openlineage marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("openlineage new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("openlineage POST %s: %w", e.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Marquez returns 201 on accept; DataHub returns 200. Anything
	// 4xx/5xx is a wire-level failure operators want surfaced.
	if resp.StatusCode >= 300 {
		return fmt.Errorf("openlineage POST %s: HTTP %d", e.URL, resp.StatusCode)
	}
	return nil
}

func providersToDatasets(providers []string) []OpenLineageDataset {
	out := make([]OpenLineageDataset, 0, len(providers))
	for _, p := range providers {
		out = append(out, OpenLineageDataset{
			Namespace: openLineageNamespace,
			Name:      "provider/" + p,
		})
	}
	return out
}
