package warehouse

// NDJSONWriter is the lightweight escape-hatch Writer — one JSON
// object per line, lossless. Designed to round-trip through DuckDB's
// `SELECT * FROM read_ndjson_auto('findings.ndjson')` without
// needing the Parquet writer in the operator's pipeline. Schema
// metadata is emitted as a leading metadata line keyed by
// `"_meta": {"schema_version": N, "table": "..."}`.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

type NDJSONWriter struct {
	w       *bufio.Writer
	logical Schema
	open    bool
}

// NewNDJSONWriter returns a Writer that emits one JSON object per
// line into dst. Caller closes dst after Close().
func NewNDJSONWriter(dst io.Writer) *NDJSONWriter {
	return &NDJSONWriter{w: bufio.NewWriterSize(dst, 64*1024)}
}

func (n *NDJSONWriter) Open(_ context.Context, s Schema) error {
	if n.open {
		return fmt.Errorf("ndjson writer: already open")
	}
	n.logical = s
	n.open = true
	meta := map[string]any{
		"_meta": map[string]any{
			"schema_version": SchemaVersion,
			"table":          string(s.Table),
			"columns":        s.Columns,
		},
	}
	if err := n.writeJSON(meta); err != nil {
		return fmt.Errorf("ndjson meta: %w", err)
	}
	return nil
}

func (n *NDJSONWriter) Write(_ context.Context, row Row) error {
	if !n.open {
		return fmt.Errorf("ndjson writer: not open")
	}
	// Project columns in declared order so the file is operator-
	// readable + DuckDB infers schema deterministically.
	out := make(map[string]any, len(n.logical.Columns))
	for _, c := range n.logical.Columns {
		if v, ok := row[c.Name]; ok {
			out[c.Name] = v
		} else if !c.Nullable {
			out[c.Name] = nil
		}
	}
	return n.writeJSON(out)
}

func (n *NDJSONWriter) Close() error {
	if !n.open {
		return nil
	}
	n.open = false
	return n.w.Flush()
}

func (n *NDJSONWriter) writeJSON(v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := n.w.Write(body); err != nil {
		return err
	}
	_, err = n.w.WriteString("\n")
	return err
}
