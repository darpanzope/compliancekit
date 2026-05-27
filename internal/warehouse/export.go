package warehouse

// Exporter walks AllTables, opens a per-table Writer via NewWriter,
// drains the corresponding Source channel, returns Stats per table.

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Format is the Writer format identifier passed on the CLI.
type Format string

const (
	FormatParquet Format = "parquet"
	FormatNDJSON  Format = "ndjson"
)

// AllFormats enumerates every shipping format. CLI flag validation +
// help text iterate this.
var AllFormats = []Format{FormatParquet, FormatNDJSON}

// NewWriter constructs the right Writer for the given format writing
// to dst. Caller closes dst after Writer.Close() (which flushes the
// underlying file format trailer).
func NewWriter(f Format, dst io.Writer) (Writer, error) {
	switch f {
	case FormatParquet:
		return NewParquetWriter(dst), nil
	case FormatNDJSON:
		return NewNDJSONWriter(dst), nil
	}
	return nil, fmt.Errorf("unknown warehouse format %q (known: parquet, ndjson)", f)
}

// FileExtension returns the canonical file extension for the format
// (no leading dot). Used by the Exporter when computing per-table
// file paths.
func FileExtension(f Format) string {
	switch f {
	case FormatParquet:
		return "parquet"
	case FormatNDJSON:
		return "ndjson"
	}
	return string(f)
}

// Exporter walks AllTables, opening a writer + draining the source
// per table. Concurrent across tables is intentionally NOT done —
// the per-table stream is already chunky and parallelism would
// multiply memory by N for marginal wall-clock gain. Per-table
// errors don't abort sibling tables (the per-table Stats.Err field
// carries the failure).
type Exporter struct {
	Source Source
	Format Format
	OutDir string
}

// Run writes every canonical table to OutDir/<table>.<ext>. Caller
// is responsible for creating OutDir before calling Run.
func (e *Exporter) Run(ctx context.Context) ([]Stats, error) {
	if e.Source == nil {
		return nil, fmt.Errorf("exporter: Source required")
	}
	if e.OutDir == "" {
		return nil, fmt.Errorf("exporter: OutDir required")
	}
	if err := os.MkdirAll(e.OutDir, 0o750); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", e.OutDir, err)
	}
	stats := make([]Stats, 0, len(AllTables))
	for _, t := range AllTables {
		s := e.exportOne(ctx, t)
		stats = append(stats, s)
	}
	return stats, nil
}

func (e *Exporter) exportOne(ctx context.Context, t Table) Stats {
	start := time.Now()
	path := filepath.Join(e.OutDir, fmt.Sprintf("%s.%s", t, FileExtension(e.Format)))
	f, err := os.Create(path) //nolint:gosec // OutDir is operator-supplied
	if err != nil {
		return Stats{Table: t, Err: fmt.Errorf("create %s: %w", path, err)}
	}
	defer func() { _ = f.Close() }()

	w, err := NewWriter(e.Format, f)
	if err != nil {
		return Stats{Table: t, Err: err}
	}
	schema := SchemaFor(t)
	if err := w.Open(ctx, schema); err != nil {
		return Stats{Table: t, Err: err}
	}

	rows, errs := e.Source.Rows(ctx, t)
	var count int64
	for {
		select {
		case <-ctx.Done():
			_ = w.Close()
			return Stats{Table: t, Rows: count, Duration: time.Since(start), Err: ctx.Err()}
		case row, ok := <-rows:
			if !ok {
				if err := w.Close(); err != nil {
					return Stats{Table: t, Rows: count, Duration: time.Since(start), Err: err}
				}
				// Sync the OS file so the size we report matches what
				// dbt / DuckDB / a downstream loader sees. The Parquet
				// writer flushes through us but the OS page cache may
				// still hold the trailing block; stat-on-open-handle
				// then returned 0 for Parquet outputs in the v1.17
				// phase 0 smoke test. os.Stat(path) reads fresh
				// metadata via the directory entry.
				_ = f.Sync()
				if info, statErr := os.Stat(path); statErr == nil {
					return Stats{Table: t, Rows: count, Bytes: info.Size(), Duration: time.Since(start)}
				}
				return Stats{Table: t, Rows: count, Duration: time.Since(start)}
			}
			if err := w.Write(ctx, row); err != nil {
				_ = w.Close()
				return Stats{Table: t, Rows: count, Duration: time.Since(start), Err: err}
			}
			count++
		case err := <-errs:
			if err != nil {
				_ = w.Close()
				return Stats{Table: t, Rows: count, Duration: time.Since(start), Err: err}
			}
		}
	}
}
