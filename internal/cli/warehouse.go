package cli

// v1.17 — `compliancekit warehouse` subcommand. Three operations:
//
//	warehouse export   write per-table Parquet/NDJSON to a directory
//	warehouse load     stream into a warehouse target (phase 2-4)
//	warehouse sync     daemon-style scheduled sync (phase 7)
//
// Phase 0 ships `export` only; load + sync land at phases 2-4 + 7.

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/darpanzope/compliancekit/internal/server/store"
	"github.com/darpanzope/compliancekit/internal/warehouse"
)

func newWarehouseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "warehouse",
		Short: "Export findings + resources + history to a warehouse (v1.17)",
		Long: `warehouse bridges the daemon's persisted state to your data
warehouse. v1.17 phase 0 ships the export sub-command; the load
sub-commands (BigQuery, Snowflake, Redshift) layer on the same
internal/warehouse package over the next phases.

Tables emitted per export call:
  findings.<ext>    every finding row, joined with framework_ids
  resources.<ext>   every resource the engine has seen
  scans.<ext>       every completed scan (status + score + counts)
  audit_log.<ext>   tamper-evident audit chain (v1.12 phase 10)

Schemas are versioned + documented at docs/warehouse-schema.md.`,
	}
	cmd.AddCommand(newWarehouseExportCmd())
	return cmd
}

func newWarehouseExportCmd() *cobra.Command {
	var (
		formatStr string
		out       string
		dbPath    string
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write findings + resources + scans + audit_log to <out>/ in the chosen format",
		Example: `  compliancekit warehouse export --format=parquet --out=./out
  compliancekit warehouse export --format=ndjson --out=./out --db=./.compliancekit/serve.db`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWarehouseExport(cmd.Context(), cmd.OutOrStdout(),
				warehouse.Format(formatStr), out, dbPath)
		},
	}
	cmd.Flags().StringVar(&formatStr, "format", "parquet", "writer format: parquet, ndjson")
	cmd.Flags().StringVar(&out, "out", "./out", "output directory (created if missing)")
	cmd.Flags().StringVar(&dbPath, "db", "./.compliancekit/serve.db", "SQLite file path or postgres://… DSN")
	return cmd
}

func runWarehouseExport(ctx context.Context, stdout io.Writer, format warehouse.Format, out, dbPath string) error {
	if !knownFormat(format) {
		return fmt.Errorf("--format must be one of: parquet, ndjson")
	}
	st, err := openStore(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store %s: %w", dbPath, err)
	}
	defer func() { _ = st.Close() }()

	if err := warmStore(ctx, st); err != nil {
		return err
	}

	src := warehouse.NewDBSource(st.DB())
	exp := &warehouse.Exporter{Source: src, Format: format, OutDir: out}
	stats, err := exp.Run(ctx)
	if err != nil {
		return fmt.Errorf("warehouse export: %w", err)
	}

	fmt.Fprintf(stdout, "warehouse export → %s (format=%s)\n", out, format)
	var total int64
	var anyErr error
	for _, s := range stats {
		path := filepath.Join(out, fmt.Sprintf("%s.%s", s.Table, warehouse.FileExtension(format)))
		if s.Err != nil {
			anyErr = s.Err
			fmt.Fprintf(stdout, "  %-12s  FAILED  %v\n", s.Table, s.Err)
			continue
		}
		fmt.Fprintf(stdout, "  %-12s  %7d rows  %s  %s\n",
			s.Table, s.Rows, humanBytes(s.Bytes), s.Duration.Truncate(time.Millisecond))
		_ = path
		total += s.Rows
	}
	if anyErr != nil {
		return fmt.Errorf("one or more tables failed to export (see log above)")
	}
	fmt.Fprintf(stdout, "  total: %d rows across %d tables\n", total, len(warehouse.AllTables))
	return nil
}

func knownFormat(f warehouse.Format) bool {
	for _, candidate := range warehouse.AllFormats {
		if candidate == f {
			return true
		}
	}
	return false
}

// warmStore confirms the schema is migrated before export. Important
// for fresh DBs that the warehouse command opens directly (instead
// of going through the daemon's MigrateUp at boot).
func warmStore(ctx context.Context, st *store.Store) error {
	if err := st.MigrateUp(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

func humanBytes(n int64) string {
	const (
		KiB = 1 << 10
		MiB = 1 << 20
		GiB = 1 << 30
	)
	switch {
	case n >= GiB:
		return fmt.Sprintf("%.1f GiB", float64(n)/float64(GiB))
	case n >= MiB:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(MiB))
	case n >= KiB:
		return fmt.Sprintf("%.1f KiB", float64(n)/float64(KiB))
	}
	return fmt.Sprintf("%d B", n)
}
