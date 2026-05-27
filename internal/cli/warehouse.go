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
	cmd.AddCommand(newWarehouseLoadCmd())
	return cmd
}

// newWarehouseLoadCmd builds `compliancekit warehouse load --to=<target>`.
// Per-target adapters live in internal/warehouse/{bigquery,snowflake,
// redshift}.go and share the Loader interface. Phase 2 ships BigQuery;
// phases 3 + 4 layer on Snowflake + Redshift.
func newWarehouseLoadCmd() *cobra.Command {
	var (
		to       string
		dbPath   string
		project  string
		dataset  string
		location string
		// snowflake
		account   string
		warehouse string
		schema    string
		user      string
		password  string
		// redshift
		clusterID string
		dbName    string
		secretARN string
		stageS3   string
	)
	cmd := &cobra.Command{
		Use:   "load",
		Short: "Stream the daemon state into a warehouse target",
		Long: `load reads the same canonical 4-table shape that export
writes and streams it into a warehouse via a per-target Loader.

Targets:
  bigquery    --project= --dataset= [--location=]
  snowflake   --account= --warehouse= --database= --schema= --user= --password=
  redshift    --cluster= --database= --secret-arn= --stage-s3-uri=

Each target reads its own auth from env per the cloud SDK convention:
  bigquery   GOOGLE_APPLICATION_CREDENTIALS (or workload identity)
  snowflake  SNOWFLAKE_PRIVATE_KEY (or --password)
  redshift   AWS_PROFILE / AWS_ROLE_ARN / IMDS`,
		Example: `  compliancekit warehouse load --to=bigquery --project=acme --dataset=compliance
  compliancekit warehouse load --to=snowflake --account=acme.us-east-1 \
    --warehouse=COMPUTE_WH --database=COMPLIANCE --schema=PUBLIC --user=ck_loader
  compliancekit warehouse load --to=redshift --cluster=my-cluster \
    --database=compliance --secret-arn=arn:aws:secretsmanager:... \
    --stage-s3-uri=s3://acme-warehouse-stage/compliancekit/`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWarehouseLoad(cmd.Context(), cmd.OutOrStdout(),
				to, dbPath,
				BigQueryArgs{Project: project, Dataset: dataset, Location: location},
				SnowflakeArgs{Account: account, Warehouse: warehouse, Database: dbName,
					Schema: schema, User: user, Password: password},
				RedshiftArgs{Cluster: clusterID, Database: dbName, SecretARN: secretARN,
					StageS3URI: stageS3})
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "warehouse target: bigquery, snowflake, redshift")
	cmd.Flags().StringVar(&dbPath, "db", "./.compliancekit/serve.db", "SQLite file path or postgres://… DSN")
	// bigquery
	cmd.Flags().StringVar(&project, "project", "", "BigQuery project id")
	cmd.Flags().StringVar(&dataset, "dataset", "compliancekit", "BigQuery dataset (created if missing)")
	cmd.Flags().StringVar(&location, "location", "US", "BigQuery dataset location (US, EU, asia-east1, …)")
	// snowflake
	cmd.Flags().StringVar(&account, "account", "", "Snowflake account locator (e.g. acme.us-east-1)")
	cmd.Flags().StringVar(&warehouse, "warehouse", "", "Snowflake compute warehouse name")
	cmd.Flags().StringVar(&dbName, "database", "", "Snowflake / Redshift database name")
	cmd.Flags().StringVar(&schema, "schema", "PUBLIC", "Snowflake schema name")
	cmd.Flags().StringVar(&user, "user", "", "Snowflake user")
	cmd.Flags().StringVar(&password, "password", "", "Snowflake password (or set SNOWFLAKE_PRIVATE_KEY env)")
	// redshift
	cmd.Flags().StringVar(&clusterID, "cluster", "", "Redshift cluster identifier")
	cmd.Flags().StringVar(&secretARN, "secret-arn", "", "AWS Secrets Manager ARN holding the Redshift credentials")
	cmd.Flags().StringVar(&stageS3, "stage-s3-uri", "", "S3 URI used as the COPY stage (e.g. s3://acme/warehouse-stage/)")
	return cmd
}

// Per-target argument structs let runWarehouseLoad route to the
// right Loader without ballooning the function signature.
type BigQueryArgs struct{ Project, Dataset, Location string }
type SnowflakeArgs struct{ Account, Warehouse, Database, Schema, User, Password string }
type RedshiftArgs struct{ Cluster, Database, SecretARN, StageS3URI string }

func runWarehouseLoad(ctx context.Context, stdout io.Writer, to, dbPath string,
	bq BigQueryArgs, sf SnowflakeArgs, rs RedshiftArgs) error {
	st, err := openStore(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store %s: %w", dbPath, err)
	}
	defer func() { _ = st.Close() }()
	if err := warmStore(ctx, st); err != nil {
		return err
	}
	src := warehouse.NewDBSource(st.DB())

	var loader warehouse.Loader
	// Per-phase loader case branches. BigQuery lands at Phase 2;
	// Snowflake at Phase 3; Redshift at Phase 4. Unsupported targets
	// in the flag enumeration return a clear "ships at v1.17 phase
	// N" message until the case is filled in.
	switch to {
	case "bigquery":
		loader = warehouse.NewBigQueryLoader(warehouse.BigQueryConfig{
			ProjectID: bq.Project, Dataset: bq.Dataset, Location: bq.Location,
		})
	case "snowflake":
		_ = sf
		return fmt.Errorf("snowflake loader ships at v1.17 phase 3")
	case "redshift":
		_ = rs
		return fmt.Errorf("redshift loader ships at v1.17 phase 4")
	default:
		return fmt.Errorf("--to must be one of: bigquery, snowflake, redshift")
	}
	if err := loader.Connect(ctx); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = loader.Close() }()

	fmt.Fprintf(stdout, "warehouse load → %s\n", to)
	for _, t := range warehouse.AllTables {
		start := time.Now()
		schema := warehouse.SchemaFor(t)
		rows, errs := src.Rows(ctx, t)
		err := loader.Load(ctx, schema, rows)
		// Drain errs channel.
		select {
		case e := <-errs:
			if e != nil {
				err = e
			}
		default:
		}
		if err != nil {
			fmt.Fprintf(stdout, "  %-12s  FAILED  %v\n", t, err)
			return fmt.Errorf("load %s: %w", t, err)
		}
		fmt.Fprintf(stdout, "  %-12s  ok  %s\n", t, time.Since(start).Truncate(time.Millisecond))
	}
	return nil
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
