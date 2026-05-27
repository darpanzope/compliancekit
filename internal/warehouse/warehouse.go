// Package warehouse implements v1.17 data-warehouse bridges. Three
// distinct shapes ship here:
//
//	Writer  — per-format serializer (Parquet, NDJSON) for a single
//	          table at a time. Stateless.
//	Loader  — per-target sink (BigQuery, Snowflake, Redshift, DuckDB)
//	          that takes batched rows + writes them into a warehouse.
//	Exporter — orchestrates Writer-per-table over a Source so a single
//	          CLI call produces every canonical artifact.
//
// The four canonical tables exposed to warehouses are findings,
// resources, scans, and audit_log. Each has a documented schema in
// docs/warehouse-schema.md; future bumps must include a schema_version
// metadata field so loaders can reject incompatible files.
package warehouse

import (
	"context"
	"fmt"
	"time"
)

// SchemaVersion is bumped whenever the canonical row shape changes.
// Loaders should reject files with a SchemaVersion they don't know.
const SchemaVersion = 1

// Table identifies one of the canonical warehouse tables. Loaders
// implement per-table behavior (e.g. BigQuery dataset auto-create);
// Writers map Table → schema definition.
type Table string

const (
	TableFindings  Table = "findings"
	TableResources Table = "resources"
	TableScans     Table = "scans"
	TableAuditLog  Table = "audit_log"
)

// AllTables enumerates every canonical table in stable order. CLI
// commands + scheduled sync iterate this slice.
var AllTables = []Table{TableFindings, TableResources, TableScans, TableAuditLog}

// Row is a per-table column→value tuple. Loaders + writers are kept
// schema-driven so a new table is one Schema entry, not a re-write.
// The map's column order is meaningless; iterate the Schema for the
// canonical projection order.
type Row map[string]any

// Schema describes the columns of a Table — the declared order
// becomes the file/SQL projection order. Loaders use Type for
// destination DDL (BigQuery STRING/INT64/TIMESTAMP, Redshift VARCHAR,
// etc.); Writers map Type → Arrow physical type.
type Schema struct {
	Table   Table
	Columns []Column
}

// Column is one field in a Schema. Type is the abstract logical
// type (per-target adapters map to concrete DDL); Nullable controls
// whether the row may omit the value.
type Column struct {
	Name     string
	Type     ColumnType
	Nullable bool
	Comment  string
}

// ColumnType is the abstract logical type. Stays small + DDL-friendly;
// new types added as additive enum values.
type ColumnType string

const (
	TypeString    ColumnType = "string"
	TypeInt       ColumnType = "int64"
	TypeFloat     ColumnType = "float64"
	TypeBool      ColumnType = "bool"
	TypeTimestamp ColumnType = "timestamp" // RFC3339 in NDJSON, TIMESTAMP_MICROS in Parquet
	TypeJSON      ColumnType = "json"      // serialized as STRING in every target
)

// Source produces row streams per Table. Callers (the CLI export
// command + the scheduled-sync worker) pass a Source backed by the
// daemon's DB. The contract: Rows returns a closer-friendly channel
// of Row + an error channel that fires AT MOST once for setup or
// cursor failures.
type Source interface {
	Rows(ctx context.Context, t Table) (rows <-chan Row, errs <-chan error)
}

// Writer serializes Rows of a single Table to a destination. Per-
// format implementations (ParquetWriter, NDJSONWriter) own the byte
// layout. Close MUST be called to flush any buffered output.
type Writer interface {
	Open(ctx context.Context, schema Schema) error
	Write(ctx context.Context, row Row) error
	Close() error
}

// Loader writes rows into a warehouse target. Per-target adapters
// (BigQuery, Snowflake, Redshift, DuckDB) own the connection +
// staging + COPY semantics. Implementations should be safe to reuse
// across many Load calls within one process.
type Loader interface {
	// Connect validates credentials + ensures destination dataset/
	// schema exists. Idempotent; safe to call before every Load.
	Connect(ctx context.Context) error
	// Load streams rows into the target table. Implementations may
	// buffer + batch but must flush before returning.
	Load(ctx context.Context, schema Schema, rows <-chan Row) error
	// Close releases connection resources. Idempotent.
	Close() error
}

// Stats wraps per-table export counts; returned by Exporter.Run so
// the CLI can render a summary line per table.
type Stats struct {
	Table    Table
	Rows     int64
	Bytes    int64
	Duration time.Duration
	Err      error
}

// SchemaFor returns the canonical Schema for one of the four tables.
// Panics on unknown table (the AllTables slice is the authoritative
// enumeration; passing anything else is a programming error).
func SchemaFor(t Table) Schema {
	switch t {
	case TableFindings:
		return Schema{Table: t, Columns: []Column{
			{Name: "id", Type: TypeString, Comment: "Stable uuid for the finding"},
			{Name: "scan_id", Type: TypeString, Comment: "Owning scan"},
			{Name: "fingerprint", Type: TypeString, Comment: "Stable join key across scans"},
			{Name: "check_id", Type: TypeString, Comment: "Catalog check id (e.g. aws-s3-no-public-acl)"},
			{Name: "severity", Type: TypeString, Comment: "critical/high/medium/low/info/pass"},
			{Name: "status", Type: TypeString, Comment: "fail/pass/error/skip"},
			{Name: "provider", Type: TypeString, Comment: "aws/gcp/digitalocean/hetzner/kubernetes/linux/ingest.<tool>"},
			{Name: "resource_id", Type: TypeString, Comment: "Stable resource id"},
			{Name: "resource_name", Type: TypeString, Nullable: true},
			{Name: "resource_type", Type: TypeString, Nullable: true},
			{Name: "message", Type: TypeString, Nullable: true, Comment: "Short, human-readable failure summary"},
			{Name: "framework_ids", Type: TypeJSON, Nullable: true, Comment: "JSON array of framework slugs the check maps to"},
			{Name: "first_seen_at", Type: TypeTimestamp, Comment: "Earliest scan that surfaced this finding"},
			{Name: "last_seen_at", Type: TypeTimestamp, Comment: "Most recent scan that confirmed it"},
			{Name: "created_at", Type: TypeTimestamp, Comment: "Row insert time"},
		}}
	case TableResources:
		return Schema{Table: t, Columns: []Column{
			{Name: "id", Type: TypeString},
			{Name: "name", Type: TypeString, Nullable: true},
			{Name: "type", Type: TypeString, Nullable: true},
			{Name: "provider", Type: TypeString, Nullable: true},
			{Name: "first_seen_at", Type: TypeTimestamp, Nullable: true},
			{Name: "last_seen_at", Type: TypeTimestamp, Nullable: true},
			{Name: "last_seen_scan_id", Type: TypeString, Nullable: true},
		}}
	case TableScans:
		return Schema{Table: t, Columns: []Column{
			{Name: "id", Type: TypeString},
			{Name: "created_at", Type: TypeTimestamp},
			{Name: "source", Type: TypeString, Nullable: true},
			{Name: "status", Type: TypeString},
			{Name: "providers_scanned", Type: TypeJSON, Nullable: true},
			{Name: "frameworks_scanned", Type: TypeJSON, Nullable: true},
			{Name: "score", Type: TypeInt, Nullable: true},
			{Name: "coverage", Type: TypeInt, Nullable: true},
			{Name: "total_findings", Type: TypeInt, Nullable: true},
			{Name: "actionable_findings", Type: TypeInt, Nullable: true},
			{Name: "duration_ms", Type: TypeInt, Nullable: true},
		}}
	case TableAuditLog:
		return Schema{Table: t, Columns: []Column{
			{Name: "id", Type: TypeString},
			{Name: "created_at", Type: TypeTimestamp},
			{Name: "actor_user_id", Type: TypeString, Nullable: true},
			{Name: "actor_token_id", Type: TypeString, Nullable: true},
			{Name: "actor_ip", Type: TypeString, Nullable: true},
			{Name: "action", Type: TypeString, Comment: "Verb — scan.trigger, waiver.add, etc."},
			{Name: "entity_type", Type: TypeString, Nullable: true},
			{Name: "entity_id", Type: TypeString, Nullable: true},
			{Name: "metadata_json", Type: TypeJSON, Nullable: true},
			{Name: "row_hash", Type: TypeString, Nullable: true, Comment: "v1.12 tamper-evident chain hash"},
		}}
	default:
		panic(fmt.Sprintf("warehouse: unknown table %q (extend AllTables + SchemaFor when adding a new canonical table)", t))
	}
}
