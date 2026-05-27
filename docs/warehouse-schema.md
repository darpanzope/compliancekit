# Warehouse schema (v1.17)

The `compliancekit warehouse` family of commands writes four
per-table files in a stable, versioned schema. This document is the
contract — every loader (Parquet readers, BigQuery / Snowflake /
Redshift COPY, DuckDB `read_ndjson_auto`) reads from this shape.

**Schema version:** `1` (carried in Parquet KV metadata under
`compliancekit.schema_version` and in NDJSON's leading `_meta`
line). Loaders should reject files with an unknown version.

**Status:** stable additive — new columns may land in later
minor versions but always at the END of a table's column list,
always nullable. No column types change in place.

## Common conventions

- **Timestamps** are emitted as RFC3339 strings in NDJSON and as
  `TIMESTAMP_MICROS` in Parquet (UTC). Empty/NULL → SQL NULL.
- **Empty strings** for nullable columns are converted to SQL
  NULL by the writers — operators see NULL semantics in the
  warehouse, not literal empty strings.
- **JSON-shaped columns** (`framework_ids`, `providers_scanned`,
  `frameworks_scanned`, `context_json`) ship as STRING in every
  format — operators wishing to query the inner shape parse them
  client-side (e.g. `JSON_EXTRACT(framework_ids, '$[0]')` in
  BigQuery).
- **Column order** in the file equals the order documented below.
  Loaders that rely on positional access (Redshift COPY, Snowflake
  COPY without column lists) get a stable contract.

## `findings`

| # | Column | Type | Nullable | Comment |
|---|---|---|---|---|
| 1 | `id` | STRING | no | Stable uuid for the finding |
| 2 | `scan_id` | STRING | no | Owning scan |
| 3 | `fingerprint` | STRING | no | Stable join key across scans |
| 4 | `check_id` | STRING | no | Catalog check id (e.g. aws-s3-no-public-acl) |
| 5 | `severity` | STRING | no | critical / high / medium / low / info / pass |
| 6 | `status` | STRING | no | fail / pass / error / skip |
| 7 | `provider` | STRING | no | aws / gcp / digitalocean / hetzner / kubernetes / linux / ingest.\<tool\> |
| 8 | `resource_id` | STRING | no | Stable resource id |
| 9 | `resource_name` | STRING | yes | |
| 10 | `resource_type` | STRING | yes | |
| 11 | `message` | STRING | yes | Short, human-readable failure summary |
| 12 | `framework_ids` | JSON-STRING | yes | JSON array of framework slugs the check maps to |
| 13 | `first_seen_at` | TIMESTAMP | no | Earliest scan that surfaced this finding |
| 14 | `last_seen_at` | TIMESTAMP | no | Most recent scan that confirmed it |
| 15 | `created_at` | TIMESTAMP | no | Row insert time |

## `resources`

| # | Column | Type | Nullable | Comment |
|---|---|---|---|---|
| 1 | `id` | STRING | no | |
| 2 | `name` | STRING | yes | |
| 3 | `type` | STRING | yes | |
| 4 | `provider` | STRING | yes | |
| 5 | `first_seen_at` | TIMESTAMP | yes | |
| 6 | `last_seen_at` | TIMESTAMP | yes | |
| 7 | `last_seen_scan_id` | STRING | yes | |

## `scans`

| # | Column | Type | Nullable | Comment |
|---|---|---|---|---|
| 1 | `id` | STRING | no | |
| 2 | `created_at` | TIMESTAMP | no | |
| 3 | `source` | STRING | yes | daemon / cli / schedule / webhook |
| 4 | `status` | STRING | no | queued / running / completed / failed / canceled |
| 5 | `providers_scanned` | JSON-STRING | yes | |
| 6 | `frameworks_scanned` | JSON-STRING | yes | |
| 7 | `score` | INT64 | yes | 0-100 hardening score |
| 8 | `coverage` | INT64 | yes | 0-100 framework coverage |
| 9 | `total_findings` | INT64 | yes | |
| 10 | `actionable_findings` | INT64 | yes | severity ≥ low and status=fail |
| 11 | `duration_ms` | INT64 | yes | end-to-end scan wall time |

## `audit_log`

| # | Column | Type | Nullable | Comment |
|---|---|---|---|---|
| 1 | `id` | STRING | no | |
| 2 | `created_at` | TIMESTAMP | no | |
| 3 | `actor_user_id` | STRING | yes | |
| 4 | `actor_token_id` | STRING | yes | |
| 5 | `actor_ip` | STRING | yes | Real-IP from the request (X-Forwarded-For trusted only behind a configured proxy) |
| 6 | `action` | STRING | no | Verb — scan.trigger / waiver.add / role.update / token.issue / etc. |
| 7 | `entity_type` | STRING | yes | scan / waiver / check / token / user / webhook / role |
| 8 | `entity_id` | STRING | yes | |
| 9 | `metadata_json` | JSON-STRING | yes | Free-form per-action metadata |
| 10 | `row_hash` | STRING | yes | v1.12 tamper-evident chain hash |

## Loader checklist

When implementing a new Loader (v1.17 phase 2-4):

1. Read SchemaFor(table) for the abstract shape.
2. Map ColumnType → destination DDL using your warehouse's standard
   types (STRING ⇒ VARCHAR / TEXT; INT64 ⇒ INT64 / BIGINT;
   TIMESTAMP ⇒ TIMESTAMP / TIMESTAMP_NTZ).
3. Honor Nullable on the destination column. Empty Source strings
   are already NULL by the time the Writer/Loader sees them.
4. Stamp the schema version on the destination (BigQuery: table
   description; Snowflake: TAG `compliancekit_schema_version`;
   Redshift: comment).
5. Use the table name verbatim (`findings`, `resources`, `scans`,
   `audit_log`) so dbt/Looker/Lightdash bindings don't drift across
   targets.
