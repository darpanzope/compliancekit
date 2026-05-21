# SQL performance reference

Internal documentation for the daemon's hot query paths. Updated when
a query's shape changes; cross-referenced from `ROADMAP.md § v1.11`.

The goal: every list endpoint scales to **100k+ rows** without
OFFSET-induced collapses, every filter chip combo is index-served,
and slow-query log (v1.11 phase 7) catches regressions per-commit.

---

## Cursor pagination (v1.11 phase 0)

Every list endpoint moved from `OFFSET/LIMIT` to cursor-based
pagination keyed on `(sort_key, id)`. The legacy `?page=N` path
remains for one minor release; removed at v1.12.

### Indexes that serve the cursor query

| Endpoint                | Index                              | Migration |
| ----------------------- | ---------------------------------- | --------- |
| `/api/v1/scans`         | `idx_scans_created_id`             | 0016      |
| `/api/v1/findings`      | `idx_findings_created_id`          | 0016      |
| `/api/v1/resources`     | `idx_resources_lastseen_id`        | 0016      |

The composite `(sort_key DESC, id DESC)` shape matches the ORDER BY
and the WHERE-tuple-compare exactly so the planner serves the query
from the index alone — no per-row heap lookup.

### EXPLAIN reference

```text
sqlite> EXPLAIN QUERY PLAN
        SELECT id, created_at FROM findings
        WHERE (created_at, id) < ('2026-05-21T08:00:00Z', 'fp-x')
        ORDER BY created_at DESC, id DESC LIMIT 51;
SEARCH findings USING INDEX idx_findings_created_id (created_at<?)
```

A SCAN here (instead of SEARCH) means the index is missing or the
WHERE clause shape doesn't match — open an issue + tag perf.

---

## Filter + cursor compositions (v1.11 phase 2)

The findings explorer (v1.5) lets operators chip-filter on
severity / status / provider while paginating. Without composite
indexes the planner picks one side and post-filters — fine at
1k rows, painful at 100k.

| Filter chip   | Index                                | Notes                              |
| ------------- | ------------------------------------ | ---------------------------------- |
| severity=...  | `idx_findings_severity_created`      | Composite — covers cursor          |
| status=...    | `idx_findings_status_created`        | Composite — covers cursor          |
| provider=...  | `idx_findings_provider_created`      | Composite — covers cursor          |
| resource_type | `idx_findings_resource_type`         | Single col; cursor scan over filter set is acceptable at expected cardinality (<10k rows per type) |
| check_id      | `idx_findings_check_id`              | Same                               |
| scan_id       | `idx_findings_scan_id`               | Same                               |

Cross-filter (≥2 chips set) intentionally falls back to scan +
post-filter — operators rarely chain ≥2 chips, and a full N×M
composite per chip pair would balloon the index footprint past
the table data.

---

## Indexed read paths beyond the explorer

| Query                                          | Index                              |
| ---------------------------------------------- | ---------------------------------- |
| `/api/v1/findings/{id}`                        | PK                                 |
| `/api/v1/scans/{id}/findings`                  | `idx_findings_scan_id` + cursor    |
| `/findings/{id}/timeline` (v1.5 drift)         | `idx_findings_fingerprint`         |
| `/audit` filtered by actor + time              | `idx_audit_log_actor_created` (0016) |
| `/inbox` filtered by event_type + newest first | `idx_inbox_user_event_type` (0016) |
| `/api/v1/comments` by finding fingerprint      | `idx_comments_finding_fp` (0008)   |
| `/api/v1/events` SSE cursor replay             | In-memory ring (5-min retention)    |

---

## When to add an index

1. **Always cursor-keyed on `(sort, id)`**. New list endpoints
   that paginate must pick a `(monotonic_col, id)` index. Just
   adding the monotonic column alone is wrong — the tuple compare
   `(a, b) < (?, ?)` needs both columns in the index in that order.

2. **Filter-then-paginate hot paths get a composite**. When chip
   filters cross-cut a cursor, add `(filter_col, sort_col, id)`.
   Cardinality threshold for "hot": expected filtered set ≥10k
   rows in the median deployment.

3. **Foreign-key joins**. `findings.scan_id` is hot because every
   `/scans/{id}/findings` query joins on it. Existing
   `idx_findings_scan_id` covers it.

4. **Never index for write-only paths**. The `audit_log.id` PK is
   sufficient for the v1.12 hash-chained verify pass (sequential
   scan); the table is append-only + the row size is small.

---

## Slow-query log (v1.11 phase 7 — preview)

The daemon emits a structured log entry when a query exceeds the
per-request budget (default 100ms). Each entry carries:

- `query_id` — sha256(normalized SQL) for grouping
- `duration_ms`
- `rows_scanned`
- `plan` — EXPLAIN QUERY PLAN output
- `query` — the SQL itself (with parameter values redacted)

Operators see slow queries in `/admin/logs` (filtered by the
`slow-query` tag) + can `compliancekit serve query-stats` for an
aggregated leaderboard.

---

## Benchmark harness (v1.11 phase 9 — preview)

`make bench-server` seeds 100k findings / 10k resources / 1k scans
into the embedded SQLite + a Postgres test container, then runs:

| Benchmark                                      | Target            |
| ---------------------------------------------- | ----------------- |
| `BenchmarkListFindings_CursorFirstPage`        | p95 <50ms (PG)   |
| `BenchmarkListFindings_CursorDeepPage`         | p95 <50ms (PG)   |
| `BenchmarkListFindings_LegacyOffsetDeep`       | regression-only baseline (will be removed at v1.12) |
| `BenchmarkListFindings_FilterSeverityCursor`   | p95 <100ms       |
| `BenchmarkListScans_Cursor`                    | p95 <30ms        |
| `BenchmarkListResources_Cursor`                | p95 <30ms        |

CI runs the bench on every push; fails the build when p95 latency
regresses >20% vs the previous tag's baseline.

---

## Maintenance

When adding a new list endpoint:

1. Read this doc + the ROADMAP § v1.11 entry.
2. Pick the cursor sort key + the composite-index shape.
3. Add the migration with `CREATE INDEX IF NOT EXISTS`.
4. Update this doc's index table.
5. Add a bench in `make bench-server`.
