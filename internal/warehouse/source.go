package warehouse

// DBSource is a Source that streams rows from the daemon's SQLite /
// Postgres store. Each Rows() call opens a per-table cursor + drives
// the row channel until the table is exhausted. Errors fire AT MOST
// once on the error channel.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// DBSource wraps a *sql.DB and projects the canonical Schema columns
// out of the daemon's tables. Optional SnapshotCursor restricts every
// read to rows with id <= cursor (v1.17 phase 6 snapshot pattern).
type DBSource struct {
	DB             *sql.DB
	SnapshotCursor SnapshotCursor
}

// SnapshotCursor is the upper-bound id per table. Empty = no
// bound (live read). audit_log id is TEXT in the daemon schema
// despite looking numeric — pass the string form.
type SnapshotCursor struct {
	Findings  string
	Resources string
	Scans     string
	AuditLog  string
}

// NewDBSource is a convenience constructor for a live (non-snapshot)
// source.
func NewDBSource(db *sql.DB) *DBSource { return &DBSource{DB: db} }

// orderByID is the canonical ORDER BY suffix appended to every table
// stream so cursor-based snapshot reads return rows in a stable order.
const orderByID = ` ORDER BY id`

func (s *DBSource) Rows(ctx context.Context, t Table) (rows <-chan Row, errs <-chan error) {
	out := make(chan Row, 64)
	errCh := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errCh)
		var err error
		switch t {
		case TableFindings:
			err = s.streamFindings(ctx, out)
		case TableResources:
			err = s.streamResources(ctx, out)
		case TableScans:
			err = s.streamScans(ctx, out)
		case TableAuditLog:
			err = s.streamAuditLog(ctx, out)
		default:
			err = fmt.Errorf("unknown table %q", t)
		}
		if err != nil {
			errCh <- err
		}
	}()
	return out, errCh
}

func (s *DBSource) streamFindings(ctx context.Context, out chan<- Row) error {
	q := `SELECT id, COALESCE(scan_id,''), COALESCE(fingerprint,''),
	             COALESCE(check_id,''), COALESCE(severity,''), COALESCE(status,''),
	             COALESCE(provider,''), COALESCE(resource_id,''),
	             COALESCE(resource_name,''), COALESCE(resource_type,''),
	             COALESCE(message,''), COALESCE(framework_ids,'[]'),
	             COALESCE(first_seen_at,''), COALESCE(last_seen_at,''),
	             COALESCE(created_at,'')
	      FROM findings`
	if s.SnapshotCursor.Findings != "" {
		q += ` WHERE id <= ` + sqlQuote(s.SnapshotCursor.Findings)
	}
	q += orderByID
	rows, err := s.DB.QueryContext(ctx, q)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var id, scanID, fp, checkID, sev, status, provider, resID, resName, resType, msg, fwIDs, firstSeen, lastSeen, createdAt string
		if err := rows.Scan(&id, &scanID, &fp, &checkID, &sev, &status, &provider,
			&resID, &resName, &resType, &msg, &fwIDs, &firstSeen, &lastSeen, &createdAt); err != nil {
			return err
		}
		select {
		case out <- Row{
			"id": id, "scan_id": scanID, "fingerprint": fp,
			"check_id": checkID, "severity": sev, "status": status, "provider": provider,
			"resource_id": resID, "resource_name": stringOrNil(resName),
			"resource_type": stringOrNil(resType), "message": stringOrNil(msg),
			"framework_ids": stringOrNil(fwIDs),
			"first_seen_at": firstSeen, "last_seen_at": lastSeen, "created_at": createdAt,
		}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return rows.Err()
}

func (s *DBSource) streamResources(ctx context.Context, out chan<- Row) error {
	q := `SELECT id, COALESCE(name,''), COALESCE(type,''), COALESCE(provider,''),
	             COALESCE(first_seen_at,''), COALESCE(last_seen_at,''),
	             COALESCE(last_seen_scan_id,'')
	      FROM resources`
	if s.SnapshotCursor.Resources != "" {
		q += ` WHERE id <= ` + sqlQuote(s.SnapshotCursor.Resources)
	}
	q += orderByID
	rows, err := s.DB.QueryContext(ctx, q)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, name, typ, provider, firstSeen, lastSeen, lastScan string
		if err := rows.Scan(&id, &name, &typ, &provider, &firstSeen, &lastSeen, &lastScan); err != nil {
			return err
		}
		select {
		case out <- Row{
			"id": id, "name": stringOrNil(name), "type": stringOrNil(typ),
			"provider": stringOrNil(provider), "first_seen_at": stringOrNil(firstSeen),
			"last_seen_at": stringOrNil(lastSeen), "last_seen_scan_id": stringOrNil(lastScan),
		}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return rows.Err()
}

func (s *DBSource) streamScans(ctx context.Context, out chan<- Row) error {
	q := `SELECT id, COALESCE(created_at,''), COALESCE(source,''), COALESCE(status,''),
	             COALESCE(providers_scanned,'[]'), COALESCE(frameworks_scanned,'[]'),
	             COALESCE(score,0), COALESCE(coverage,0),
	             COALESCE(total_findings,0), COALESCE(actionable_findings,0),
	             COALESCE(duration_ms,0)
	      FROM scans`
	if s.SnapshotCursor.Scans != "" {
		q += ` WHERE id <= ` + sqlQuote(s.SnapshotCursor.Scans)
	}
	q += orderByID
	rows, err := s.DB.QueryContext(ctx, q)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, createdAt, source, status, providers, frameworks string
		var score, coverage, total, actionable, duration int64
		if err := rows.Scan(&id, &createdAt, &source, &status, &providers, &frameworks,
			&score, &coverage, &total, &actionable, &duration); err != nil {
			return err
		}
		select {
		case out <- Row{
			"id": id, "created_at": createdAt,
			"source": stringOrNil(source), "status": status,
			"providers_scanned": stringOrNil(providers), "frameworks_scanned": stringOrNil(frameworks),
			"score": score, "coverage": coverage,
			"total_findings": total, "actionable_findings": actionable, "duration_ms": duration,
		}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return rows.Err()
}

func (s *DBSource) streamAuditLog(ctx context.Context, out chan<- Row) error {
	q := `SELECT id, COALESCE(created_at,''), COALESCE(actor_user_id,''),
	             COALESCE(actor_token_id,''), COALESCE(actor_ip,''),
	             COALESCE(action,''), COALESCE(entity_type,''), COALESCE(entity_id,''),
	             COALESCE(metadata_json,''), COALESCE(row_hash,'')
	      FROM audit_log`
	if s.SnapshotCursor.AuditLog != "" {
		q += ` WHERE id <= ` + sqlQuote(s.SnapshotCursor.AuditLog)
	}
	q += ` ORDER BY created_at, id`
	rows, err := s.DB.QueryContext(ctx, q)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, createdAt, actorID, actorToken, actorIP, action, entityType, entityID, metaJSON, rowHash string
		if err := rows.Scan(&id, &createdAt, &actorID, &actorToken, &actorIP, &action,
			&entityType, &entityID, &metaJSON, &rowHash); err != nil {
			return err
		}
		select {
		case out <- Row{
			"id": id, "created_at": createdAt,
			"actor_user_id":  stringOrNil(actorID),
			"actor_token_id": stringOrNil(actorToken),
			"actor_ip":       stringOrNil(actorIP),
			"action":         action,
			"entity_type":    stringOrNil(entityType),
			"entity_id":      stringOrNil(entityID),
			"metadata_json":  stringOrNil(metaJSON),
			"row_hash":       stringOrNil(rowHash),
		}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return rows.Err()
}

// stringOrNil maps empty SQL strings to nil so the warehouse sees
// NULLs for the Nullable columns instead of empty strings. Loaders
// can then materialize the right NULL semantics in the destination.
func stringOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// sqlQuote is a defensive escaper used ONLY for cursor values pulled
// from snapshot rows already validated at write time. Never accept
// untrusted input here.
func sqlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// toTimestampMicros accepts the RFC3339 strings the daemon writes
// (or a stdlib time.Time) and returns microseconds since epoch.
func toTimestampMicros(v any) (int64, error) {
	switch x := v.(type) {
	case time.Time:
		return x.UnixMicro(), nil
	case string:
		if x == "" {
			return 0, nil
		}
		t, err := time.Parse(time.RFC3339Nano, x)
		if err != nil {
			t, err = time.Parse(time.RFC3339, x)
			if err != nil {
				return 0, fmt.Errorf("parse timestamp %q: %w", x, err)
			}
		}
		return t.UnixMicro(), nil
	}
	return 0, fmt.Errorf("not a timestamp: %T", v)
}
